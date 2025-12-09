package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/dexidp/dex/storage"
)

// signupRequest represents a user signup request
type signupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Username string `json:"username"`
	Token    string `json:"token"`
	Csrf     string `json:"csrf"`
}

type signupTokenRequest struct {
	Email string `json:"email"`
}

// signupResponse represents a user signup response
type signupResponse struct {
	UserID   string `json:"user_id"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Message  string `json:"message"`
}

type signupTokenResponse struct {
	Email     string    `json:"email"`
	CsrfToken string    `json:"csrfToken"`
	Expiry    time.Time `json:"expiry"`
}

// signupErrorResponse represents an error response for signup
type signupErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// handleSignup allows users to sign up with email and password via UI or API
func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check if signup is enabled
	if !s.enableSignup {
		if r.Method == http.MethodGet || r.Header.Get("Content-Type") != "application/json" {
			s.renderError(r, w, http.StatusForbidden, "User signup is disabled.")
			return
		}
		s.signupErrHelper(w, "access_denied", "User signup is disabled", http.StatusForbidden)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Show signup form
		backLink := r.URL.Query().Get("back")
		if backLink == "" {
			backPath := fmt.Sprintf("/auth?%s", r.URL.Query().Encode())
			backLink = s.absPath(backPath)
		}
		if err := s.templates.signup(r, w, r.URL.String(), "", "", "", false, backLink); err != nil {
			s.logger.ErrorContext(r.Context(), "server template error", "err", err)
		}
		return
	case http.MethodPost:
		// Handle both HTML form and JSON submissions
		var req signupRequest
		contentType := r.Header.Get("Content-Type")
		isJSONRequest := strings.Contains(contentType, "application/json")

		if isJSONRequest {
			// JSON API request
			if err := r.ParseForm(); err == nil && r.FormValue("email") != "" {
				// Actually a form submission with wrong content-type
				isJSONRequest = false
				req.Email = r.FormValue("email")
				req.Password = r.FormValue("password")
				req.Username = r.FormValue("username")
				req.Token = r.FormValue("token")
				req.Csrf = r.FormValue("csrf")

				if req.Token == "" || req.Csrf == "" {
					s.signupErrHelper(w, "invalid_request", "Missing Token", http.StatusBadRequest)
					return
				}
			} else {
				// True JSON request
				r.Body = http.MaxBytesReader(w, r.Body, 1048576) // 1MB limit
				decoder := json.NewDecoder(r.Body)
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&req); err != nil {
					s.signupErrHelper(w, "invalid_request", "Invalid JSON payload", http.StatusBadRequest)
					return
				}
			}
		} else {
			// HTML form submission
			if err := r.ParseForm(); err != nil {
				s.logger.ErrorContext(r.Context(), "failed to parse form", "err", err)
				s.renderError(r, w, http.StatusBadRequest, "Failed to parse form.")
				return
			}
			req.Email = r.FormValue("email")
			req.Password = r.FormValue("password")
			req.Username = r.FormValue("username")
			req.Token = r.FormValue("token")
			req.Csrf = r.FormValue("csrf")
		}

		s.processSignup(w, r, ctx, req, isJSONRequest)
		return
	default:
		s.signupErrHelper(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

// processSignup handles the actual signup logic
func (s *Server) processSignup(w http.ResponseWriter, r *http.Request, ctx context.Context, req signupRequest, isJSONRequest bool) {
	// Validate and process signup
	errorMsg, statusCode := s.validateSignupRequest(req)
	if errorMsg != "" {
		s.handleSignupError(w, r, req, errorMsg, statusCode, isJSONRequest)
		return
	}

	token, err := s.storage.GetSignupToken(ctx, req.Email)
	if err != nil {
		s.logger.ErrorContext(ctx, "validation token not found", "err", err)
		if isJSONRequest {
			s.signupErrHelper(w, "bad_request", "Validation token not found", http.StatusBadRequest)
		} else {
			s.renderError(r, w, http.StatusBadRequest, "Validation token not found.")
		}
		return
	}

	if req.Csrf != token.CsrfToken {
		_ = s.storage.DeleteSignupToken(ctx, req.Email)
		if isJSONRequest {
			s.signupErrHelper(w, "bad_request", "Invalid token", http.StatusBadRequest)
		} else {
			s.renderError(r, w, http.StatusBadRequest, "Invalid token.")
		}
		return
	}

	if req.Token != token.ValidationToken {
		_ = s.storage.DeleteSignupToken(ctx, req.Email)
		if isJSONRequest {
			s.signupErrHelper(w, "bad_request", "Invalid token", http.StatusBadRequest)
		} else {
			s.renderError(r, w, http.StatusBadRequest, "Invalid token.")
		}
		return
	}
	_ = s.storage.DeleteSignupToken(ctx, req.Email)
	// Check if user already exists
	_, err = s.storage.GetPassword(ctx, req.Email)
	if err == nil {
		s.handleSignupError(w, r, req, "User with this email already exists", http.StatusConflict, isJSONRequest)
		return
	}
	if err != storage.ErrNotFound {
		s.logger.ErrorContext(ctx, "failed to check existing user", "err", err)
		if isJSONRequest {
			s.signupErrHelper(w, "server_error", "Internal server error", http.StatusInternalServerError)
		} else {
			s.renderError(r, w, http.StatusInternalServerError, "Internal server error.")
		}
		return
	}

	// Hash the password using bcrypt (cost 10 is the default)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to hash password", "err", err)
		if isJSONRequest {
			s.signupErrHelper(w, "server_error", "Failed to process password", http.StatusInternalServerError)
		} else {
			s.renderError(r, w, http.StatusInternalServerError, "Failed to process password.")
		}
		return
	}

	// Generate a unique user ID
	userID := storage.NewID()

	// Create the password entry
	password := storage.Password{
		Email:    strings.ToLower(req.Email), // Store email in lowercase for consistency
		Hash:     hashedPassword,
		Username: req.Username,
		UserID:   userID,
	}

	// Store the password in the database
	if err := s.storage.CreatePassword(ctx, password); err != nil {
		if err == storage.ErrAlreadyExists {
			s.handleSignupError(w, r, req, "User with this email already exists", http.StatusConflict, isJSONRequest)
			return
		}
		s.logger.ErrorContext(ctx, "failed to create user", "err", err)
		if isJSONRequest {
			s.signupErrHelper(w, "server_error", "Failed to create user", http.StatusInternalServerError)
		} else {
			s.renderError(r, w, http.StatusInternalServerError, "Failed to create user.")
		}
		return
	}

	// Log successful signup
	s.logger.InfoContext(ctx, "user signed up successfully", "email", req.Email, "user_id", userID)

	// Return success response
	if isJSONRequest {
		resp := signupResponse{
			UserID:   userID,
			Email:    req.Email,
			Username: req.Username,
			Message:  "User created successfully",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			s.logger.ErrorContext(ctx, "failed to encode signup response", "err", err)
		}
	} else {
		// Redirect to login page with success message
		backLink := r.URL.Query().Get("back")
		if backLink == "" {
			backPath := fmt.Sprintf("/auth?%s", r.URL.Query().Encode())
			backLink = s.absPath(backPath)
		}
		http.Redirect(w, r, backLink, http.StatusSeeOther)
	}
}

// handleSignupError handles error responses for signup
func (s *Server) handleSignupError(w http.ResponseWriter, r *http.Request, req signupRequest, errorMsg string, statusCode int, isJSONRequest bool) {
	if isJSONRequest {
		s.signupErrHelper(w, "invalid_request", errorMsg, statusCode)
	} else {
		backLink := r.URL.Query().Get("back")
		if backLink == "" {
			backPath := fmt.Sprintf("/auth?%s", r.URL.Query().Encode())
			backLink = s.absPath(backPath)
		}
		if err := s.templates.signup(r, w, r.URL.String(), req.Email, req.Username, errorMsg, true, backLink); err != nil {
			s.logger.ErrorContext(r.Context(), "server template error", "err", err)
		}
	}
}

// validateSignupRequest validates the signup request fields
func (s *Server) validateSignupRequest(req signupRequest) (string, int) {
	// Validate email
	if req.Email == "" {
		return "Email is required", http.StatusBadRequest
	}

	// Validate email format
	if _, err := mail.ParseAddress(req.Email); err != nil {
		return "Invalid email format", http.StatusBadRequest
	}

	// Validate password
	if req.Password == "" {
		return "Password is required", http.StatusBadRequest
	}

	// Validate password strength (minimum 8 characters)
	if len(req.Password) < 8 {
		return "Password must be at least 8 characters long", http.StatusBadRequest
	}

	// Validate username
	if req.Username == "" {
		return "Username is required", http.StatusBadRequest
	}

	return "", 0
}

// signupErrHelper sends a JSON error response
func (s *Server) signupErrHelper(w http.ResponseWriter, errorType, description string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	resp := signupErrorResponse{
		Error:       errorType,
		Description: description,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("signup error response", "err", err)
	}
}

// handleSignup allows users to sign up with email and password via UI or API
func (s *Server) handleSignupToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check if signup is enabled
	if !s.enableSignup {
		s.signupErrHelper(w, "access_denied", "User signup is disabled", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
		s.renderError(r, w, http.StatusBadRequest, "Invalid method or content type.")
		return
	}

	switch r.Method {
	case http.MethodPost:
		// Handle both HTML form and JSON submissions
		var req signupTokenRequest

		r.Body = http.MaxBytesReader(w, r.Body, 1048576) // 1MB limit
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			s.signupErrHelper(w, "invalid_request", "Invalid JSON payload", http.StatusBadRequest)
			return
		}

		if _, err := mail.ParseAddress(req.Email); err != nil {
			s.signupErrHelper(w, "invalid_request", "Invalid Email format", http.StatusBadRequest)
		}
		csrf := getRandomCode(16)
		token := getRandomCode(6)
		exp := time.Now().Add(time.Duration(5) * time.Minute)
		signupToken := storage.SignupToken{
			Email:           req.Email,
			CsrfToken:       csrf,
			ValidationToken: token,
			Expiry:          exp,
		}
		if err := s.storage.CreateSignupToken(ctx, signupToken); err != nil {
			if err == storage.ErrAlreadyExists {
				s.signupErrHelper(w, "Internal_server_error", "Error creating signup token", http.StatusInternalServerError)
				return
			}
			s.logger.ErrorContext(ctx, "failed to create signup token", "err", err)
			return
		}

		body := fmt.Sprintf("Hello,<br/>The email validation code for signup to openobserve cloud is<br/><h2>%s</h2><br/>Please enter it in the signup form before submitting.<br/>This code is valid for 5 minutes.<br/>Regards,<br/>Openobserve Team.", token)
		err := sendEmail(s, req.Email, "Email validation Token for Openobserve Cloud", body)
		if err != nil {
			s.logger.ErrorContext(ctx, "failed to send token email", err)
			s.signupErrHelper(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		resp := signupTokenResponse{
			Email:     req.Email,
			CsrfToken: signupToken.CsrfToken,
			Expiry:    signupToken.Expiry,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			s.logger.ErrorContext(ctx, "failed to encode signup token response", "err", err)
		}
		return
	default:
		s.signupErrHelper(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}
