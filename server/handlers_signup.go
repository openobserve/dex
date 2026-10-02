package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/storage"
)

const (
	ssoRequiredDescription = "Your company signs in with single sign-on. Use “Sign in” with your work email."

	// accountCreatedParam and loginHintParam carry a finished sign-up to the password step when auto sign-in is not possible.
	accountCreatedParam  = "account_created"
	loginHintParam       = "login_hint"
	accountCreatedNotice = "Account created. Sign in to continue."
)

// oauthAuthorizeParams restart a client's authorization request at /auth/local.
var oauthAuthorizeParams = []string{"client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method", "approval_prompt"}

// signupRequest represents a user signup request
type signupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Username string `json:"username"`
	Token    string `json:"token"`
	Csrf     string `json:"csrf"`
}

type passwordResetRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
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

func (s *Server) isEmailAllowed(ctx context.Context, email string) bool {
	if !s.EnableEmailValidation {
		return true
	}
	nandiUrl := s.EmailValidationServerUrl
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	domain := parts[1]
	url := fmt.Sprintf("%s/api/v1/classify/%s", nandiUrl, domain)
	res, err := http.Get(url)
	if err != nil {
		s.logger.ErrorContext(ctx, "error checking email domain validity", "err", err)
		return false
	}
	defer res.Body.Close()

	// for some reason trying to create a type for this didn't work,
	// so used this method, as the response structure is pretty fixed
	var response map[string]interface{}
	err = json.NewDecoder(res.Body).Decode(&response)
	if err != nil {
		s.logger.ErrorContext(ctx, "error checking email domain validity", "err", err)
		return false
	}

	classification, ok := response["classification"].(string)
	if !ok {
		s.logger.ErrorContext(ctx, "unexpected response from email validation server", "response", response)
		return false
	}
	return (classification == "allowlisted" || classification == "legitimate" || classification == "unknown")
}

// isSSODomain reports whether email belongs to a domain that must sign in through its domain connector.
func (s *Server) isSSODomain(email string) bool {
	if addr, err := mail.ParseAddress(email); err == nil {
		email = addr.Address
	}
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	domain := email[at+1:]
	if domain == "" {
		return false
	}
	for _, domainConnector := range s.DomainConnectors {
		if strings.EqualFold(domainConnector.Domain, domain) {
			return true
		}
	}
	return false
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
		backLink := s.backLinkOr(r, s.defaultBackLink(r))
		email := strings.TrimSpace(r.URL.Query().Get("email"))
		if err := s.templates.signup(r, w, r.URL.String(), email, "", "", "", 0, backLink); err != nil {
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
	if wait, ok := s.limits.allowCodeVerify(r, req.Email); !ok {
		s.logger.WarnContext(ctx, "signup rate limited", "email", req.Email, "client_ip", clientIP(r))
		setRetryAfter(w, wait)
		if isJSONRequest {
			s.signupErrHelper(w, rateLimitedError, tooManyAttemptsMessage(wait), http.StatusTooManyRequests)
			return
		}
		s.handleSignupError(w, r, req, tooManyAttemptsMessage(wait), http.StatusTooManyRequests, false)
		return
	}

	// Validate and process signup
	errorMsg, statusCode := s.validateSignupRequest(req)
	if errorMsg != "" {
		s.handleSignupError(w, r, req, errorMsg, statusCode, isJSONRequest)
		return
	}

	// A password account for an SSO domain would bypass the company IdP's offboarding and MFA.
	if s.isSSODomain(req.Email) {
		if isJSONRequest {
			s.signupErrHelper(w, "sso_required", ssoRequiredDescription, http.StatusBadRequest)
		} else {
			s.handleSignupError(w, r, req, ssoRequiredDescription, http.StatusBadRequest, isJSONRequest)
		}
		return
	}

	token, err := s.storage.GetSignupToken(ctx, req.Email)
	if err != nil {
		s.logger.ErrorContext(ctx, "validation token not found", "err", err)
		req.Csrf = ""
		s.handleSignupError(w, r, req, "OTP not found or expired. Please request a new OTP.", http.StatusBadRequest, isJSONRequest)
		return
	}

	if msg, codeStillValid := s.verifyCode(ctx, req.Email, req.Csrf, req.Token, token); msg != "" {
		if !codeStillValid {
			req.Csrf = ""
		}
		s.handleSignupError(w, r, req, msg, http.StatusBadRequest, isJSONRequest)
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

	if len([]byte(req.Password)) > 72 {
		s.handleSignupError(w, r, req, "Password must not be longer than 72 characters/bytes.", http.StatusBadRequest, isJSONRequest)
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
		return
	}
	s.signInAfterSignup(w, r, password)
}

// verifyCode checks a submitted csrf and code against token; it returns an error message, and whether the code is still usable.
func (s *Server) verifyCode(ctx context.Context, email, csrf, code string, token storage.SignupToken) (string, bool) {
	if subtle.ConstantTimeCompare([]byte(csrf), []byte(token.CsrfToken)) != 1 {
		return "Invalid session. Please request a new OTP.", false
	}

	if s.now().After(token.Expiry) {
		_ = s.storage.DeleteSignupToken(ctx, email)
		return "OTP Expired. Please try again.", false
	}

	key := limitKey(email)
	if subtle.ConstantTimeCompare([]byte(code), []byte(token.ValidationToken)) != 1 {
		if s.limits.wrongCodes.fail(key) < maxWrongCodes {
			return "Invalid OTP. Please check and try again.", true
		}
		s.limits.wrongCodes.reset(key)
		if err := s.storage.DeleteSignupToken(ctx, email); err != nil && err != storage.ErrNotFound {
			s.logger.ErrorContext(ctx, "failed to revoke verification code", "err", err)
		}
		s.logger.WarnContext(ctx, "verification code revoked after too many wrong attempts", "email", email)
		return tooManyWrongCodeMsg, false
	}
	s.limits.wrongCodes.reset(key)
	return "", true
}

// signInAfterSignup signs a new user into the dex auth request they signed up from, or sends them to its password step.
func (s *Server) signInAfterSignup(w http.ResponseWriter, r *http.Request, password storage.Password) {
	ctx := r.Context()
	authReq, conn, reason := s.signupAuthRequest(ctx, r.URL.Query().Get("state"))
	if reason != "" {
		s.logger.InfoContext(ctx, "signup sign-in", "signup_auto_login", false, "reason", reason, "email", password.Email)
		s.signupFallback(w, r, authReq, password.Email)
		return
	}

	s.logger.InfoContext(ctx, "signup sign-in", "signup_auto_login", true, "email", password.Email, "auth_request", authReq.ID)
	identity := connector.Identity{
		UserID:        password.UserID,
		Username:      password.Username,
		Email:         password.Email,
		EmailVerified: true,
	}
	s.completeLogin(w, r, identity, authReq, conn)
}

// signupAuthRequest returns the live local-connector auth request for authID, or the reason it cannot be used.
func (s *Server) signupAuthRequest(ctx context.Context, authID string) (storage.AuthRequest, connector.Connector, string) {
	if authID == "" {
		return storage.AuthRequest{}, nil, "missing_state"
	}
	authReq, err := s.storage.GetAuthRequest(ctx, authID)
	if err != nil {
		if err != storage.ErrNotFound {
			s.logger.ErrorContext(ctx, "failed to get auth request", "err", err)
		}
		return storage.AuthRequest{}, nil, "auth_request_not_found"
	}
	if s.now().After(authReq.Expiry) {
		return authReq, nil, "auth_request_expired"
	}
	if authReq.LoggedIn {
		return authReq, nil, "already_logged_in"
	}
	conn, err := s.getConnector(ctx, authReq.ConnectorID)
	if err != nil {
		return authReq, nil, "connector_unavailable"
	}
	_, isPassword := conn.Connector.(connector.PasswordConnector)
	// Only the local password DB holds the account just created; another password connector (LDAP) must not vouch for it.
	_, isLocal := conn.Connector.(passwordDB)
	if !isPassword || !isLocal {
		return authReq, nil, "non_local_connector"
	}
	return authReq, conn.Connector, ""
}

// signupFallback restarts the client's authorization at the local password step with the new email filled in.
func (s *Server) signupFallback(w http.ResponseWriter, r *http.Request, authReq storage.AuthRequest, email string) {
	params := authorizeParamsFromAuthRequest(authReq)
	if params == nil {
		params = authorizeParamsFromQuery(r.URL.Query())
	}
	if params != nil {
		params.Set(loginHintParam, email)
		params.Set(accountCreatedParam, "1")
		http.Redirect(w, r, s.absPath("/auth", LocalConnector)+"?"+params.Encode(), http.StatusSeeOther)
		return
	}

	// No client to resume: the page still confirms the account and offers the password step.
	query := r.URL.Query()
	query.Del("back")
	query.Del("email")
	loginPath := s.absPath("/auth", LocalConnector, "login") + "?" + query.Encode()
	signupPath := s.absPath("/signup") + "?" + query.Encode()
	resetPasswordPath := s.absPath("/password_reset") + "?" + query.Encode()
	if err := s.templates.password(r, w, loginPath, email, "email", false, "", signupPath, resetPasswordPath, s.enableSignup, false, authTabs{}, authNotice{Success: accountCreatedNotice}); err != nil {
		s.logger.ErrorContext(r.Context(), "server template error", "err", err)
	}
}

// authorizeParamsFromAuthRequest rebuilds the client's /auth parameters, or nil when there is no client.
func authorizeParamsFromAuthRequest(a storage.AuthRequest) url.Values {
	if a.ClientID == "" || a.RedirectURI == "" {
		return nil
	}
	v := url.Values{}
	v.Set("client_id", a.ClientID)
	v.Set("redirect_uri", a.RedirectURI)
	v.Set("response_type", strings.Join(a.ResponseTypes, " "))
	v.Set("scope", strings.Join(a.Scopes, " "))
	if a.State != "" {
		v.Set("state", a.State)
	}
	if a.Nonce != "" {
		v.Set("nonce", a.Nonce)
	}
	if a.PKCE.CodeChallenge != "" {
		v.Set("code_challenge", a.PKCE.CodeChallenge)
		v.Set("code_challenge_method", a.PKCE.CodeChallengeMethod)
	}
	if a.ForceApprovalPrompt {
		v.Set("approval_prompt", "force")
	}
	return v
}

// authorizeParamsFromQuery keeps the client's own /auth parameters from a sign-up URL, or nil when it has none.
func authorizeParamsFromQuery(q url.Values) url.Values {
	if q.Get("client_id") == "" {
		return nil
	}
	v := url.Values{}
	for _, k := range oauthAuthorizeParams {
		if val := q.Get(k); val != "" {
			v.Set(k, val)
		}
	}
	return v
}

// accountCreatedEmail returns the email a finished sign-up handed to the password step.
func accountCreatedEmail(q url.Values) (string, bool) {
	if q.Get(accountCreatedParam) != "1" {
		return "", false
	}
	hint := strings.TrimSpace(q.Get(loginHintParam))
	if addr, err := mail.ParseAddress(hint); err != nil || addr.Address != hint {
		return "", false
	}
	return hint, true
}

// withoutAccountCreated drops the one-shot sign-up hand-off so it does not leak into other links.
func withoutAccountCreated(q url.Values) url.Values {
	out := url.Values{}
	for k, v := range q {
		out[k] = v
	}
	out.Del(accountCreatedParam)
	out.Del(loginHintParam)
	return out
}

// handleSignupError handles error responses for signup
func (s *Server) handleSignupError(w http.ResponseWriter, r *http.Request, req signupRequest, errorMsg string, statusCode int, isJSONRequest bool) {
	if isJSONRequest {
		s.signupErrHelper(w, "invalid_request", errorMsg, statusCode)
	} else {
		backLink := s.backLinkOr(r, s.defaultBackLink(r))
		if err := s.templates.signup(r, w, r.URL.String(), req.Email, req.Username, req.Csrf, errorMsg, statusCode, backLink); err != nil {
			s.logger.ErrorContext(r.Context(), "server template error", "err", err)
		}
	}
}

func (s *Server) handlePasswordResetError(w http.ResponseWriter, r *http.Request, req passwordResetRequest, errorMsg string, statusCode int, isJSONRequest bool) {
	if isJSONRequest {
		s.passwordResetErrHelper(w, "invalid_request", errorMsg, statusCode)
	} else {
		backLink := s.backLinkOr(r, s.defaultBackLink(r))
		if err := s.templates.passwordReset(r, w, r.URL.String(), req.Email, errorMsg, statusCode, backLink); err != nil {
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

	// Validate username
	if req.Username == "" {
		return "Username is required", http.StatusBadRequest
	}

	// Validate password
	if req.Password == "" {
		return "Password is required", http.StatusBadRequest
	}

	// Validate password strength (minimum 8 characters)
	if len(req.Password) < 8 {
		return "Password must be at least 8 characters long", http.StatusBadRequest
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

func (s *Server) passwordResetErrHelper(w http.ResponseWriter, errorType, description string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	resp := signupErrorResponse{
		Error:       errorType,
		Description: description,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("password reset error response", "err", err)
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
			return
		}

		if wait, ok := s.limits.allowCodeSend(r, req.Email); !ok {
			s.logger.WarnContext(ctx, "signup code rate limited", "email", req.Email, "client_ip", clientIP(r))
			setRetryAfter(w, wait)
			s.signupErrHelper(w, rateLimitedError, tooManyAttemptsMessage(wait), http.StatusTooManyRequests)
			return
		}

		if s.isSSODomain(req.Email) {
			s.signupErrHelper(w, "sso_required", ssoRequiredDescription, http.StatusBadRequest)
			return
		}

		_, err := s.storage.GetPassword(ctx, req.Email)
		if err == nil {
			s.signupErrHelper(w, "invalid_request", "Email already registered", http.StatusConflict)
			return
		}

		if !s.isEmailAllowed(ctx, req.Email) {
			s.signupErrHelper(w, "invalid_request", "Personal email addresses aren't supported. Use your work email.", http.StatusBadRequest)
			return
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
		s.limits.wrongCodes.reset(limitKey(req.Email))

		body := fmt.Sprintf("Hello,<br/>The email validation code for signup to Openobserve is<br/><h2>%s</h2><br/>Please enter it in the signup form before submitting.<br/>This code is valid for 5 minutes.<br/>Regards,<br/>Openobserve Team.", token)
		err = sendEmail(s, req.Email, "Email validation Token for Openobserve", body)
		if err != nil {
			s.logger.ErrorContext(ctx, "failed to send token email", "err", err)
			s.signupErrHelper(w, "server_error", "We couldn't send the code. Try again in a minute.", http.StatusBadGateway)
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

func (s *Server) handlePasswordReset(w http.ResponseWriter, r *http.Request) {
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
		backLink := s.backLinkOr(r, s.defaultBackLink(r))
		if err := s.templates.passwordReset(r, w, r.URL.String(), "", "", 0, backLink); err != nil {
			s.logger.ErrorContext(r.Context(), "server template error", "err", err)
		}
		return
	case http.MethodPost:
		// Handle both HTML form and JSON submissions
		var req passwordResetRequest
		contentType := r.Header.Get("Content-Type")
		isJSONRequest := strings.Contains(contentType, "application/json")

		if isJSONRequest {
			// JSON API request
			if err := r.ParseForm(); err == nil && r.FormValue("email") != "" {
				// Actually a form submission with wrong content-type
				isJSONRequest = false
				req.Email = r.FormValue("email")
				req.Password = r.FormValue("password")
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
			req.Token = r.FormValue("token")
			req.Csrf = r.FormValue("csrf")
		}

		s.processPasswordReset(w, r, ctx, req, isJSONRequest)
		return
	default:
		s.signupErrHelper(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func (s *Server) processPasswordReset(w http.ResponseWriter, r *http.Request, ctx context.Context, req passwordResetRequest, isJSONRequest bool) {
	if wait, ok := s.limits.allowCodeVerify(r, req.Email); !ok {
		s.logger.WarnContext(ctx, "password reset rate limited", "email", req.Email, "client_ip", clientIP(r))
		setRetryAfter(w, wait)
		if isJSONRequest {
			s.passwordResetErrHelper(w, rateLimitedError, tooManyAttemptsMessage(wait), http.StatusTooManyRequests)
			return
		}
		s.handlePasswordResetError(w, r, req, tooManyAttemptsMessage(wait), http.StatusTooManyRequests, false)
		return
	}

	token, err := s.storage.GetSignupToken(ctx, req.Email)
	if err != nil {
		s.logger.ErrorContext(ctx, "password reset validation token not found", "err", err)
		s.handlePasswordResetError(w, r, req, "OTP not found or expired. Please request a new OTP.", http.StatusBadRequest, isJSONRequest)
		return
	}

	if msg, _ := s.verifyCode(ctx, req.Email, req.Csrf, req.Token, token); msg != "" {
		s.handlePasswordResetError(w, r, req, msg, http.StatusBadRequest, isJSONRequest)
		return
	}

	_ = s.storage.DeleteSignupToken(ctx, req.Email)
	// Check if user already exists
	_, err = s.storage.GetPassword(ctx, req.Email)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to check existing user", "err", err)
		s.handlePasswordResetError(w, r, req, "User with this email does not exist", http.StatusConflict, isJSONRequest)
		return
	}

	if len([]byte(req.Password)) > 72 {
		s.handlePasswordResetError(w, r, req, "Password must not be longer than 72 characters/bytes.", http.StatusBadRequest, isJSONRequest)
		return
	}

	// Hash the password using bcrypt (cost 10 is the default)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to hash password", "err", err)
		if isJSONRequest {
			s.passwordResetErrHelper(w, "server_error", "Failed to process password", http.StatusInternalServerError)
		} else {
			s.renderError(r, w, http.StatusInternalServerError, "Failed to process password.")
		}
		return
	}

	updater := func(old storage.Password) (storage.Password, error) {
		old.Hash = hashedPassword
		return old, nil
	}

	// Store the password in the database
	if err := s.storage.UpdatePassword(ctx, req.Email, updater); err != nil {
		s.logger.ErrorContext(ctx, "failed to update password", "err", err)
		if isJSONRequest {
			s.passwordResetErrHelper(w, "server_error", "Failed to update password", http.StatusInternalServerError)
		} else {
			s.renderError(r, w, http.StatusInternalServerError, "Failed to update password.")
		}
		return
	}

	// Log successful reset
	s.logger.InfoContext(ctx, "user password reset successfully", "email", req.Email)

	// Return success response
	if isJSONRequest {
		w.WriteHeader(http.StatusNoContent)
	} else {
		http.Redirect(w, r, s.backLinkOr(r, s.defaultBackLink(r)), http.StatusSeeOther)
	}
}

// handleSignup allows users to sign up with email and password via UI or API
func (s *Server) handlePasswordResetToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check if signup is enabled
	if !s.enableSignup {
		s.passwordResetErrHelper(w, "access_denied", "User signup is disabled", http.StatusForbidden)
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
			s.passwordResetErrHelper(w, "invalid_request", "Invalid JSON payload", http.StatusBadRequest)
			return
		}

		if _, err := mail.ParseAddress(req.Email); err != nil {
			s.passwordResetErrHelper(w, "invalid_request", "Invalid Email format", http.StatusBadRequest)
			return
		}

		if wait, ok := s.limits.allowCodeSend(r, req.Email); !ok {
			s.logger.WarnContext(ctx, "password reset code rate limited", "email", req.Email, "client_ip", clientIP(r))
			setRetryAfter(w, wait)
			s.passwordResetErrHelper(w, rateLimitedError, tooManyAttemptsMessage(wait), http.StatusTooManyRequests)
			return
		}

		_, err := s.storage.GetPassword(ctx, req.Email)
		if err != nil {
			s.passwordResetErrHelper(w, "invalid_request", "Email not found", http.StatusConflict)
			return
		}

		if !s.isEmailAllowed(ctx, req.Email) {
			s.passwordResetErrHelper(w, "invalid_request", "Email domain not allowed", http.StatusBadRequest)
			return
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
				s.passwordResetErrHelper(w, "Internal_server_error", "Error creating password reset token", http.StatusInternalServerError)
				return
			}
			s.logger.ErrorContext(ctx, "failed to create password reset token", "err", err)
			return
		}
		s.limits.wrongCodes.reset(limitKey(req.Email))

		body := fmt.Sprintf("Hello,<br/>The email validation code for password reset to Openobserve is<br/><h2>%s</h2><br/>Please enter it in the password reset form before submitting.<br/>This code is valid for 5 minutes.<br/>Regards,<br/>Openobserve Team.", token)
		err = sendEmail(s, req.Email, "Password reset Token for Openobserve", body)
		if err != nil {
			s.logger.ErrorContext(ctx, "failed to send password reset token email", "err", err)
			s.passwordResetErrHelper(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
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
			s.logger.ErrorContext(ctx, "failed to encode password reset token response", "err", err)
		}
		return
	default:
		s.passwordResetErrHelper(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}
