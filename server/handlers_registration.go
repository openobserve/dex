package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/dexidp/dex/storage"
)

// clientRegistrationRequest represents an RFC 7591 client registration request
type clientRegistrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
}

// clientRegistrationResponse represents an RFC 7591 client registration response
type clientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
}

// handleClientRegistration implements RFC 7591 OAuth 2.0 Dynamic Client Registration Protocol
func (s *Server) handleClientRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Only POST method is allowed
	if r.Method != http.MethodPost {
		s.registrationErrHelper(w, errInvalidRequest, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check Initial Access Token if configured (RFC 7591 Section 3.1)
	if s.registrationToken != "" {
		authHeader := r.Header.Get("Authorization")
		const bearerPrefix = "Bearer "

		if authHeader == "" || !strings.HasPrefix(authHeader, bearerPrefix) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			s.registrationErrHelper(w, errInvalidRequest, "Initial access token required", http.StatusUnauthorized)
			return
		}

		providedToken := strings.TrimPrefix(authHeader, bearerPrefix)
		if providedToken != s.registrationToken {
			w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
			s.registrationErrHelper(w, errInvalidRequest, "Invalid initial access token", http.StatusUnauthorized)
			return
		}

		s.logger.InfoContext(ctx, "client registration authenticated with initial access token")
	} else {
		s.logger.WarnContext(ctx, "client registration endpoint is open - no authentication required. Set registrationToken in config for production use.")
	}

	// Parse the request body
	var req clientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.ErrorContext(ctx, "failed to parse registration request", "err", err)
		s.registrationErrHelper(w, errInvalidRequest, "Invalid JSON request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if len(req.RedirectURIs) == 0 {
		s.registrationErrHelper(w, errInvalidRequest, "redirect_uris is required", http.StatusBadRequest)
		return
	}

	// Apply default values
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{grantTypeAuthorizationCode, grantTypeRefreshToken}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{responseTypeCode}
	}

	// Validate token_endpoint_auth_method
	if req.TokenEndpointAuthMethod != "client_secret_basic" && req.TokenEndpointAuthMethod != "client_secret_post" && req.TokenEndpointAuthMethod != "none" {
		s.registrationErrHelper(w, errInvalidRequest, "Unsupported token_endpoint_auth_method", http.StatusBadRequest)
		return
	}

	// Validate grant_types
	for _, gt := range req.GrantTypes {
		if !contains(s.supportedGrantTypes, gt) {
			s.registrationErrHelper(w, errInvalidRequest, fmt.Sprintf("Unsupported grant_type: %s", gt), http.StatusBadRequest)
			return
		}
	}

	// Validate response_types
	for _, rt := range req.ResponseTypes {
		if !s.supportedResponseTypes[rt] {
			s.registrationErrHelper(w, errInvalidRequest, fmt.Sprintf("Unsupported response_type: %s", rt), http.StatusBadRequest)
			return
		}
	}

	// Generate client_id and client_secret
	// Following the same pattern as the gRPC API (api.go:CreateClient)
	clientID := storage.NewID()

	// Determine if this is a public client
	isPublic := req.TokenEndpointAuthMethod == "none"

	// Only generate secret for confidential clients
	var clientSecret string
	if !isPublic {
		clientSecret = storage.NewID() + storage.NewID() // Double NewID for longer secret
	}

	// Create the client in storage
	client := storage.Client{
		ID:           clientID,
		Secret:       clientSecret,
		RedirectURIs: req.RedirectURIs,
		Name:         req.ClientName,
		LogoURL:      req.LogoURI,
		Public:       isPublic,
	}

	if err := s.storage.CreateClient(ctx, client); err != nil {
		s.logger.ErrorContext(ctx, "failed to create client", "err", err)
		if err == storage.ErrAlreadyExists {
			s.registrationErrHelper(w, errInvalidRequest, "Client ID already exists", http.StatusBadRequest)
		} else {
			s.registrationErrHelper(w, errServerError, "Failed to register client", http.StatusInternalServerError)
		}
		return
	}

	// Build the response
	resp := clientRegistrationResponse{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		ClientSecretExpiresAt:   0, // 0 indicates the secret never expires
		ClientName:              req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		Scope:                   req.Scope,
		LogoURI:                 req.LogoURI,
	}

	// For public clients, don't return the secret
	if isPublic {
		resp.ClientSecret = ""
	}

	// Return HTTP 201 Created
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.ErrorContext(ctx, "failed to encode registration response", "err", err)
	}
}

func (s *Server) registrationErrHelper(w http.ResponseWriter, typ, description string, statusCode int) {
	if err := tokenErr(w, typ, description, statusCode); err != nil {
		s.logger.Error("registration error response", "err", err)
	}
}
