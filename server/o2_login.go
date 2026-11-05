package server

// o2_login.go is the OpenObserve fork's sign-in flow: the two-stage password
// page (email first, then password), the domain-specific connector routing
// behind /check-handler, and the back-link and tab helpers the sign-up pages share.

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/gorilla/mux"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/server/templates"
	"github.com/dexidp/dex/server/tokens"
	"github.com/dexidp/dex/storage"
)

const (
	screenHintParam     = templates.ScreenHintParam
	screenHintSignup    = templates.ScreenHintSignup
	accountCreatedParam = templates.AccountCreatedParam
	loginHintParam      = templates.LoginHintParam
)

type (
	authTabs   = templates.AuthTabs
	authNotice = templates.AuthNotice
)

func (s *Server) handlePasswordLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	authID := r.URL.Query().Get("state")
	if authID == "" {
		s.renderError(r, w, http.StatusBadRequest, "User session error.")
		return
	}

	backLink := s.backLinkOr(r, "")

	authReq, err := s.storage.GetAuthRequest(ctx, authID)
	if err != nil {
		if err == storage.ErrNotFound {
			s.logger.ErrorContext(r.Context(), "invalid 'state' parameter provided", "err", err)
			s.renderError(r, w, http.StatusBadRequest, "Requested resource does not exist.")
			return
		}
		s.logger.ErrorContext(r.Context(), "failed to get auth request", "err", err)
		s.renderError(r, w, http.StatusInternalServerError, "Database error.")
		return
	}

	connID, err := url.PathUnescape(mux.Vars(r)["connector"])
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to parse connector", "err", err)
		s.renderError(r, w, http.StatusBadRequest, "Requested resource does not exist")
		return
	} else if connID != "" && connID != authReq.ConnectorID {
		s.logger.ErrorContext(r.Context(), "connector mismatch: password login triggered for different connector from authentication start", "start_connector_id", authReq.ConnectorID, "password_connector_id", connID)
		s.renderError(r, w, http.StatusInternalServerError, "Requested resource does not exist.")
		return
	}

	conn, err := s.getConnector(ctx, authReq.ConnectorID)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to get connector", "connector_id", authReq.ConnectorID, "err", err)
		s.renderError(r, w, http.StatusInternalServerError, "Connector failed to initialize.")
		return
	}

	pwConn, ok := conn.Connector.(connector.PasswordConnector)
	if !ok {
		s.logger.ErrorContext(r.Context(), "expected password connector in handlePasswordLogin()", "password_connector", pwConn)
		s.renderError(r, w, http.StatusInternalServerError, "Requested resource does not exist.")
		return
	}

	query := withoutAccountCreated(r.URL.Query())
	signupPath := fmt.Sprintf("%s?%s", s.absPath("/signup"), query.Encode())
	checkPath := fmt.Sprintf("%s?%s", s.absPath("/check-handler"), query.Encode())
	resetPasswordPath := fmt.Sprintf("%s?%s", s.absPath("/password_reset"), query.Encode())
	loginPath := fmt.Sprintf("%s?%s", r.URL.Path, query.Encode())
	tabs := s.authTabs(r.URL.Path, query)

	switch r.Method {
	case http.MethodGet:
		// Connectors that support SPNEGO try Kerberos before the password form is shown.
		if s.authflow.TrySPNEGO(w, r, authReq, conn.Connector) {
			return
		}
		if email, ok := accountCreatedEmail(r.URL.Query()); ok {
			if err := s.templates.PasswordO2(r, w, loginPath, email, usernamePrompt(pwConn), false, backLink, signupPath, resetPasswordPath, s.enableSignup, false, tabs, authNotice{Success: accountCreatedNotice}); err != nil {
				s.logger.ErrorContext(r.Context(), "server template error", "err", err)
			}
			return
		}
		if err := s.templates.PasswordO2(r, w, checkPath, "", usernamePrompt(pwConn), false, backLink, signupPath, resetPasswordPath, s.enableSignup, true, tabs, authNotice{}); err != nil {
			s.logger.ErrorContext(r.Context(), "server template error", "err", err)
		}
	case http.MethodPost:
		username := r.FormValue("login")
		password := r.FormValue("password")
		scopes := tokens.ParseScopes(authReq.Scopes)

		// A locked account gets the same answer whatever the password, so lockout never confirms a guess.
		if wait, blocked := s.limits.loginBlocked(r, username); blocked {
			s.logger.WarnContext(r.Context(), "password login rate limited", "user", username, "client_ip", clientIP(r))
			w.WriteHeader(http.StatusTooManyRequests)
			if err := s.templates.PasswordO2(r, w, loginPath, username, usernamePrompt(pwConn), false, backLink, signupPath, resetPasswordPath, s.enableSignup, false, tabs, authNotice{Error: tooManyAttemptsMessage(wait)}); err != nil {
				s.logger.ErrorContext(r.Context(), "server template error", "err", err)
			}
			return
		}

		identity, ok, err := pwConn.Login(r.Context(), scopes, username, password)
		if err != nil {
			s.logger.ErrorContext(r.Context(), "failed to login user", "err", err)
			s.renderError(r, w, http.StatusInternalServerError, fmt.Sprintf("Login error: %v", err))
			return
		}
		if !ok {
			s.limits.loginFailed(r, username)
			if err := s.templates.PasswordO2(r, w, loginPath, username, usernamePrompt(pwConn), true, backLink, signupPath, resetPasswordPath, s.enableSignup, false, tabs, authNotice{}); err != nil {
				s.logger.ErrorContext(r.Context(), "server template error", "err", err)
			}
			s.logger.ErrorContext(r.Context(), "failed login attempt: Invalid credentials.", "user", username)
			return
		}
		s.limits.loginSucceeded(username)
		s.completeLogin(w, r, identity, authReq, conn.Connector)
	default:
		s.renderError(r, w, http.StatusBadRequest, "Unsupported request method.")
	}
}

// completeLogin attaches a verified identity to authReq, then continues the flow at the /auth dispatcher.
func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, identity connector.Identity, authReq storage.AuthRequest, conn connector.Connector) {
	s.authflow.CompleteLogin(w, r, identity, authReq, conn)
}

func (s *Server) checkHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	authID := r.URL.Query().Get("state")
	if authID == "" {
		s.renderError(r, w, http.StatusBadRequest, "User session error.")
		return
	}

	backLink := s.backLinkOr(r, "")

	authReq, err := s.storage.GetAuthRequest(ctx, authID)
	if err != nil {
		if err == storage.ErrNotFound {
			s.logger.ErrorContext(r.Context(), "invalid 'state' parameter provided", "err", err)
			s.renderError(r, w, http.StatusBadRequest, "Requested resource does not exist.")
			return
		}
		s.logger.ErrorContext(r.Context(), "failed to get auth request", "err", err)
		s.renderError(r, w, http.StatusInternalServerError, "Database error.")
		return
	}

	username := r.FormValue("login")
	signupPath := fmt.Sprintf("%s?%s", s.absPath("/signup"), r.URL.Query().Encode())
	resetPasswordPath := fmt.Sprintf("%s?%s", s.absPath("/password_reset"), r.URL.Query().Encode())
	loginPath := fmt.Sprintf("%s?%s", s.absPath("/auth/local/login"), r.URL.Query().Encode())
	checkPath := fmt.Sprintf("%s?%s", s.absPath("/check-handler"), r.URL.Query().Encode())
	tabs := s.authTabs(s.absPath("/auth/local/login"), r.URL.Query())

	if wait, ok := s.limits.checkIP.allow(clientIP(r)); !ok {
		s.logger.WarnContext(ctx, "check-handler rate limited", "client_ip", clientIP(r))
		w.WriteHeader(http.StatusTooManyRequests)
		if err := s.templates.PasswordO2(r, w, checkPath, username, "email", false, backLink, signupPath, resetPasswordPath, s.enableSignup, true, tabs, authNotice{Error: tooManyAttemptsMessage(wait)}); err != nil {
			s.logger.ErrorContext(ctx, "server template error", "err", err)
		}
		return
	}

	splits := strings.Split(username, "@")

	if len(splits) != 2 {
		if err := s.templates.PasswordO2(r, w, loginPath, username, "email", true, backLink, signupPath, resetPasswordPath, s.enableSignup, true, tabs, authNotice{}); err != nil {
			s.logger.ErrorContext(r.Context(), "server template error", "err", err)
		}
		return
	}

	domain := splits[1]
	scopes := tokens.ParseScopes(authReq.Scopes)

	switch r.Method {
	case http.MethodPost:
		for _, domainConnector := range s.DomainConnectors {
			if domainConnector.Domain == domain {
				// by default at this point, we would have the connector id set to "local"
				// because check-handler itself is part of the local login flow
				// so we reset it to actual id, so that in the callback flow
				// we can detect the correct one
				s.storage.UpdateAuthRequest(ctx, authReq.ID, func(old storage.AuthRequest) (storage.AuthRequest, error) {
					old.ConnectorID = domainConnector.Id
					return old, nil
				})
				switch conn := domainConnector.Connector.(type) {
				case connector.CallbackConnector:
					callbackURL, connData, err := conn.LoginURL(scopes, s.absURL("/callback"), authReq.ID)
					if err != nil {
						s.logger.ErrorContext(r.Context(), "connector returned error when creating callback", "connector_id", domainConnector.Id, "err", err)
						s.renderError(r, w, http.StatusInternalServerError, "Login error.")
						return
					}
					if len(connData) > 0 {
						if err := s.storage.UpdateAuthRequest(ctx, authReq.ID, func(a storage.AuthRequest) (storage.AuthRequest, error) {
							a.ConnectorData = connData
							return a, nil
						}); err != nil {
							s.logger.ErrorContext(r.Context(), "failed to set connector data on auth request", "connector_id", domainConnector.Id, "err", err)
							s.renderError(r, w, http.StatusInternalServerError, "Database error.")
							return
						}
					}
					http.Redirect(w, r, callbackURL, http.StatusFound)
				case connector.PasswordConnector:
					loginURL := url.URL{
						Path: s.absPath("/auth", "local", "login"),
					}
					q := loginURL.Query()
					q.Set("state", authReq.ID)
					q.Set("back", backLink)
					loginURL.RawQuery = q.Encode()

					http.Redirect(w, r, loginURL.String(), http.StatusFound)
				case connector.SAMLConnector:
					action, value, err := conn.POSTData(scopes, authReq.ID)
					if err != nil {
						s.logger.ErrorContext(r.Context(), "creating SAML data", "err", err)
						s.renderError(r, w, http.StatusInternalServerError, "Connector Login Error")
						return
					}

					// TODO(ericchiang): Don't inline this.
					fmt.Fprintf(w, `<!DOCTYPE html>
			  <html lang="en">
			  <head>
			    <meta http-equiv="content-type" content="text/html; charset=utf-8">
			    <title>SAML login</title>
			  </head>
			  <body>
			    <form method="post" action="%s" >
				    <input type="hidden" name="SAMLRequest" value="%s" />
				    <input type="hidden" name="RelayState" value="%s" />
			    </form>
				<script>
				    document.forms[0].submit();
				</script>
			  </body>
			  </html>`, action, value, authReq.ID)
				default:
					s.renderError(r, w, http.StatusBadRequest, "Requested resource does not exist.")
				}
				return
			}
		}
		_, err := s.storage.GetPassword(ctx, username)
		if err == storage.ErrNotFound {
			signupURL := signupURLWithEmail(signupPath, username)
			personal := s.enableSignup && !s.isEmailAllowed(ctx, username)
			if tabs.SignupMode && !personal {
				http.Redirect(w, r, signupURL, http.StatusSeeOther)
				return
			}
			// No password account: stay on the email step instead of offering a sign-in that can only fail.
			notice := authNotice{SignupURL: signupURL}
			if personal {
				notice = authNotice{PersonalEmail: true}
			}
			if err := s.templates.PasswordO2(r, w, checkPath, username, "email", false, backLink, signupPath, resetPasswordPath, s.enableSignup, true, tabs, notice); err != nil {
				s.logger.ErrorContext(r.Context(), "server template error", "err", err)
			}
			return
		}
		notice := authNotice{}
		if err != nil {
			s.logger.ErrorContext(r.Context(), "failed to look up password account", "err", err)
		} else if tabs.SignupMode {
			notice = authNotice{ExistingAccount: true}
		}
		if tabs.SignupMode {
			// A returning user who chose Create account continues as a plain sign-in.
			signInQuery := r.URL.Query()
			signInQuery.Del(screenHintParam)
			if back := signInQuery.Get("back"); back != "" {
				signInQuery.Set("back", withoutScreenHint(back))
			}
			backLink = withoutScreenHint(backLink)
			signupPath = fmt.Sprintf("%s?%s", s.absPath("/signup"), signInQuery.Encode())
			resetPasswordPath = fmt.Sprintf("%s?%s", s.absPath("/password_reset"), signInQuery.Encode())
			loginPath = fmt.Sprintf("%s?%s", s.absPath("/auth/local/login"), signInQuery.Encode())
			tabs = s.authTabs(s.absPath("/auth/local/login"), signInQuery)
		}
		if err := s.templates.PasswordO2(r, w, loginPath, username, "email", false, backLink, signupPath, resetPasswordPath, s.enableSignup, false, tabs, notice); err != nil {
			s.logger.ErrorContext(r.Context(), "server template error", "err", err)
		}
		return
	default:
		s.renderError(r, w, http.StatusBadRequest, "Unsupported request method.")
	}
}

// authTabs builds the Sign in / Create account tab links for path, keeping every other query param.
func (s *Server) authTabs(path string, query url.Values) authTabs {
	return templates.NewAuthTabs(s.enableSignup, path, query)
}

// signupURLWithEmail is the sign-up page for email, keeping signupPath's query.
func signupURLWithEmail(signupPath, email string) string {
	return fmt.Sprintf("%s&email=%s", signupPath, url.QueryEscape(email))
}

// isSafeBackLink accepts only a relative path under the issuer, so a crafted back param can never send users off dex.
func (s *Server) isSafeBackLink(link string) bool {
	if !strings.HasPrefix(link, "/") || strings.HasPrefix(link, "//") || strings.Contains(link, `\`) {
		return false
	}
	for _, c := range link {
		// Browsers drop tabs and newlines inside URLs, which would turn "/\t/evil" into "//evil".
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return false
	}
	base := strings.TrimSuffix(s.issuerURL.Path, "/")
	cleaned := path.Clean(u.Path)
	return base == "" || cleaned == base || strings.HasPrefix(cleaned, base+"/")
}

// backLinkOr returns the request's back param when it is safe to follow, otherwise fallback.
func (s *Server) backLinkOr(r *http.Request, fallback string) string {
	if back := r.URL.Query().Get("back"); back != "" && s.isSafeBackLink(back) {
		return back
	}
	return fallback
}

// defaultBackLink is the connector chooser for the request's own OAuth parameters.
func (s *Server) defaultBackLink(r *http.Request) string {
	q := r.URL.Query()
	q.Del("back")
	return s.absPath("/auth") + "?" + q.Encode()
}

// withoutScreenHint drops the sign-up intent so links meant for signing in open on the Sign in tab.
func withoutScreenHint(link string) string {
	return templates.WithoutScreenHint(link)
}

// withoutAccountCreated drops the one-shot sign-up hand-off so it does not leak into other links.
func withoutAccountCreated(q url.Values) url.Values {
	return templates.WithoutAccountCreated(q)
}

// Check for username prompt override from connector. Defaults to "Username".
func usernamePrompt(conn connector.PasswordConnector) string {
	if attr := conn.Prompt(); attr != "" {
		return attr
	}
	return "Username"
}
