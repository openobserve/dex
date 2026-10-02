package server

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/dexidp/dex/storage"
)

const (
	flowClientID     = "o2-web"
	flowClientSecret = "o2-secret"
	flowRedirectURI  = "https://app.example/cb"
	flowClientState  = "client-state"
	flowCSRF         = "csrf-0000000001"
	flowCode         = "123456"
)

var formActionRE = regexp.MustCompile(`<form method="post" action="([^"]+)"`)

// testClock lets a test move the server's clock past a lockout or rate-limit window.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newSignupFlowServer(t *testing.T) (*Server, *testClock) {
	clock := &testClock{now: time.Now()}
	httpServer, s := newTestServer(t, func(c *Config) {
		c.EnableSignup = true
		c.Web.Dir = "../o2web"
		c.Now = clock.Now
	})
	t.Cleanup(httpServer.Close)
	ctx := t.Context()
	require.NoError(t, s.storage.CreateConnector(ctx, storage.Connector{ID: "local", Type: LocalConnector, Name: "Email"}))
	require.NoError(t, s.storage.CreateClient(ctx, storage.Client{
		ID:           flowClientID,
		Secret:       flowClientSecret,
		RedirectURIs: []string{flowRedirectURI},
		Name:         "OpenObserve",
	}))
	return s, clock
}

func createFlowAuthRequest(t *testing.T, s *Server, mutate func(*storage.AuthRequest)) storage.AuthRequest {
	a := storage.AuthRequest{
		ID:            storage.NewID(),
		ClientID:      flowClientID,
		RedirectURI:   flowRedirectURI,
		ResponseTypes: []string{responseTypeCode},
		Scopes:        []string{"openid", "email", "profile"},
		State:         flowClientState,
		ConnectorID:   "local",
		Expiry:        s.now().Add(10 * time.Minute),
		HMACKey:       storage.NewHMACKey(crypto.SHA256),
	}
	if mutate != nil {
		mutate(&a)
	}
	require.NoError(t, s.storage.CreateAuthRequest(t.Context(), a))
	return a
}

func seedSignupCode(t *testing.T, s *Server, email string) {
	require.NoError(t, s.storage.CreateSignupToken(t.Context(), storage.SignupToken{
		Email:           email,
		CsrfToken:       flowCSRF,
		ValidationToken: flowCode,
		Expiry:          s.now().Add(5 * time.Minute),
	}))
}

func signupForm(email, code string) url.Values {
	return url.Values{
		"email":    {email},
		"username": {"Jane Smith"},
		"password": {"password123"},
		"token":    {code},
		"csrf":     {flowCSRF},
	}
}

func postForm(s *Server, target string, form url.Values, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return rr
}

func postJSON(s *Server, target string, body any, remoteAddr string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return rr
}

// followDexRedirects follows redirects that stay on dex and returns the first non-dex response.
func followDexRedirects(t *testing.T, s *Server, rr *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	for i := 0; i < 5; i++ {
		loc := rr.Header().Get("Location")
		if rr.Code < 300 || rr.Code >= 400 || !strings.HasPrefix(loc, "/") {
			return rr
		}
		rr = httptest.NewRecorder()
		s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, loc, nil))
	}
	t.Fatal("too many redirects")
	return nil
}

func requireCodeRedirect(t *testing.T, rr *httptest.ResponseRecorder, wantState string) string {
	t.Helper()
	require.Equal(t, http.StatusSeeOther, rr.Code, rr.Body.String())
	loc, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, flowRedirectURI, loc.Scheme+"://"+loc.Host+loc.Path)
	code := loc.Query().Get("code")
	require.NotEmpty(t, code)
	require.Equal(t, wantState, loc.Query().Get("state"))
	return code
}

func signupIDTokenClaims(t *testing.T, s *Server, code string) map[string]any {
	t.Helper()
	form := url.Values{"grant_type": {grantTypeAuthorizationCode}, "code": {code}, "redirect_uri": {flowRedirectURI}}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(flowClientID, flowClientSecret)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var tok struct {
		IDToken string `json:"id_token"`
	}
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&tok))
	parts := strings.Split(tok.IDToken, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	claims := map[string]any{}
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

func TestSignupSignsIntoPendingAuthRequest(t *testing.T) {
	s, _ := newSignupFlowServer(t)
	ctx := t.Context()
	authReq := createFlowAuthRequest(t, s, nil)
	seedSignupCode(t, s, "jane@acme.com")

	target := "/signup?" + url.Values{"state": {authReq.ID}, "back": {"https://evil.example/after-signup"}}.Encode()
	rr := postForm(s, target, signupForm("Jane@Acme.com", flowCode), "")

	code := requireCodeRedirect(t, rr, flowClientState)
	require.NotContains(t, rr.Header().Get("Location"), "evil.example", "a sign-up must never follow back")

	_, err := s.storage.GetAuthRequest(ctx, authReq.ID)
	require.ErrorIs(t, err, storage.ErrNotFound, "the auth request must be consumed")

	pw, err := s.storage.GetPassword(ctx, "jane@acme.com")
	require.NoError(t, err)
	authCode, err := s.storage.GetAuthCode(ctx, code)
	require.NoError(t, err)
	require.Equal(t, "jane@acme.com", authCode.Claims.Email)
	require.True(t, authCode.Claims.EmailVerified)
	require.Equal(t, pw.UserID, authCode.Claims.UserID)

	claims := signupIDTokenClaims(t, s, code)
	require.Equal(t, "jane@acme.com", claims["email"])
	require.Equal(t, true, claims["email_verified"])
	require.Equal(t, "Jane Smith", claims["name"])
}

func TestSignupReplayDoesNotSignInTwice(t *testing.T) {
	s, _ := newSignupFlowServer(t)
	authReq := createFlowAuthRequest(t, s, nil)
	seedSignupCode(t, s, "jane@acme.com")
	target := "/signup?state=" + authReq.ID

	first := postForm(s, target, signupForm("jane@acme.com", flowCode), "")
	requireCodeRedirect(t, first, flowClientState)

	replay := postForm(s, target, signupForm("jane@acme.com", flowCode), "")
	require.Equal(t, http.StatusBadRequest, replay.Code)
	require.Empty(t, replay.Header().Get("Location"))
	require.Contains(t, replay.Body.String(), "OTP not found or expired")
}

func TestSignupFallsBackToPasswordStep(t *testing.T) {
	oauthQuery := url.Values{
		"client_id":     {flowClientID},
		"redirect_uri":  {flowRedirectURI},
		"response_type": {responseTypeCode},
		"scope":         {"openid email"},
	}
	tests := []struct {
		name      string
		target    func(t *testing.T, s *Server) string
		wantState string
	}{
		{
			name: "expired auth request",
			target: func(t *testing.T, s *Server) string {
				a := createFlowAuthRequest(t, s, func(a *storage.AuthRequest) { a.Expiry = s.now().Add(-time.Minute) })
				return "/signup?state=" + a.ID
			},
			wantState: flowClientState,
		},
		{
			name: "auth request already logged in",
			target: func(t *testing.T, s *Server) string {
				a := createFlowAuthRequest(t, s, func(a *storage.AuthRequest) { a.LoggedIn = true })
				return "/signup?state=" + a.ID
			},
			wantState: flowClientState,
		},
		{
			name: "auth request on a non-local connector",
			target: func(t *testing.T, s *Server) string {
				a := createFlowAuthRequest(t, s, func(a *storage.AuthRequest) { a.ConnectorID = "mock" })
				return "/signup?state=" + a.ID
			},
			wantState: flowClientState,
		},
		{
			name: "missing state with client parameters",
			target: func(t *testing.T, s *Server) string {
				return "/signup?" + oauthQuery.Encode()
			},
			wantState: "",
		},
		{
			name: "state is the client's own state, not an auth request",
			target: func(t *testing.T, s *Server) string {
				q := url.Values{"state": {"opaque-client-state"}}
				for k, v := range oauthQuery {
					q[k] = v
				}
				return "/signup?" + q.Encode()
			},
			wantState: "opaque-client-state",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newSignupFlowServer(t)
			seedSignupCode(t, s, "jane@acme.com")

			rr := postForm(s, tc.target(t, s), signupForm("jane@acme.com", flowCode), "")
			require.Equal(t, http.StatusSeeOther, rr.Code, rr.Body.String())
			require.True(t, strings.HasPrefix(rr.Header().Get("Location"), "/auth/local?"), rr.Header().Get("Location"))

			page := followDexRedirects(t, s, rr)
			require.Equal(t, http.StatusOK, page.Code)
			body := page.Body.String()
			require.Contains(t, body, accountCreatedNotice)
			require.Contains(t, body, `value="jane@acme.com"`)
			require.Contains(t, body, `name="password"`)
			require.Contains(t, body, `autocomplete="current-password"`)
			require.NotContains(t, body, loginHintParam, "the hand-off must not leak into the page's links")

			// The fallback must not be a dead end: the password step completes the original client flow.
			m := formActionRE.FindStringSubmatch(body)
			require.Len(t, m, 2)
			login := postForm(s, html.UnescapeString(m[1]), url.Values{"login": {"jane@acme.com"}, "password": {"password123"}}, "")
			requireCodeRedirect(t, login, tc.wantState)
		})
	}
}

func TestSignupWithoutAnyClientRendersPasswordStep(t *testing.T) {
	s, _ := newSignupFlowServer(t)
	seedSignupCode(t, s, "jane@acme.com")

	rr := postForm(s, "/signup", signupForm("jane@acme.com", flowCode), "")

	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	require.Contains(t, body, accountCreatedNotice)
	require.Contains(t, body, `value="jane@acme.com"`)
	require.Contains(t, body, `name="password"`)
}

func TestJSONSignupDoesNotSignIn(t *testing.T) {
	s, _ := newSignupFlowServer(t)
	authReq := createFlowAuthRequest(t, s, nil)
	seedSignupCode(t, s, "jane@acme.com")

	rr := postJSON(s, "/signup?state="+authReq.ID, map[string]string{
		"email": "jane@acme.com", "username": "Jane Smith", "password": "password123", "token": flowCode, "csrf": flowCSRF,
	}, "")

	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var resp signupResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	require.Equal(t, "jane@acme.com", resp.Email)
	got, err := s.storage.GetAuthRequest(t.Context(), authReq.ID)
	require.NoError(t, err)
	require.False(t, got.LoggedIn)
}

func TestSignupFormAutocomplete(t *testing.T) {
	s, _ := newSignupFlowServer(t)
	authReq := createFlowAuthRequest(t, s, nil)

	for _, target := range []string{"/signup?state=" + authReq.ID, "/signup?state=" + authReq.ID + "&email=jane%40acme.com"} {
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, target, nil))
		require.Equal(t, http.StatusOK, rr.Code)
		body := rr.Body.String()
		require.Regexp(t, `id="email" name="email" type="email" autocomplete="username"`, body)
		require.Contains(t, body, `autocomplete="new-password"`)
	}

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/auth/local/login?state="+authReq.ID, nil))
	require.Equal(t, http.StatusOK, rr.Code)
	require.Contains(t, rr.Body.String(), `name="login" type="email" autocomplete="username"`)
}

func TestSignupWrongCodesRevokeCode(t *testing.T) {
	s, _ := newSignupFlowServer(t)
	ctx := t.Context()
	seedSignupCode(t, s, "jane@acme.com")

	for i := 1; i <= 6; i++ {
		rr := postForm(s, "/signup", signupForm("jane@acme.com", "000000"), "")
		require.Equal(t, http.StatusBadRequest, rr.Code)
		switch {
		case i < maxWrongCodes:
			require.Contains(t, rr.Body.String(), "Invalid OTP", "attempt %d", i)
		case i == maxWrongCodes:
			require.Contains(t, rr.Body.String(), tooManyWrongCodeMsg, "attempt %d", i)
		default:
			require.Contains(t, rr.Body.String(), "OTP not found or expired", "attempt %d", i)
		}
	}
	_, err := s.storage.GetSignupToken(ctx, "jane@acme.com")
	require.ErrorIs(t, err, storage.ErrNotFound)

	rr := postForm(s, "/signup", signupForm("jane@acme.com", flowCode), "")
	require.Equal(t, http.StatusBadRequest, rr.Code, "the right code must not work once the code is revoked")
	_, err = s.storage.GetPassword(ctx, "jane@acme.com")
	require.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPasswordResetWrongCodesRevokeCode(t *testing.T) {
	s, _ := newSignupFlowServer(t)
	ctx := t.Context()
	hash, err := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.DefaultCost)
	require.NoError(t, err)
	require.NoError(t, s.storage.CreatePassword(ctx, storage.Password{Email: "jane@acme.com", Hash: hash, Username: "Jane", UserID: "jane-id"}))
	seedSignupCode(t, s, "jane@acme.com")

	reset := func(code string) signupErrorResponse {
		rr := postJSON(s, "/password_reset", map[string]string{"email": "jane@acme.com", "password": "new-password", "token": code, "csrf": flowCSRF}, "")
		require.Equal(t, http.StatusBadRequest, rr.Code)
		var resp signupErrorResponse
		require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
		return resp
	}
	for i := 1; i < maxWrongCodes; i++ {
		require.Contains(t, reset("000000").Description, "Invalid OTP")
	}
	require.Equal(t, tooManyWrongCodeMsg, reset("000000").Description)
	require.Contains(t, reset(flowCode).Description, "OTP not found or expired")

	pw, err := s.storage.GetPassword(ctx, "jane@acme.com")
	require.NoError(t, err)
	require.NoError(t, bcrypt.CompareHashAndPassword(pw.Hash, []byte("old-password")), "the password must not change")
}

func TestExpiredCodeIsRejectedBeforeComparing(t *testing.T) {
	s, clock := newSignupFlowServer(t)
	seedSignupCode(t, s, "jane@acme.com")
	clock.Advance(6 * time.Minute)

	rr := postForm(s, "/signup", signupForm("jane@acme.com", "000000"), "")

	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "OTP Expired")
	_, blocked := s.limits.wrongCodes.blocked(limitKey("jane@acme.com"))
	require.False(t, blocked)
	require.Empty(t, s.limits.wrongCodes.store.entries, "an expired code must not count as a wrong guess")
}

func TestGetRandomCodeReadsCryptoSource(t *testing.T) {
	orig := codeRandReader
	t.Cleanup(func() { codeRandReader = orig })

	codeRandReader = bytes.NewReader(make([]byte, 64))
	require.Equal(t, "000000", getRandomCode(6), "codes must come from the crypto/rand reader, not a time-seeded PRNG")
}

func TestGetRandomCodeDistribution(t *testing.T) {
	const codes, length = 20000, 6
	var counts [10]int
	for i := 0; i < codes; i++ {
		c := getRandomCode(length)
		require.Len(t, c, length)
		for _, d := range c {
			require.True(t, d >= '0' && d <= '9')
			counts[d-'0']++
		}
	}
	expected := float64(codes*length) / 10
	for digit, n := range counts {
		require.InDelta(t, expected, float64(n), expected*0.05, "digit %d is skewed", digit)
	}

	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		c := getRandomCode(16)
		require.False(t, seen[c], "back-to-back codes repeated")
		seen[c] = true
	}
}

func TestSignupTokenRateLimit(t *testing.T) {
	t.Run("per email", func(t *testing.T) {
		s, _ := newSignupFlowServer(t)
		for i := 0; i < codeSendPerEmail; i++ {
			rr := postJSON(s, "/signup-token", signupTokenRequest{Email: "jane@acme.com"}, "203.0.113.1:1000")
			require.NotEqual(t, http.StatusTooManyRequests, rr.Code, "request %d", i+1)
		}
		rr := postJSON(s, "/signup-token", signupTokenRequest{Email: "JANE@acme.com"}, "203.0.113.2:1000")
		require.Equal(t, http.StatusTooManyRequests, rr.Code)
		require.NotEmpty(t, rr.Header().Get("Retry-After"))
		var resp signupErrorResponse
		require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
		require.Equal(t, rateLimitedError, resp.Error)
		require.Equal(t, "Too many attempts. Try again in 15 minutes.", resp.Description)
	})
	t.Run("per ip", func(t *testing.T) {
		s, _ := newSignupFlowServer(t)
		for i := 0; i < codeSendPerIP; i++ {
			rr := postJSON(s, "/signup-token", signupTokenRequest{Email: "user" + string(rune('a'+i)) + "@acme.com"}, "203.0.113.9:1000")
			require.NotEqual(t, http.StatusTooManyRequests, rr.Code, "request %d", i+1)
		}
		rr := postJSON(s, "/signup-token", signupTokenRequest{Email: "fresh@acme.com"}, "203.0.113.9:2000")
		require.Equal(t, http.StatusTooManyRequests, rr.Code)
	})
	t.Run("password reset shares the email budget", func(t *testing.T) {
		s, _ := newSignupFlowServer(t)
		for i := 0; i < codeSendPerEmail; i++ {
			postJSON(s, "/reset-token", signupTokenRequest{Email: "jane@acme.com"}, "")
		}
		rr := postJSON(s, "/reset-token", signupTokenRequest{Email: "jane@acme.com"}, "")
		require.Equal(t, http.StatusTooManyRequests, rr.Code)
	})
}

func TestSignupSubmitRateLimitHTML(t *testing.T) {
	s, _ := newSignupFlowServer(t)
	for i := 0; i < codeVerifyPerEmail; i++ {
		rr := postForm(s, "/signup", signupForm("jane@acme.com", "000000"), "")
		require.NotEqual(t, http.StatusTooManyRequests, rr.Code)
	}
	rr := postForm(s, "/signup", signupForm("jane@acme.com", "000000"), "")
	require.Equal(t, http.StatusTooManyRequests, rr.Code)
	require.Contains(t, rr.Body.String(), `role="alert">Too many attempts. Try again in 15 minutes.</div>`)
	require.Contains(t, rr.Body.String(), `name="email"`)
}

func TestCheckHandlerRateLimit(t *testing.T) {
	s, clock := newSignupFlowServer(t)
	authReq := createFlowAuthRequest(t, s, nil)
	target := "/check-handler?state=" + authReq.ID
	for i := 0; i < checkHandlerPerIP; i++ {
		rr := postForm(s, target, url.Values{"login": {"someone@acme.com"}}, "")
		require.Equal(t, http.StatusOK, rr.Code, "request %d", i+1)
	}
	rr := postForm(s, target, url.Values{"login": {"someone@acme.com"}}, "")
	require.Equal(t, http.StatusTooManyRequests, rr.Code)
	require.Contains(t, rr.Body.String(), "Too many attempts. Try again in 1 minute.")

	other := postForm(s, target, url.Values{"login": {"someone@acme.com"}}, "198.51.100.7:1000")
	require.Equal(t, http.StatusOK, other.Code, "the limit is per client IP")

	clock.Advance(checkHandlerWindow)
	rr = postForm(s, target, url.Values{"login": {"someone@acme.com"}}, "")
	require.Equal(t, http.StatusOK, rr.Code)
}

func TestClientIPUsesTrustedRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:4000"
	require.Equal(t, "10.0.0.1", clientIP(req))
	req = req.WithContext(WithRemoteIP(req.Context(), "198.51.100.20"))
	require.Equal(t, "198.51.100.20", clientIP(req))
}

func TestPasswordLoginLockout(t *testing.T) {
	s, clock := newSignupFlowServer(t)
	ctx := t.Context()
	hash, err := bcrypt.GenerateFromPassword([]byte("right-password"), bcrypt.DefaultCost)
	require.NoError(t, err)
	require.NoError(t, s.storage.CreatePassword(ctx, storage.Password{Email: "jane@acme.com", Hash: hash, Username: "Jane", UserID: "jane-id"}))
	authReq := createFlowAuthRequest(t, s, nil)
	target := "/auth/local/login?state=" + authReq.ID
	login := func(password, remote string) *httptest.ResponseRecorder {
		return postForm(s, target, url.Values{"login": {"jane@acme.com"}, "password": {password}}, remote)
	}

	for i := 0; i < loginFailuresPerAccount; i++ {
		rr := login("wrong-password", "")
		require.Equal(t, http.StatusUnauthorized, rr.Code, "attempt %d", i+1)
	}

	right := login("right-password", "203.0.113.50:1000")
	wrong := login("wrong-password", "203.0.113.51:1000")
	require.Equal(t, http.StatusTooManyRequests, right.Code, "a locked account must refuse even the right password")
	require.Equal(t, right.Code, wrong.Code)
	require.Equal(t, right.Body.String(), wrong.Body.String(), "the locked response must not reveal whether the password was right")
	require.Contains(t, right.Body.String(), "Too many attempts. Try again in 15 minutes.")
	require.Empty(t, right.Header().Get("Location"))

	clock.Advance(loginLockout)
	fresh := createFlowAuthRequest(t, s, nil)
	after := postForm(s, "/auth/local/login?state="+fresh.ID, url.Values{"login": {"jane@acme.com"}, "password": {"right-password"}}, "")
	requireCodeRedirect(t, after, flowClientState)
}

func TestPasswordLoginSuccessResetsFailures(t *testing.T) {
	s, _ := newSignupFlowServer(t)
	ctx := t.Context()
	hash, err := bcrypt.GenerateFromPassword([]byte("right-password"), bcrypt.DefaultCost)
	require.NoError(t, err)
	require.NoError(t, s.storage.CreatePassword(ctx, storage.Password{Email: "jane@acme.com", Hash: hash, Username: "Jane", UserID: "jane-id"}))

	for round := 0; round < 2; round++ {
		authReq := createFlowAuthRequest(t, s, nil)
		target := "/auth/local/login?state=" + authReq.ID
		for i := 0; i < loginFailuresPerAccount-1; i++ {
			require.Equal(t, http.StatusUnauthorized, postForm(s, target, url.Values{"login": {"jane@acme.com"}, "password": {"nope"}}, "203.0.113.60:1").Code)
		}
		requireCodeRedirect(t, postForm(s, target, url.Values{"login": {"jane@acme.com"}, "password": {"right-password"}}, "203.0.113.60:1"), flowClientState)
	}
}

func TestPasswordLoginPerIPLimit(t *testing.T) {
	s, _ := newSignupFlowServer(t)
	authReq := createFlowAuthRequest(t, s, nil)
	target := "/auth/local/login?state=" + authReq.ID
	for i := 0; i < loginFailuresPerIP; i++ {
		email := "nobody" + strings.Repeat("x", i) + "@acme.com"
		require.Equal(t, http.StatusUnauthorized, postForm(s, target, url.Values{"login": {email}, "password": {"guess"}}, "203.0.113.70:1").Code)
	}
	rr := postForm(s, target, url.Values{"login": {"another@acme.com"}, "password": {"guess"}}, "203.0.113.70:2")
	require.Equal(t, http.StatusTooManyRequests, rr.Code)
	require.Contains(t, rr.Body.String(), "Too many attempts.")
}

func TestIsSafeBackLink(t *testing.T) {
	root := &Server{issuerURL: url.URL{Scheme: "https", Host: "auth.example", Path: ""}}
	sub := &Server{issuerURL: url.URL{Scheme: "https", Host: "auth.example", Path: "/dex"}}
	tests := []struct {
		link     string
		wantRoot bool
		wantSub  bool
	}{
		{"/auth?client_id=x", true, false},
		{"/dex/auth?client_id=x", true, true},
		{"/dex", true, true},
		{"/dexevil/auth", true, false},
		{"/dex/../evil", true, false},
		{"https://evil.example", false, false},
		{"http://evil.example/dex/auth", false, false},
		{"//evil.example", false, false},
		{"//evil.example/dex/auth", false, false},
		{`/\evil.example`, false, false},
		{"/\t/evil.example", false, false},
		{"/\n/evil.example", false, false},
		{"javascript:alert(1)", false, false},
		{"evil.example", false, false},
		{"", false, false},
	}
	for _, tc := range tests {
		require.Equal(t, tc.wantRoot, root.isSafeBackLink(tc.link), "root issuer: %q", tc.link)
		require.Equal(t, tc.wantSub, sub.isSafeBackLink(tc.link), "issuer /dex: %q", tc.link)
	}
}

func TestPasswordResetDoesNotFollowOffsiteBack(t *testing.T) {
	for _, back := range []string{"https://evil.example", "//evil.example", `/\evil.example`} {
		t.Run(back, func(t *testing.T) {
			s, _ := newSignupFlowServer(t)
			ctx := t.Context()
			hash, err := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.DefaultCost)
			require.NoError(t, err)
			require.NoError(t, s.storage.CreatePassword(ctx, storage.Password{Email: "jane@acme.com", Hash: hash, Username: "Jane", UserID: "jane-id"}))
			seedSignupCode(t, s, "jane@acme.com")

			target := "/password_reset?" + url.Values{"back": {back}, "client_id": {flowClientID}}.Encode()
			form := url.Values{"email": {"jane@acme.com"}, "password": {"new-password"}, "token": {flowCode}, "csrf": {flowCSRF}}
			rr := postForm(s, target, form, "")

			require.Equal(t, http.StatusSeeOther, rr.Code, rr.Body.String())
			loc := rr.Header().Get("Location")
			require.True(t, strings.HasPrefix(loc, "/auth?"), loc)
			require.NotContains(t, loc, "evil.example")
		})
	}

	t.Run("safe back is followed", func(t *testing.T) {
		s, _ := newSignupFlowServer(t)
		ctx := t.Context()
		hash, err := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.DefaultCost)
		require.NoError(t, err)
		require.NoError(t, s.storage.CreatePassword(ctx, storage.Password{Email: "jane@acme.com", Hash: hash, Username: "Jane", UserID: "jane-id"}))
		seedSignupCode(t, s, "jane@acme.com")

		target := "/password_reset?" + url.Values{"back": {"/auth/local/login?state=abc"}}.Encode()
		form := url.Values{"email": {"jane@acme.com"}, "password": {"new-password"}, "token": {flowCode}, "csrf": {flowCSRF}}
		rr := postForm(s, target, form, "")
		require.Equal(t, http.StatusSeeOther, rr.Code)
		require.Equal(t, "/auth/local/login?state=abc", rr.Header().Get("Location"))
	})
}

func TestPagesDoNotRenderOffsiteBack(t *testing.T) {
	s, _ := newSignupFlowServer(t)
	authReq := createFlowAuthRequest(t, s, nil)
	for _, back := range []string{"https://evil.example", "//evil.example"} {
		for _, page := range []string{"/signup", "/password_reset", "/auth/local/login"} {
			target := page + "?" + url.Values{"state": {authReq.ID}, "back": {back}}.Encode()
			rr := httptest.NewRecorder()
			s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, target, nil))
			require.Equal(t, http.StatusOK, rr.Code, target)
			require.NotContains(t, rr.Body.String(), `href="`+back, target)
		}
	}
}
