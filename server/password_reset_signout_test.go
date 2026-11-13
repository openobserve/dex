package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/storage"
)

// seedSignedInUser gives a password account a browser session and a refresh
// token for flowClientID on connectorID. It returns the session ID, the refresh
// token's storage ID, and the refresh token as a client would send it.
func seedSignedInUser(t *testing.T, s *Server, email, userID, connectorID string) (sessionID, refreshID, refreshToken string) {
	t.Helper()
	ctx := t.Context()
	now := s.now()

	refresh := storage.RefreshToken{
		ID:          storage.NewID(),
		Token:       storage.NewID(),
		ClientID:    flowClientID,
		ConnectorID: connectorID,
		Scopes:      []string{"openid", "email", "offline_access"},
		CreatedAt:   now,
		LastUsed:    now,
		Claims:      storage.Claims{UserID: userID, Username: email, Email: email, EmailVerified: true},
	}
	require.NoError(t, s.storage.CreateRefresh(ctx, refresh))
	require.NoError(t, s.storage.CreateOfflineSessions(ctx, storage.OfflineSessions{
		UserID:  userID,
		ConnID:  connectorID,
		Refresh: map[string]*storage.RefreshTokenRef{flowClientID: {ID: refresh.ID, ClientID: flowClientID}},
	}))

	session := storage.AuthSession{
		ID:          storage.NewID(),
		Secret:      storage.NewID(),
		UserID:      userID,
		ConnectorID: connectorID,
		ClientStates: map[string]*storage.ClientAuthState{
			flowClientID: {AuthenticatedAt: now, LastActivity: now},
		},
		CreatedAt:      now,
		LastActivity:   now,
		AbsoluteExpiry: now.Add(24 * time.Hour),
		IdleExpiry:     now.Add(time.Hour),
	}
	require.NoError(t, s.storage.CreateAuthSession(ctx, session))

	token, err := internal.Marshal(&internal.RefreshToken{RefreshId: refresh.ID, Token: refresh.Token})
	require.NoError(t, err)
	return session.ID, refresh.ID, token
}

func createPasswordAccount(t *testing.T, s *Server, email, userID, password string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err)
	require.NoError(t, s.storage.CreatePassword(t.Context(), storage.Password{Email: email, Hash: hash, Username: email, UserID: userID}))
}

func refreshGrant(s *Server, refreshToken string) *httptest.ResponseRecorder {
	form := url.Values{"grant_type": {oauth2.GrantTypeRefreshToken}, "refresh_token": {refreshToken}}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(flowClientID, flowClientSecret)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return rr
}

func TestPasswordResetEndsSessionsAndRefreshTokens(t *testing.T) {
	s, _ := newSignupFlowServer(t)
	ctx := t.Context()

	createPasswordAccount(t, s, "jane@acme.com", "jane-id", "old-password")
	createPasswordAccount(t, s, "bob@acme.com", "bob-id", "bob-password")
	janeSession, _, janeRefresh := seedSignedInUser(t, s, "jane@acme.com", "jane-id", "local")
	bobSession, bobRefreshID, _ := seedSignedInUser(t, s, "bob@acme.com", "bob-id", "local")
	// Jane's sign-in through another connector does not use the local password.
	janeOtherSession, _, _ := seedSignedInUser(t, s, "jane@acme.com", "jane-id", "other")

	resetBody := func(code string) map[string]string {
		return map[string]string{"email": "jane@acme.com", "password": "new-password", "token": code, "csrf": flowCSRF}
	}
	seedSignupCode(t, s, "jane@acme.com")

	// A rejected reset must leave the account's sign-ins alone.
	rr := postJSON(s, "/password_reset", resetBody("000000"), "")
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	_, err := s.storage.GetAuthSession(ctx, janeSession)
	require.NoError(t, err, "a failed reset must not end sessions")

	rr = postJSON(s, "/password_reset", resetBody(flowCode), "")
	require.Equal(t, http.StatusNoContent, rr.Code, rr.Body.String())

	_, err = s.storage.GetAuthSession(ctx, janeSession)
	require.ErrorIs(t, err, storage.ErrNotFound, "the reset account's session must be deleted")
	offline, err := s.storage.GetOfflineSessions(ctx, "jane-id", "local")
	require.NoError(t, err)
	require.Empty(t, offline.Refresh, "the reset account's refresh tokens must be revoked")
	rr = refreshGrant(s, janeRefresh)
	require.Equal(t, http.StatusBadRequest, rr.Code, "a refresh token issued before the reset must stop working")
	require.Contains(t, rr.Body.String(), "invalid_grant")

	_, err = s.storage.GetAuthSession(ctx, janeOtherSession)
	require.NoError(t, err, "a session through another connector does not depend on the local password")
	_, err = s.storage.GetAuthSession(ctx, bobSession)
	require.NoError(t, err, "other users' sessions must survive")
	// Checked in storage rather than through /token: a successful refresh on the
	// memory store re-enters its lock from inside UpdateRefreshToken and hangs.
	bobOffline, err := s.storage.GetOfflineSessions(ctx, "bob-id", "local")
	require.NoError(t, err)
	require.Contains(t, bobOffline.Refresh, flowClientID, "other users' refresh tokens must survive")
	_, err = s.storage.GetRefresh(ctx, bobRefreshID)
	require.NoError(t, err, "other users' refresh tokens must survive")
}

// With the sessions feature off there are no auth sessions, but refresh tokens
// still exist and must still be revoked.
func TestPasswordResetRevokesRefreshTokensWithoutSessions(t *testing.T) {
	s, _ := newSignupFlowServer(t)
	ctx := t.Context()

	createPasswordAccount(t, s, "jane@acme.com", "jane-id", "old-password")
	sessionID, refreshID, janeRefresh := seedSignedInUser(t, s, "jane@acme.com", "jane-id", "local")
	require.NoError(t, s.storage.DeleteAuthSession(ctx, sessionID))

	seedSignupCode(t, s, "jane@acme.com")
	rr := postJSON(s, "/password_reset", map[string]string{"email": "jane@acme.com", "password": "new-password", "token": flowCode, "csrf": flowCSRF}, "")
	require.Equal(t, http.StatusNoContent, rr.Code, rr.Body.String())

	// Checked in storage first: a live token would reach the memory store's
	// re-entrant refresh path and hang instead of failing.
	_, err := s.storage.GetRefresh(ctx, refreshID)
	require.ErrorIs(t, err, storage.ErrNotFound, "the refresh token must be deleted")
	rr = refreshGrant(s, janeRefresh)
	require.Equal(t, http.StatusBadRequest, rr.Code, "a refresh token issued before the reset must stop working")
}
