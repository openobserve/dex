package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/storage"
)

func TestResetGroupsOverridesLoginAndRefreshClaims(t *testing.T) {
	t.Setenv("RESET_GROUPS", "admin,ops")
	httpServer, s := newTestServer(t, nil)
	defer httpServer.Close()
	ctx := t.Context()
	require.NoError(t, s.storage.CreateClient(ctx, storage.Client{ID: flowClientID, Secret: flowClientSecret, RedirectURIs: []string{flowRedirectURI}}))
	authReq := createFlowAuthRequest(t, s, func(a *storage.AuthRequest) {
		a.ConnectorID = "mock"
		a.Scopes = append(a.Scopes, "groups", "offline_access")
	})

	// The mock connector returns real groups ("authors"); the hack must replace them.
	cb := httptest.NewRecorder()
	s.ServeHTTP(cb, httptest.NewRequest(http.MethodGet, "/callback?state="+authReq.ID, nil))
	code := requireCodeRedirect(t, s, cb, flowClientState)

	form := url.Values{"grant_type": {oauth2.GrantTypeAuthorizationCode}, "code": {code}, "redirect_uri": {flowRedirectURI}}
	tok := postToken(t, s, form)
	require.Equal(t, []any{"admin", "ops"}, idTokenClaims(t, tok.IDToken)["groups"], "login must use RESET_GROUPS")
	require.NotEmpty(t, tok.RefreshToken)

	refreshed := postToken(t, s, url.Values{"grant_type": {oauth2.GrantTypeRefreshToken}, "refresh_token": {tok.RefreshToken}})
	require.Equal(t, []any{"admin", "ops"}, idTokenClaims(t, refreshed.IDToken)["groups"], "refresh must use RESET_GROUPS")
}

type resetGroupsToken struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

func postToken(t *testing.T, s *Server, form url.Values) resetGroupsToken {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(flowClientID, flowClientSecret)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var tok resetGroupsToken
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&tok))
	return tok
}
