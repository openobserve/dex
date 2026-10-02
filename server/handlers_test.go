package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"
	"time"

	gosundheit "github.com/AppsFlyer/go-sundheit"
	"github.com/AppsFlyer/go-sundheit/checks"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/dexidp/dex/storage"
)

func TestHandleHealth(t *testing.T) {
	httpServer, server := newTestServer(t, nil)
	defer httpServer.Close()

	rr := httptest.NewRecorder()
	server.ServeHTTP(rr, httptest.NewRequest("GET", "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 got %d", rr.Code)
	}
}

func TestHandleDiscovery(t *testing.T) {
	httpServer, server := newTestServer(t, nil)
	defer httpServer.Close()

	rr := httptest.NewRecorder()
	server.ServeHTTP(rr, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 got %d", rr.Code)
	}

	var res discovery
	err := json.NewDecoder(rr.Result().Body).Decode(&res)
	require.NoError(t, err)
	require.Equal(t, discovery{
		Issuer:         httpServer.URL,
		Auth:           fmt.Sprintf("%s/auth", httpServer.URL),
		Token:          fmt.Sprintf("%s/token", httpServer.URL),
		Keys:           fmt.Sprintf("%s/keys", httpServer.URL),
		UserInfo:       fmt.Sprintf("%s/userinfo", httpServer.URL),
		DeviceEndpoint: fmt.Sprintf("%s/device/code", httpServer.URL),
		Introspect:     fmt.Sprintf("%s/token/introspect", httpServer.URL),
		Registration:   fmt.Sprintf("%s/register", httpServer.URL),
		GrantTypes: []string{
			"authorization_code",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code",
			"urn:ietf:params:oauth:grant-type:token-exchange",
		},
		ResponseTypes: []string{
			"code",
		},
		Subjects: []string{
			"public",
		},
		IDTokenAlgs: []string{
			"RS256",
		},
		CodeChallengeAlgs: []string{
			"S256",
			"plain",
		},
		Scopes: []string{
			"openid",
			"email",
			"groups",
			"profile",
			"offline_access",
		},
		AuthMethods: []string{
			"client_secret_basic",
			"client_secret_post",
		},
		Claims: []string{
			"iss",
			"sub",
			"aud",
			"iat",
			"exp",
			"email",
			"email_verified",
			"locale",
			"name",
			"preferred_username",
			"at_hash",
		},
	}, res)
}

func TestHandleHealthFailure(t *testing.T) {
	httpServer, server := newTestServer(t, func(c *Config) {
		c.HealthChecker = gosundheit.New()

		c.HealthChecker.RegisterCheck(
			&checks.CustomCheck{
				CheckName: "fail",
				CheckFunc: func(_ context.Context) (details interface{}, err error) {
					return nil, errors.New("error")
				},
			},
			gosundheit.InitiallyPassing(false),
			gosundheit.ExecutionPeriod(1*time.Second),
		)
	})
	defer httpServer.Close()

	rr := httptest.NewRecorder()
	server.ServeHTTP(rr, httptest.NewRequest("GET", "/healthz", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 got %d", rr.Code)
	}
}

type emptyStorage struct {
	storage.Storage
}

func (*emptyStorage) GetAuthRequest(context.Context, string) (storage.AuthRequest, error) {
	return storage.AuthRequest{}, storage.ErrNotFound
}

func TestHandleInvalidOAuth2Callbacks(t *testing.T) {
	httpServer, server := newTestServer(t, func(c *Config) {
		c.Storage = &emptyStorage{c.Storage}
	})
	defer httpServer.Close()

	tests := []struct {
		TargetURI    string
		ExpectedCode int
	}{
		{"/callback", http.StatusBadRequest},
		{"/callback?code=&state=", http.StatusBadRequest},
		{"/callback?code=AAAAAAA&state=BBBBBBB", http.StatusBadRequest},
	}

	rr := httptest.NewRecorder()

	for i, r := range tests {
		server.ServeHTTP(rr, httptest.NewRequest("GET", r.TargetURI, nil))
		if rr.Code != r.ExpectedCode {
			t.Fatalf("test %d expected %d, got %d", i, r.ExpectedCode, rr.Code)
		}
	}
}

func TestHandleInvalidSAMLCallbacks(t *testing.T) {
	httpServer, server := newTestServer(t, func(c *Config) {
		c.Storage = &emptyStorage{c.Storage}
	})
	defer httpServer.Close()

	type requestForm struct {
		RelayState string
	}
	tests := []struct {
		RequestForm  requestForm
		ExpectedCode int
	}{
		{requestForm{}, http.StatusBadRequest},
		{requestForm{RelayState: "AAAAAAA"}, http.StatusBadRequest},
	}

	rr := httptest.NewRecorder()

	for i, r := range tests {
		jsonValue, err := json.Marshal(r.RequestForm)
		if err != nil {
			t.Fatal(err.Error())
		}
		server.ServeHTTP(rr, httptest.NewRequest("POST", "/callback", bytes.NewBuffer(jsonValue)))
		if rr.Code != r.ExpectedCode {
			t.Fatalf("test %d expected %d, got %d", i, r.ExpectedCode, rr.Code)
		}
	}
}

// TestHandleAuthCode checks that it is forbidden to use same code twice
func TestHandleAuthCode(t *testing.T) {
	tests := []struct {
		name       string
		handleCode func(*testing.T, context.Context, *oauth2.Config, string)
	}{
		{
			name: "Code Reuse should return invalid_grant",
			handleCode: func(t *testing.T, ctx context.Context, oauth2Config *oauth2.Config, code string) {
				_, err := oauth2Config.Exchange(ctx, code)
				require.NoError(t, err)

				_, err = oauth2Config.Exchange(ctx, code)
				require.Error(t, err)

				oauth2Err, ok := err.(*oauth2.RetrieveError)
				require.True(t, ok)

				var errResponse struct{ Error string }
				err = json.Unmarshal(oauth2Err.Body, &errResponse)
				require.NoError(t, err)

				// invalid_grant must be returned for invalid values
				// https://tools.ietf.org/html/rfc6749#section-5.2
				require.Equal(t, errInvalidGrant, errResponse.Error)
			},
		},
		{
			name: "No Code should return invalid_request",
			handleCode: func(t *testing.T, ctx context.Context, oauth2Config *oauth2.Config, _ string) {
				_, err := oauth2Config.Exchange(ctx, "")
				require.Error(t, err)

				oauth2Err, ok := err.(*oauth2.RetrieveError)
				require.True(t, ok)

				var errResponse struct{ Error string }
				err = json.Unmarshal(oauth2Err.Body, &errResponse)
				require.NoError(t, err)

				require.Equal(t, errInvalidRequest, errResponse.Error)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()

			httpServer, s := newTestServer(t, func(c *Config) { c.Issuer += "/non-root-path" })
			defer httpServer.Close()

			p, err := oidc.NewProvider(ctx, httpServer.URL)
			require.NoError(t, err)

			var oauth2Client oauth2Client
			oauth2Client.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/callback" {
					http.Redirect(w, r, oauth2Client.config.AuthCodeURL(""), http.StatusSeeOther)
					return
				}

				q := r.URL.Query()
				require.Equal(t, q.Get("error"), "", q.Get("error_description"))

				code := q.Get("code")
				tc.handleCode(t, ctx, oauth2Client.config, code)

				w.WriteHeader(http.StatusOK)
			}))
			defer oauth2Client.server.Close()

			redirectURL := oauth2Client.server.URL + "/callback"
			client := storage.Client{
				ID:           "testclient",
				Secret:       "testclientsecret",
				RedirectURIs: []string{redirectURL},
			}
			err = s.storage.CreateClient(ctx, client)
			require.NoError(t, err)

			oauth2Client.config = &oauth2.Config{
				ClientID:     client.ID,
				ClientSecret: client.Secret,
				Endpoint:     p.Endpoint(),
				Scopes:       []string{oidc.ScopeOpenID, "email", "offline_access"},
				RedirectURL:  redirectURL,
			}

			resp, err := http.Get(oauth2Client.server.URL + "/login")
			require.NoError(t, err)

			resp.Body.Close()
		})
	}
}

func mockConnectorDataTestStorage(t *testing.T, s storage.Storage) {
	ctx := t.Context()
	c := storage.Client{
		ID:           "test",
		Secret:       "barfoo",
		RedirectURIs: []string{"foo://bar.com/", "https://auth.example.com"},
		Name:         "dex client",
		LogoURL:      "https://goo.gl/JIyzIC",
	}

	err := s.CreateClient(ctx, c)
	require.NoError(t, err)

	c1 := storage.Connector{
		ID:   "test",
		Type: "mockPassword",
		Name: "mockPassword",
		Config: []byte(`{
"username": "test",
"password": "test"
}`),
	}

	err = s.CreateConnector(ctx, c1)
	require.NoError(t, err)

	c2 := storage.Connector{
		ID:   "http://any.valid.url/",
		Type: "mock",
		Name: "mockURLID",
	}

	err = s.CreateConnector(ctx, c2)
	require.NoError(t, err)
}

func TestHandlePassword(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name                  string
		scopes                string
		offlineSessionCreated bool
	}{
		{
			name:                  "Password login, request refresh token",
			scopes:                "openid offline_access email",
			offlineSessionCreated: true,
		},
		{
			name:                  "Password login",
			scopes:                "openid email",
			offlineSessionCreated: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup a dex server.
			httpServer, s := newTestServer(t, func(c *Config) {
				c.PasswordConnector = "test"
				c.Now = time.Now
			})
			defer httpServer.Close()

			mockConnectorDataTestStorage(t, s.storage)

			makeReq := func(username, password string) *httptest.ResponseRecorder {
				u, err := url.Parse(s.issuerURL.String())
				require.NoError(t, err)

				u.Path = path.Join(u.Path, "/token")
				v := url.Values{}
				v.Add("scope", tc.scopes)
				v.Add("grant_type", "password")
				v.Add("username", username)
				v.Add("password", password)

				req, _ := http.NewRequest("POST", u.String(), bytes.NewBufferString(v.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
				req.SetBasicAuth("test", "barfoo")

				rr := httptest.NewRecorder()
				s.ServeHTTP(rr, req)

				return rr
			}

			// Check unauthorized error
			{
				rr := makeReq("test", "invalid")
				require.Equal(t, 401, rr.Code)
			}

			// Check that we received expected refresh token
			{
				rr := makeReq("test", "test")
				require.Equal(t, 200, rr.Code)

				var ref struct {
					Token string `json:"refresh_token"`
				}
				err := json.Unmarshal(rr.Body.Bytes(), &ref)
				require.NoError(t, err)

				newSess, err := s.storage.GetOfflineSessions(ctx, "0-385-28089-0", "test")
				if tc.offlineSessionCreated {
					require.NoError(t, err)
					require.Equal(t, `{"test": "true"}`, string(newSess.ConnectorData))
				} else {
					require.Error(t, storage.ErrNotFound, err)
				}
			}
		})
	}
}

func TestHandlePasswordLoginWithSkipApproval(t *testing.T) {
	ctx := t.Context()

	connID := "mockPw"
	authReqID := "test"
	expiry := time.Now().Add(100 * time.Second)
	resTypes := []string{responseTypeCode}

	tests := []struct {
		name                  string
		skipApproval          bool
		authReq               storage.AuthRequest
		expectedRes           string
		offlineSessionCreated bool
	}{
		{
			name:         "Force approval",
			skipApproval: false,
			authReq: storage.AuthRequest{
				ID:                  authReqID,
				ConnectorID:         connID,
				RedirectURI:         "cb",
				Expiry:              expiry,
				ResponseTypes:       resTypes,
				ForceApprovalPrompt: true,
			},
			expectedRes:           "/approval",
			offlineSessionCreated: false,
		},
		{
			name:         "Skip approval by server config",
			skipApproval: true,
			authReq: storage.AuthRequest{
				ID:                  authReqID,
				ConnectorID:         connID,
				RedirectURI:         "cb",
				Expiry:              expiry,
				ResponseTypes:       resTypes,
				ForceApprovalPrompt: true,
			},
			expectedRes:           "/approval",
			offlineSessionCreated: false,
		},
		{
			name:         "No skip",
			skipApproval: false,
			authReq: storage.AuthRequest{
				ID:                  authReqID,
				ConnectorID:         connID,
				RedirectURI:         "cb",
				Expiry:              expiry,
				ResponseTypes:       resTypes,
				ForceApprovalPrompt: false,
			},
			expectedRes:           "/approval",
			offlineSessionCreated: false,
		},
		{
			name:         "Skip approval",
			skipApproval: true,
			authReq: storage.AuthRequest{
				ID:                  authReqID,
				ConnectorID:         connID,
				RedirectURI:         "cb",
				Expiry:              expiry,
				ResponseTypes:       resTypes,
				ForceApprovalPrompt: false,
			},
			expectedRes:           "/auth/mockPw/cb",
			offlineSessionCreated: false,
		},
		{
			name:         "Force approval, request refresh token",
			skipApproval: false,
			authReq: storage.AuthRequest{
				ID:                  authReqID,
				ConnectorID:         connID,
				RedirectURI:         "cb",
				Expiry:              expiry,
				ResponseTypes:       resTypes,
				ForceApprovalPrompt: true,
				Scopes:              []string{"offline_access"},
			},
			expectedRes:           "/approval",
			offlineSessionCreated: true,
		},
		{
			name:         "Skip approval, request refresh token",
			skipApproval: true,
			authReq: storage.AuthRequest{
				ID:                  authReqID,
				ConnectorID:         connID,
				RedirectURI:         "cb",
				Expiry:              expiry,
				ResponseTypes:       resTypes,
				ForceApprovalPrompt: false,
				Scopes:              []string{"offline_access"},
			},
			expectedRes:           "/auth/mockPw/cb",
			offlineSessionCreated: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			httpServer, s := newTestServer(t, func(c *Config) {
				c.SkipApprovalScreen = tc.skipApproval
				c.Now = time.Now
			})
			defer httpServer.Close()

			sc := storage.Connector{
				ID:              connID,
				Type:            "mockPassword",
				Name:            "MockPassword",
				ResourceVersion: "1",
				Config:          []byte("{\"username\": \"foo\", \"password\": \"password\"}"),
			}
			if err := s.storage.CreateConnector(ctx, sc); err != nil {
				t.Fatalf("create connector: %v", err)
			}
			if _, err := s.OpenConnector(sc); err != nil {
				t.Fatalf("open connector: %v", err)
			}
			if err := s.storage.CreateAuthRequest(ctx, tc.authReq); err != nil {
				t.Fatalf("failed to create AuthRequest: %v", err)
			}

			rr := httptest.NewRecorder()

			path := fmt.Sprintf("/auth/%s/login?state=%s&back=&login=foo&password=password", connID, authReqID)
			s.handlePasswordLogin(rr, httptest.NewRequest("POST", path, nil))

			require.Equal(t, 303, rr.Code)

			resp := rr.Result()

			defer resp.Body.Close()

			cb, _ := url.Parse(resp.Header.Get("Location"))
			require.Equal(t, tc.expectedRes, cb.Path)

			offlineSession, err := s.storage.GetOfflineSessions(ctx, "0-385-28089-0", connID)
			if tc.offlineSessionCreated {
				require.NoError(t, err)
				require.NotEmpty(t, offlineSession)
			} else {
				require.Error(t, storage.ErrNotFound, err)
			}
		})
	}
}

func TestHandleConnectorCallbackWithSkipApproval(t *testing.T) {
	ctx := t.Context()

	connID := "mock"
	authReqID := "test"
	expiry := time.Now().Add(100 * time.Second)
	resTypes := []string{responseTypeCode}

	tests := []struct {
		name                  string
		skipApproval          bool
		authReq               storage.AuthRequest
		expectedRes           string
		offlineSessionCreated bool
	}{
		{
			name:         "Force approval",
			skipApproval: false,
			authReq: storage.AuthRequest{
				ID:                  authReqID,
				ConnectorID:         connID,
				RedirectURI:         "cb",
				Expiry:              expiry,
				ResponseTypes:       resTypes,
				ForceApprovalPrompt: true,
			},
			expectedRes:           "/approval",
			offlineSessionCreated: false,
		},
		{
			name:         "Skip approval by server config",
			skipApproval: true,
			authReq: storage.AuthRequest{
				ID:                  authReqID,
				ConnectorID:         connID,
				RedirectURI:         "cb",
				Expiry:              expiry,
				ResponseTypes:       resTypes,
				ForceApprovalPrompt: true,
			},
			expectedRes:           "/approval",
			offlineSessionCreated: false,
		},
		{
			name:         "Skip approval by auth request",
			skipApproval: false,
			authReq: storage.AuthRequest{
				ID:                  authReqID,
				ConnectorID:         connID,
				RedirectURI:         "cb",
				Expiry:              expiry,
				ResponseTypes:       resTypes,
				ForceApprovalPrompt: false,
			},
			expectedRes:           "/approval",
			offlineSessionCreated: false,
		},
		{
			name:         "Skip approval",
			skipApproval: true,
			authReq: storage.AuthRequest{
				ID:                  authReqID,
				ConnectorID:         connID,
				RedirectURI:         "cb",
				Expiry:              expiry,
				ResponseTypes:       resTypes,
				ForceApprovalPrompt: false,
			},
			expectedRes:           "/callback/cb",
			offlineSessionCreated: false,
		},
		{
			name:         "Force approval, request refresh token",
			skipApproval: false,
			authReq: storage.AuthRequest{
				ID:                  authReqID,
				ConnectorID:         connID,
				RedirectURI:         "cb",
				Expiry:              expiry,
				ResponseTypes:       resTypes,
				ForceApprovalPrompt: true,
				Scopes:              []string{"offline_access"},
			},
			expectedRes:           "/approval",
			offlineSessionCreated: true,
		},
		{
			name:         "Skip approval, request refresh token",
			skipApproval: true,
			authReq: storage.AuthRequest{
				ID:                  authReqID,
				ConnectorID:         connID,
				RedirectURI:         "cb",
				Expiry:              expiry,
				ResponseTypes:       resTypes,
				ForceApprovalPrompt: false,
				Scopes:              []string{"offline_access"},
			},
			expectedRes:           "/callback/cb",
			offlineSessionCreated: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			httpServer, s := newTestServer(t, func(c *Config) {
				c.SkipApprovalScreen = tc.skipApproval
				c.Now = time.Now
			})
			defer httpServer.Close()

			if err := s.storage.CreateAuthRequest(ctx, tc.authReq); err != nil {
				t.Fatalf("failed to create AuthRequest: %v", err)
			}
			rr := httptest.NewRecorder()

			path := fmt.Sprintf("/callback/%s?state=%s", connID, authReqID)
			s.handleConnectorCallback(rr, httptest.NewRequest("GET", path, nil))

			require.Equal(t, 303, rr.Code)

			resp := rr.Result()
			defer resp.Body.Close()

			cb, _ := url.Parse(resp.Header.Get("Location"))
			require.Equal(t, tc.expectedRes, cb.Path)

			offlineSession, err := s.storage.GetOfflineSessions(ctx, "0-385-28089-0", connID)
			if tc.offlineSessionCreated {
				require.NoError(t, err)
				require.NotEmpty(t, offlineSession)
			} else {
				require.Error(t, storage.ErrNotFound, err)
			}
		})
	}
}

func TestHandleTokenExchange(t *testing.T) {
	tests := []struct {
		name               string
		scope              string
		requestedTokenType string
		subjectTokenType   string
		subjectToken       string

		expectedCode      int
		expectedTokenType string
	}{
		{
			"id-for-acccess",
			"openid",
			tokenTypeAccess,
			tokenTypeID,
			"foobar",
			http.StatusOK,
			tokenTypeAccess,
		},
		{
			"id-for-id",
			"openid",
			tokenTypeID,
			tokenTypeID,
			"foobar",
			http.StatusOK,
			tokenTypeID,
		},
		{
			"id-for-default",
			"openid",
			"",
			tokenTypeID,
			"foobar",
			http.StatusOK,
			tokenTypeAccess,
		},
		{
			"access-for-access",
			"openid",
			tokenTypeAccess,
			tokenTypeAccess,
			"foobar",
			http.StatusOK,
			tokenTypeAccess,
		},
		{
			"missing-subject_token_type",
			"openid",
			tokenTypeAccess,
			"",
			"foobar",
			http.StatusBadRequest,
			"",
		},
		{
			"missing-subject_token",
			"openid",
			tokenTypeAccess,
			tokenTypeAccess,
			"",
			http.StatusBadRequest,
			"",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			httpServer, s := newTestServer(t, func(c *Config) {
				c.Storage.CreateClient(ctx, storage.Client{
					ID:     "client_1",
					Secret: "secret_1",
				})
			})
			defer httpServer.Close()
			vals := make(url.Values)
			vals.Set("grant_type", grantTypeTokenExchange)
			setNonEmpty(vals, "connector_id", "mock")
			setNonEmpty(vals, "scope", tc.scope)
			setNonEmpty(vals, "requested_token_type", tc.requestedTokenType)
			setNonEmpty(vals, "subject_token_type", tc.subjectTokenType)
			setNonEmpty(vals, "subject_token", tc.subjectToken)
			setNonEmpty(vals, "client_id", "client_1")
			setNonEmpty(vals, "client_secret", "secret_1")

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, httpServer.URL+"/token", strings.NewReader(vals.Encode()))
			req.Header.Set("content-type", "application/x-www-form-urlencoded")

			s.handleToken(rr, req)

			require.Equal(t, tc.expectedCode, rr.Code, rr.Body.String())
			require.Equal(t, "application/json", rr.Result().Header.Get("content-type"))
			if tc.expectedCode == http.StatusOK {
				var res accessTokenResponse
				err := json.NewDecoder(rr.Result().Body).Decode(&res)
				require.NoError(t, err)
				require.Equal(t, tc.expectedTokenType, res.IssuedTokenType)
			}
		})
	}
}

func setNonEmpty(vals url.Values, key, value string) {
	if value != "" {
		vals.Set(key, value)
	}
}

func TestHandleClientRegistration(t *testing.T) {
	tests := []struct {
		name               string
		requestBody        clientRegistrationRequest
		expectedStatusCode int
		validateResponse   func(t *testing.T, resp clientRegistrationResponse)
	}{
		{
			name: "successful registration with minimal fields",
			requestBody: clientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
			},
			expectedStatusCode: http.StatusCreated,
			validateResponse: func(t *testing.T, resp clientRegistrationResponse) {
				require.NotEmpty(t, resp.ClientID)
				require.NotEmpty(t, resp.ClientSecret)
				require.Equal(t, int64(0), resp.ClientSecretExpiresAt)
				require.Equal(t, []string{"https://example.com/callback"}, resp.RedirectURIs)
				require.Equal(t, "client_secret_basic", resp.TokenEndpointAuthMethod)
				require.Equal(t, []string{"authorization_code", "refresh_token"}, resp.GrantTypes)
				require.Equal(t, []string{"code"}, resp.ResponseTypes)
			},
		},
		{
			name: "successful registration with all fields",
			requestBody: clientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback", "https://example.com/callback2"},
				ClientName:              "Test Client",
				TokenEndpointAuthMethod: "client_secret_post",
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
				Scope:                   "openid email profile",
				LogoURI:                 "https://example.com/logo.png",
			},
			expectedStatusCode: http.StatusCreated,
			validateResponse: func(t *testing.T, resp clientRegistrationResponse) {
				require.NotEmpty(t, resp.ClientID)
				require.NotEmpty(t, resp.ClientSecret)
				require.Equal(t, "Test Client", resp.ClientName)
				require.Equal(t, "client_secret_post", resp.TokenEndpointAuthMethod)
				require.Equal(t, []string{"authorization_code"}, resp.GrantTypes)
				require.Equal(t, []string{"code"}, resp.ResponseTypes)
				require.Equal(t, "openid email profile", resp.Scope)
				require.Equal(t, "https://example.com/logo.png", resp.LogoURI)
			},
		},
		{
			name: "public client (no secret)",
			requestBody: clientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "none",
			},
			expectedStatusCode: http.StatusCreated,
			validateResponse: func(t *testing.T, resp clientRegistrationResponse) {
				require.NotEmpty(t, resp.ClientID)
				require.Empty(t, resp.ClientSecret)
				require.Equal(t, "none", resp.TokenEndpointAuthMethod)
			},
		},
		{
			name: "missing redirect_uris",
			requestBody: clientRegistrationRequest{
				ClientName: "Test Client",
			},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name: "unsupported token_endpoint_auth_method",
			requestBody: clientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "invalid_method",
			},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name: "unsupported grant_type",
			requestBody: clientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				GrantTypes:   []string{"invalid_grant"},
			},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name: "unsupported response_type",
			requestBody: clientRegistrationRequest{
				RedirectURIs:  []string{"https://example.com/callback"},
				ResponseTypes: []string{"invalid_response"},
			},
			expectedStatusCode: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			httpServer, s := newTestServer(t, nil)
			defer httpServer.Close()

			body, err := json.Marshal(tc.requestBody)
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, httpServer.URL+"/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			s.handleClientRegistration(rr, req)

			require.Equal(t, tc.expectedStatusCode, rr.Code, rr.Body.String())

			if tc.expectedStatusCode == http.StatusCreated {
				var resp clientRegistrationResponse
				err := json.NewDecoder(rr.Result().Body).Decode(&resp)
				require.NoError(t, err)
				tc.validateResponse(t, resp)

				// Verify the client was actually created in storage
				ctx := context.Background()
				client, err := s.storage.GetClient(ctx, resp.ClientID)
				require.NoError(t, err)
				require.Equal(t, resp.ClientID, client.ID)
				require.Equal(t, resp.RedirectURIs, client.RedirectURIs)
			}
		})
	}
}

func TestHandleClientRegistrationMethodNotAllowed(t *testing.T) {
	httpServer, s := newTestServer(t, nil)
	defer httpServer.Close()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, httpServer.URL+"/register", nil)

	s.handleClientRegistration(rr, req)

	require.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestHandleClientRegistrationInvalidJSON(t *testing.T) {
	httpServer, s := newTestServer(t, nil)
	defer httpServer.Close()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, httpServer.URL+"/register", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")

	s.handleClientRegistration(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleClientRegistrationWithAuth(t *testing.T) {
	tests := []struct {
		name               string
		registrationToken  string
		authHeader         string
		requestBody        clientRegistrationRequest
		expectedStatusCode int
	}{
		{
			name:              "successful registration with valid token",
			registrationToken: "secret-token-123",
			authHeader:        "Bearer secret-token-123",
			requestBody: clientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
			},
			expectedStatusCode: http.StatusCreated,
		},
		{
			name:              "missing auth header when token required",
			registrationToken: "secret-token-123",
			authHeader:        "",
			requestBody: clientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
			},
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name:              "invalid token",
			registrationToken: "secret-token-123",
			authHeader:        "Bearer wrong-token",
			requestBody: clientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
			},
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name:              "malformed auth header",
			registrationToken: "secret-token-123",
			authHeader:        "Basic secret-token-123",
			requestBody: clientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
			},
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name:              "open registration (no token configured)",
			registrationToken: "",
			authHeader:        "",
			requestBody: clientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
			},
			expectedStatusCode: http.StatusCreated,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			httpServer, s := newTestServer(t, func(c *Config) {
				c.RegistrationToken = tc.registrationToken
			})
			defer httpServer.Close()

			body, err := json.Marshal(tc.requestBody)
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, httpServer.URL+"/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}

			s.handleClientRegistration(rr, req)

			require.Equal(t, tc.expectedStatusCode, rr.Code, rr.Body.String())

			if tc.expectedStatusCode == http.StatusCreated {
				var resp clientRegistrationResponse
				err := json.NewDecoder(rr.Result().Body).Decode(&resp)
				require.NoError(t, err)
				require.NotEmpty(t, resp.ClientID)
				require.NotEmpty(t, resp.ClientSecret)

				// Verify the client was actually created in storage
				client, err := s.storage.GetClient(ctx, resp.ClientID)
				require.NoError(t, err)
				require.Equal(t, resp.ClientID, client.ID)
			}

			// Check WWW-Authenticate header on 401
			if tc.expectedStatusCode == http.StatusUnauthorized {
				wwwAuth := rr.Header().Get("WWW-Authenticate")
				require.NotEmpty(t, wwwAuth)
				require.Contains(t, wwwAuth, "Bearer")
			}
		})
	}
}

func TestHandleSignup(t *testing.T) {
	tests := []struct {
		name               string
		enableSignup       bool
		requestBody        interface{}
		expectedStatusCode int
		expectedError      string
	}{
		{
			name:         "successful signup",
			enableSignup: true,
			requestBody: map[string]string{
				"email":    "test@example.com",
				"password": "password123",
				"username": "testuser",
				"csrf":     "1234",
				"token":    "5678",
			},
			expectedStatusCode: http.StatusCreated,
		},
		{
			name:         "signup disabled",
			enableSignup: false,
			requestBody: map[string]string{
				"email":    "test@example.com",
				"password": "password123",
				"username": "testuser",
				"csrf":     "1234",
				"token":    "5678",
			},
			expectedStatusCode: http.StatusForbidden,
			expectedError:      "access_denied",
		},
		{
			name:         "missing email",
			enableSignup: true,
			requestBody: map[string]string{
				"password": "password123",
				"username": "testuser",
				"csrf":     "1234",
				"token":    "5678",
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedError:      "invalid_request",
		},
		{
			name:         "invalid email format",
			enableSignup: true,
			requestBody: map[string]string{
				"email":    "invalid-email",
				"password": "password123",
				"username": "testuser",
				"csrf":     "1234",
				"token":    "5678",
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedError:      "invalid_request",
		},
		{
			name:         "missing password",
			enableSignup: true,
			requestBody: map[string]string{
				"email":    "test@example.com",
				"username": "testuser",
				"csrf":     "1234",
				"token":    "5678",
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedError:      "invalid_request",
		},
		{
			name:         "password too short",
			enableSignup: true,
			requestBody: map[string]string{
				"email":    "test@example.com",
				"password": "short",
				"username": "testuser",
				"csrf":     "1234",
				"token":    "5678",
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedError:      "invalid_request",
		},
		{
			name:         "missing username",
			enableSignup: true,
			requestBody: map[string]string{
				"email":    "test@example.com",
				"password": "password123",
				"csrf":     "1234",
				"token":    "5678",
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedError:      "invalid_request",
		},
		{
			name:         "duplicate email",
			enableSignup: true,
			requestBody: map[string]string{
				"email":    "admin@example.com", // This email is already in the test storage
				"password": "password123",
				"username": "testuser",
				"csrf":     "1234",
				"token":    "5678",
			},
			expectedStatusCode: http.StatusConflict,
			expectedError:      "invalid_request",
		},
		{
			name:               "invalid JSON",
			enableSignup:       true,
			requestBody:        "invalid json",
			expectedStatusCode: http.StatusBadRequest,
			expectedError:      "invalid_request",
		},
		{
			name:         "invalid validation Token",
			enableSignup: true,
			requestBody: map[string]string{
				"email":    "test@example.com",
				"password": "password123",
				"username": "testuser",
				"csrf":     "1234",
				"token":    "1234",
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedError:      "invalid_request",
		},
		{
			name:         "invalid csrf Token",
			enableSignup: true,
			requestBody: map[string]string{
				"email":    "test@example.com",
				"password": "password123",
				"username": "testuser",
				"csrf":     "5678",
				"token":    "5678",
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedError:      "invalid_request",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create test server with signup enabled or disabled
			httpServer, server := newTestServer(t, func(c *Config) {
				c.EnableSignup = tc.enableSignup
			})
			defer httpServer.Close()

			// Add a test user to check duplicate email scenario
			ctx := context.Background()
			_ = server.storage.CreatePassword(ctx, storage.Password{
				Email:    "admin@example.com",
				Hash:     []byte("$2a$10$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W"),
				Username: "admin",
				UserID:   "admin-id",
			})
			_ = server.storage.CreateSignupToken(ctx, storage.SignupToken{
				Email:           "test@example.com",
				CsrfToken:       "1234",
				ValidationToken: "5678",
				Expiry:          time.Now().Add(time.Duration(5) * time.Minute),
			})
			_ = server.storage.CreateSignupToken(ctx, storage.SignupToken{
				Email:           "admin@example.com",
				CsrfToken:       "1234",
				ValidationToken: "5678",
				Expiry:          time.Now().Add(time.Duration(5) * time.Minute),
			})

			// Prepare request body
			var bodyBytes []byte
			if strBody, ok := tc.requestBody.(string); ok {
				bodyBytes = []byte(strBody)
			} else {
				bodyBytes, _ = json.Marshal(tc.requestBody)
			}

			// Make request
			req := httptest.NewRequest("POST", "/signup", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			server.ServeHTTP(rr, req)

			// Check status code
			require.Equal(t, tc.expectedStatusCode, rr.Code)

			// Check response for errors or success
			if tc.expectedError != "" {
				var errResp signupErrorResponse
				err := json.NewDecoder(rr.Body).Decode(&errResp)
				require.NoError(t, err)
				require.Equal(t, tc.expectedError, errResp.Error)
			} else if tc.expectedStatusCode == http.StatusCreated {
				var resp signupResponse
				err := json.NewDecoder(rr.Body).Decode(&resp)
				require.NoError(t, err)
				require.NotEmpty(t, resp.UserID)
				require.Equal(t, "test@example.com", resp.Email)
				require.Equal(t, "testuser", resp.Username)

				// Verify the user was created in storage
				password, err := server.storage.GetPassword(ctx, "test@example.com")
				require.NoError(t, err)
				require.Equal(t, "test@example.com", password.Email)
				require.Equal(t, "testuser", password.Username)
			}
		})
	}
}

func TestHandleSignupMethodNotAllowed(t *testing.T) {
	httpServer, server := newTestServer(t, func(c *Config) {
		c.EnableSignup = true
	})
	defer httpServer.Close()

	// Test GET method (should return signup form with 200)
	req := httptest.NewRequest("GET", "/signup", nil)
	rr := httptest.NewRecorder()

	server.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	require.Contains(t, rr.Body.String(), "Create Your Account")

	// Test unsupported method like PUT (should fail)
	req = httptest.NewRequest("PUT", "/signup", nil)
	rr = httptest.NewRecorder()

	server.ServeHTTP(rr, req)

	require.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func newO2WebSignupServer(t *testing.T) (*httptest.Server, *Server) {
	httpServer, s := newTestServer(t, func(c *Config) {
		c.EnableSignup = true
		c.Web.Dir = "../o2web"
	})
	ctx := t.Context()
	require.NoError(t, s.storage.CreatePassword(ctx, storage.Password{
		Email:    "known@example.com",
		Hash:     []byte("$2a$10$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W"),
		Username: "known",
		UserID:   "known-id",
	}))
	require.NoError(t, s.storage.CreateAuthRequest(ctx, storage.AuthRequest{
		ID:            "test",
		ConnectorID:   "local",
		RedirectURI:   "cb",
		Expiry:        time.Now().Add(100 * time.Second),
		ResponseTypes: []string{responseTypeCode},
	}))
	return httpServer, s
}

func TestCheckHandlerAccountLookup(t *testing.T) {
	tests := []struct {
		name         string
		query        string
		login        string
		wantNotice   bool
		wantPassword bool
		wantHeading  string
	}{
		{
			name:        "unknown email stays on the email step with a notice",
			query:       "state=test&back=",
			login:       "new.person@example.com",
			wantNotice:  true,
			wantHeading: "Sign in to OpenObserve",
		},
		{
			name:         "known email goes to the password step",
			query:        "state=test&back=",
			login:        "known@example.com",
			wantPassword: true,
			wantHeading:  "Sign in to OpenObserve",
		},
		{
			name:        "unknown email keeps the sign-up intent",
			query:       "state=test&back=&screen_hint=signup",
			login:       "new.person@example.com",
			wantNotice:  true,
			wantHeading: "Create your OpenObserve account",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			httpServer, s := newO2WebSignupServer(t)
			defer httpServer.Close()

			form := url.Values{"login": {tc.login}}
			req := httptest.NewRequest(http.MethodPost, "/check-handler?"+tc.query, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			s.ServeHTTP(rr, req)

			require.Equal(t, http.StatusOK, rr.Code)
			body := rr.Body.String()
			require.Contains(t, body, tc.wantHeading)
			require.Equal(t, tc.wantNotice, strings.Contains(body, "There's no password account for"))
			require.Equal(t, tc.wantPassword, strings.Contains(body, `name="password"`))
			if tc.wantNotice {
				require.Contains(t, body, "email="+url.QueryEscape(tc.login))
				require.Contains(t, body, `action="/check-handler?`)
				require.Contains(t, body, "Create account</a>")
			} else {
				require.Contains(t, body, "Forgot password?")
				require.Contains(t, body, "New here?")
			}
		})
	}
}

func TestHandleSignupPrefillsEmail(t *testing.T) {
	httpServer, s := newO2WebSignupServer(t)
	defer httpServer.Close()

	req := httptest.NewRequest(http.MethodGet, "/signup?state=test&email="+url.QueryEscape("jane@acme.com"), nil)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	require.Contains(t, body, `value="jane@acme.com"`)
	require.Contains(t, body, `data-autosend="true"`)
	require.Contains(t, body, ">Change</a>")
	for _, name := range []string{"email", "username", "password", "token", "csrf"} {
		require.Contains(t, body, `name="`+name+`"`, "signup form must still post %q", name)
	}
	require.NotContains(t, body, "password-confirm")
}

func TestHandleSignupRerenderKeepsName(t *testing.T) {
	httpServer, s := newO2WebSignupServer(t)
	defer httpServer.Close()

	form := url.Values{
		"email":    {"jane@acme.com"},
		"username": {"Jane van Smith"},
		"password": {"short"},
		"token":    {"123456"},
		"csrf":     {"abc"},
	}
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	body := rr.Body.String()
	require.Contains(t, body, `value="Jane"`)
	require.Contains(t, body, `value="van Smith"`)
	require.Contains(t, body, `value="Jane van Smith"`)
	require.NotContains(t, body, `data-autosend="true"`)
}

func TestHandleSignupTokenErrors(t *testing.T) {
	tests := []struct {
		name            string
		email           string
		wantStatus      int
		wantError       string
		wantDescription string
	}{
		{
			name:            "SSO domain is rejected",
			email:           "jane@SSO.example.com",
			wantStatus:      http.StatusBadRequest,
			wantError:       "sso_required",
			wantDescription: ssoRequiredDescription,
		},
		{
			name:       "invalid email stops after one error",
			email:      "not-an-email",
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request",
		},
		{
			name:            "email send failure is a 502",
			email:           "jane@acme.com",
			wantStatus:      http.StatusBadGateway,
			wantError:       "server_error",
			wantDescription: "We couldn't send the code. Try again in a minute.",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			httpServer, s := newO2WebSignupServer(t)
			defer httpServer.Close()
			s.DomainConnectors = []DomainSpecificConnector{{}, {Domain: "sso.example.com", Id: "sso"}}

			body, err := json.Marshal(signupTokenRequest{Email: tc.email})
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/signup-token", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			s.ServeHTTP(rr, req)

			require.Equal(t, tc.wantStatus, rr.Code)
			require.Equal(t, 1, strings.Count(rr.Body.String(), "error_description"), "exactly one error response must be written")
			var errResp signupErrorResponse
			require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
			require.Equal(t, tc.wantError, errResp.Error)
			if tc.wantDescription != "" {
				require.Equal(t, tc.wantDescription, errResp.Description)
			}
		})
	}
}

func TestHandleSignupRejectsSSODomain(t *testing.T) {
	httpServer, s := newO2WebSignupServer(t)
	defer httpServer.Close()
	s.DomainConnectors = []DomainSpecificConnector{{Domain: "sso.example.com", Id: "sso"}}

	ctx := t.Context()
	require.NoError(t, s.storage.CreateSignupToken(ctx, storage.SignupToken{
		Email:           "jane@sso.example.com",
		CsrfToken:       "1234",
		ValidationToken: "5678",
		Expiry:          time.Now().Add(5 * time.Minute),
	}))

	body, err := json.Marshal(map[string]string{
		"email":    "jane@sso.example.com",
		"password": "password123",
		"username": "Jane Smith",
		"csrf":     "1234",
		"token":    "5678",
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	var errResp signupErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	require.Equal(t, "sso_required", errResp.Error)
	_, err = s.storage.GetPassword(ctx, "jane@sso.example.com")
	require.ErrorIs(t, err, storage.ErrNotFound)
}

func TestHandleAuthorizationSignupTab(t *testing.T) {
	httpServer, s := newO2WebSignupServer(t)
	defer httpServer.Close()
	require.NoError(t, s.storage.CreateConnector(t.Context(), storage.Connector{ID: "local", Type: LocalConnector, Name: "Email"}))

	render := func(query string) string {
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/auth?"+query, nil))
		require.Equal(t, http.StatusOK, rr.Code)
		return rr.Body.String()
	}

	signIn := render("client_id=x&state=abc")
	require.Contains(t, signIn, "Sign in to OpenObserve")
	require.Contains(t, signIn, `href="/auth/local?client_id=x&amp;state=abc"`)

	signup := render("client_id=x&state=abc&screen_hint=signup")
	require.Contains(t, signup, "Create your OpenObserve account")
	require.Contains(t, signup, "Email sign-up needs a")
	require.Contains(t, signup, `href="/auth/local?client_id=x&amp;screen_hint=signup&amp;state=abc"`, "sign-up by email must go through the local connector so a dex auth request exists")
	require.Contains(t, signup, `href="/auth/mock?client_id=x&amp;screen_hint=signup&amp;state=abc"`)
}

func TestCheckHandlerPersonalEmail(t *testing.T) {
	classifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		classification := "legitimate"
		if strings.HasSuffix(r.URL.Path, "/gmail.com") {
			classification = "free"
		}
		_, _ = w.Write([]byte(`{"classification":"` + classification + `"}`))
	}))
	defer classifier.Close()

	httpServer, s := newTestServer(t, func(c *Config) {
		c.EnableSignup = true
		c.Web.Dir = "../o2web"
		c.EnableEmailValidation = true
		c.EmailValidationServerUrl = classifier.URL
	})
	defer httpServer.Close()
	require.NoError(t, s.storage.CreateAuthRequest(t.Context(), storage.AuthRequest{
		ID:            "test",
		ConnectorID:   "local",
		RedirectURI:   "cb",
		Expiry:        time.Now().Add(100 * time.Second),
		ResponseTypes: []string{responseTypeCode},
	}))

	post := func(login string) string {
		form := url.Values{"login": {login}}
		req := httptest.NewRequest(http.MethodPost, "/check-handler?state=test&back=", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		return rr.Body.String()
	}

	personal := post("jane@gmail.com")
	require.Contains(t, personal, "Personal email addresses like")
	require.NotContains(t, personal, "Create an account</a>")

	work := post("jane@acme.example")
	require.Contains(t, work, "There's no password account for")
	require.Contains(t, work, "email="+url.QueryEscape("jane@acme.example"))
}
