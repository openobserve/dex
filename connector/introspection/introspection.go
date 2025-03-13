// Package introspection implements token validation through OAuth 2.0 introspection endpoints.
package introspection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/dexidp/dex/connector"
	groups_pkg "github.com/dexidp/dex/pkg/groups"
	"github.com/dexidp/dex/pkg/httpclient"
)

// Config holds configuration options for Introspection token validation.
type Config struct {
	IntrospectionURL string   `json:"introspectionURL"`
	ClientID         string   `json:"clientID"`
	ClientSecret     string   `json:"clientSecret"`
	Scopes           []string `json:"scopes"` // Optional scopes to validate

	// Certificates for SSL validation
	RootCAs []string `json:"rootCAs"`

	// Override the value of email_verified to true in the returned claims
	InsecureSkipEmailVerified bool `json:"insecureSkipEmailVerified"`

	// InsecureEnableGroups enables groups claims
	InsecureEnableGroups bool     `json:"insecureEnableGroups"`
	AllowedGroups        []string `json:"allowedGroups"`

	// Disable certificate verification
	InsecureSkipVerify bool `json:"insecureSkipVerify"`

	// User identification fields
	UserIDKey   string `json:"userIDKey"`   // Defaults to "sub"
	UserNameKey string `json:"userNameKey"` // Defaults to "name"

	// OverrideClaimMapping will be used to override the options defined in claimMappings.
	OverrideClaimMapping bool `json:"overrideClaimMapping"` // defaults to false

	ClaimMapping struct {
		// Configurable key which contains the preferred username claims
		PreferredUsernameKey string `json:"preferred_username"` // defaults to "preferred_username"

		// Configurable key which contains the email claims
		EmailKey string `json:"email"` // defaults to "email"

		// Configurable key which contains the groups claims
		GroupsKey string `json:"groups"` // defaults to "groups"
	} `json:"claimMapping"`

	// ClaimMutations holds all claim mutations options
	ClaimMutations struct {
		NewGroupFromClaims []NewGroupFromClaims `json:"newGroupFromClaims"`
		FilterGroupClaims  FilterGroupClaims    `json:"filterGroupClaims"`
	} `json:"claimModifications"`
}

// NewGroupFromClaims creates a new group from a list of claims and appends it to the list of existing groups.
type NewGroupFromClaims struct {
	// List of claim to join together
	Claims []string `json:"claims"`

	// String to separate the claims
	Delimiter string `json:"delimiter"`

	// Should Dex remove the Delimiter string from claim values
	// This is done to keep resulting claim structure in full control of the Dex operator
	ClearDelimiter bool `json:"clearDelimiter"`

	// String to place before the first claim
	Prefix string `json:"prefix"`
}

// FilterGroupClaims is a regex filter for to keep only the matching groups.
type FilterGroupClaims struct {
	GroupsFilter string `json:"groupsFilter"`
}

// Open returns a connector which can be used to validate tokens using OAuth 2.0 introspection.
func (c *Config) Open(id string, logger *slog.Logger) (conn connector.Connector, err error) {
	if c.IntrospectionURL == "" {
		return nil, errors.New("introspection: no introspection URL provided")
	}

	if c.UserIDKey == "" {
		c.UserIDKey = "sub"
	}

	if c.UserNameKey == "" {
		c.UserNameKey = "name"
	}

	httpClient, err := httpclient.NewHTTPClient(c.RootCAs, c.InsecureSkipVerify)
	if err != nil {
		return nil, err
	}

	var groupsFilter *regexp.Regexp
	if c.ClaimMutations.FilterGroupClaims.GroupsFilter != "" {
		groupsFilter, err = regexp.Compile(c.ClaimMutations.FilterGroupClaims.GroupsFilter)
		if err != nil {
			logger.Warn("ignoring invalid", "invalid_regex", c.ClaimMutations.FilterGroupClaims.GroupsFilter, "connector_id", id)
		}
	}

	return &introspectionConnector{
		introspectionURL:          c.IntrospectionURL,
		clientID:                  c.ClientID,
		clientSecret:              c.ClientSecret,
		scopes:                    c.Scopes,
		logger:                    logger.With(slog.Group("connector", "type", "introspection", "id", id)),
		httpClient:                httpClient,
		insecureSkipEmailVerified: c.InsecureSkipEmailVerified,
		insecureEnableGroups:      c.InsecureEnableGroups,
		allowedGroups:             c.AllowedGroups,
		userIDKey:                 c.UserIDKey,
		userNameKey:               c.UserNameKey,
		overrideClaimMapping:      c.OverrideClaimMapping,
		preferredUsernameKey:      c.ClaimMapping.PreferredUsernameKey,
		emailKey:                  c.ClaimMapping.EmailKey,
		groupsKey:                 c.ClaimMapping.GroupsKey,
		newGroupFromClaims:        c.ClaimMutations.NewGroupFromClaims,
		groupsFilter:              groupsFilter,
	}, nil
}

var (
	_ connector.TokenIdentityConnector = (*introspectionConnector)(nil)
)

type introspectionConnector struct {
	introspectionURL          string
	clientID                  string
	clientSecret              string
	scopes                    []string
	logger                    *slog.Logger
	httpClient                *http.Client
	insecureSkipEmailVerified bool
	insecureEnableGroups      bool
	allowedGroups             []string
	userIDKey                 string
	userNameKey               string
	overrideClaimMapping      bool
	preferredUsernameKey      string
	emailKey                  string
	groupsKey                 string
	newGroupFromClaims        []NewGroupFromClaims
	groupsFilter              *regexp.Regexp
}

func (c *introspectionConnector) Close() error {
	return nil
}

func (c *introspectionConnector) Type() string {
	return "introspection"
}

func (c *introspectionConnector) TokenIdentity(ctx context.Context, subjectTokenType, subjectToken string) (connector.Identity, error) {
	// Create form data for the introspection request
	form := url.Values{}
	form.Add("token", subjectToken)
	form.Add("token_type_hint", subjectTokenType)
	if c.clientID != "" {
		form.Add("client_id", c.clientID)
	}

	// Create the request
	req, err := http.NewRequestWithContext(ctx, "POST", c.introspectionURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return connector.Identity{}, fmt.Errorf("introspection: failed to create request: %v", err)
	}

	// Set headers
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Add client authentication if provided
	if c.clientID != "" && c.clientSecret != "" {
		req.SetBasicAuth(c.clientID, c.clientSecret)
	}

	// Send the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return connector.Identity{}, fmt.Errorf("introspection: request failed: %v", err)
	}
	defer resp.Body.Close()

	// Check the response status
	if resp.StatusCode != http.StatusOK {
		return connector.Identity{}, fmt.Errorf("introspection: endpoint returned status %d", resp.StatusCode)
	}

	// Parse the response
	var introspectionResp struct {
		Active bool                   `json:"active"`
		Extra  map[string]interface{} `json:"-"`
	}

	// Use a decoder that captures unknown fields
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&introspectionResp); err != nil {
		return connector.Identity{}, fmt.Errorf("introspection: failed to decode response: %v", err)
	}

	// Check if token is active
	if !introspectionResp.Active {
		return connector.Identity{}, errors.New("introspection: token is not active")
	}

	var claims map[string]interface{}

	// Check if we have the X-Debug header
	debugHeader := resp.Header.Get("X-Debug")
	if debugHeader != "" {
		// Try to decode from header if present
		if err := json.NewDecoder(strings.NewReader(debugHeader)).Decode(&claims); err != nil {
			log.Printf("failed to decode X-Debug header: %v", err)
			claims = make(map[string]interface{})
		}
	} else {
		// No X-Debug header, initialize empty map
		claims = make(map[string]interface{})
	}

	// If the introspection response has data, use it
	if len(claims) == 0 {
		// Either use the Extra field if available
		if introspectionResp.Extra != nil {
			for k, v := range introspectionResp.Extra {
				claims[k] = v
			}
		} else {
			if claims == nil {
				claims = make(map[string]interface{})
			}
		}
	}

	// Check token expiration
	if expValue, ok := claims["exp"]; ok {
		var expTime int64
		switch v := expValue.(type) {
		case float64:
			expTime = int64(v)
		case float32:
			expTime = int64(v)
		case int64:
			expTime = v
		case int:
			expTime = int64(v)
		case json.Number:
			expTime, _ = v.Int64()
		default:
			return connector.Identity{}, fmt.Errorf("introspection: invalid exp claim format")
		}

		if time.Now().Unix() > expTime {
			return connector.Identity{}, fmt.Errorf("introspection: token expired")
		}
	}

	// Get user ID (subject) - check both "sub" and "upn" fields
	subject, found := claims[c.userIDKey].(string)
	if !found {
		// Check if upn is available as fallback for subject
		subject, found = claims["upn"].(string)
		if !found {
			return connector.Identity{}, fmt.Errorf("introspection: missing \"%s\" claim", c.userIDKey)
		}
	}

	// Get username - also check "upn" as fallback
	name, found := claims[c.userNameKey].(string)
	if !found {
		// Check if upn is available as fallback for username
		name, found = claims["upn"].(string)
		if !found {
			return connector.Identity{}, fmt.Errorf("introspection: missing \"%s\" claim", c.userNameKey)
		}
	}

	// Rest of the code remains the same
	// Get preferred username
	preferredUsername, found := claims["preferred_username"].(string)
	if (!found || c.overrideClaimMapping) && c.preferredUsernameKey != "" {
		preferredUsername, _ = claims[c.preferredUsernameKey].(string)
	}

	// Get email
	emailKey := "email"
	if c.emailKey != "" {
		emailKey = c.emailKey
	}
	email, found := claims[emailKey].(string)
	if !found {
		// Email is optional in introspection
		email = ""
	}

	// Get email verification status
	emailVerified, found := claims["email_verified"].(bool)
	if !found {
		if c.insecureSkipEmailVerified {
			emailVerified = true
		} else {
			emailVerified = false
		}
	}

	// Get groups
	var groups []string
	if c.insecureEnableGroups {
		groupsKey := "groups"
		if c.groupsKey != "" {
			groupsKey = c.groupsKey
		}

		// Try to get groups as array
		if vs, found := claims[groupsKey].([]interface{}); found {
			for _, v := range vs {
				if s, ok := v.(string); ok {
					if c.groupsFilter != nil && !c.groupsFilter.MatchString(s) {
						continue
					}
					groups = append(groups, s)
				} else if groupMap, ok := v.(map[string]interface{}); ok {
					if s, ok := groupMap["name"].(string); ok {
						if c.groupsFilter != nil && !c.groupsFilter.MatchString(s) {
							continue
						}
						groups = append(groups, s)
					}
				}
			}
		}

		// Try to get groups as a string (single group case)
		if g, ok := claims[groupsKey].(string); ok {
			groups = []string{g}
		}

		// Validate that the user is part of allowedGroups
		if len(c.allowedGroups) > 0 {
			groupMatches := groups_pkg.Filter(groups, c.allowedGroups)
			if len(groupMatches) == 0 {
				// No group membership matches found, disallowing
				return connector.Identity{}, fmt.Errorf("introspection: user not a member of allowed groups")
			}
			groups = groupMatches
		}
	}

	// Process new groups from claims
	for _, config := range c.newGroupFromClaims {
		newGroupSegments := []string{
			config.Prefix,
		}
		for _, claimName := range config.Claims {
			claimValue, ok := claims[claimName].(string)
			if !ok {
				continue
			}

			if config.ClearDelimiter {
				claimValue = strings.ReplaceAll(claimValue, config.Delimiter, "")
			}

			newGroupSegments = append(newGroupSegments, claimValue)
		}

		if len(newGroupSegments) > 1 {
			groups = append(groups, strings.Join(newGroupSegments, config.Delimiter))
		}
	}

	// Create the identity
	identity := connector.Identity{
		UserID:            subject,
		Username:          name,
		PreferredUsername: preferredUsername,
		Email:             email,
		EmailVerified:     emailVerified,
		Groups:            groups,
		// No connector data needed for token introspection
	}

	return identity, nil
}

// TokenIntrospectionConnector represents a connector that can validate tokens using introspection
type TokenIntrospectionConnector interface {
	// All the methods from the base Connector interface
	connector.Connector

	// IntrospectToken validates a token using introspection and returns the identity
	IntrospectToken(ctx context.Context, tokenType, token string) (connector.Identity, error)
}

var _ connector.TokenIntrospectionConnector = (*introspectionConnector)(nil)

// IntrospectToken validates a token using introspection and returns the identity
// This method is required to implement the TokenIntrospectionConnector interface
func (c *introspectionConnector) IntrospectToken(ctx context.Context, tokenType, token string) (connector.Identity, error) {
	// This can simply call your existing TokenIdentity method
	return c.TokenIdentity(ctx, tokenType, token)
}
