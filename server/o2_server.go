package server

// o2_server.go wires the OpenObserve fork's additions into the server: sign-up
// and password-reset settings, dynamic client registration, hidden and
// domain-specific connectors, and the routes that serve them.

import (
	"context"
	"fmt"
	"time"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/server/authflow"
	"github.com/dexidp/dex/server/connectors"
	"github.com/dexidp/dex/server/router"
)

// DomainSpecificConnector is a connector reached by the email domain typed on the sign-in page, not from the chooser.
type DomainSpecificConnector struct {
	ResourceVersion string
	Domain          string
	Id              string
	Connector       connector.Connector
}

// o2Server holds the fork's server state, embedded in Server.
type o2Server struct {
	// authflow is the login flow handler; the fork's pages finish a login through it.
	authflow *authflow.Handler

	now func() time.Time

	// If enabled, allows users to sign up with email and password
	enableSignup bool

	SmtpHost     string
	SmtpPort     int
	SmtpSender   string
	SmtpUser     string
	SmtpPassword string

	EnableEmailValidation    bool
	EmailValidationServerUrl string

	// Optional bearer token for client registration endpoint
	registrationToken string

	supportedResponseTypes map[string]bool
	supportedGrantTypes    []string

	DomainConnectors []DomainSpecificConnector

	limits *authLimits
}

// initO2 copies the fork's settings from c and opens the domain connectors.
func (s *Server) initO2(c Config, rc resolvedConfig) error {
	s.o2Server = o2Server{
		now:                      rc.now,
		enableSignup:             c.EnableSignup,
		SmtpHost:                 c.SmtpHost,
		SmtpPort:                 c.SmtpPort,
		SmtpSender:               c.SmtpSender,
		SmtpUser:                 c.SmtpUser,
		SmtpPassword:             c.SmtpPassword,
		EnableEmailValidation:    c.EnableEmailValidation,
		EmailValidationServerUrl: c.EmailValidationServerUrl,
		registrationToken:        c.RegistrationToken,
		supportedResponseTypes:   rc.responseTypes,
		supportedGrantTypes:      rc.grantTypes,
		limits:                   newAuthLimits(rc.now),
	}

	resolve := connectors.Resolver(s.storage, s.logger, ConnectorsConfig)
	domainConnectors := make([]DomainSpecificConnector, 0, len(c.DomainConnectors))
	for _, conn := range c.DomainConnectors {
		impl, err := resolve(conn.Conn)
		if err != nil {
			return fmt.Errorf("server: Failed to open connector %s: %v", conn.Conn.ID, err)
		}
		domainConnectors = append(domainConnectors, DomainSpecificConnector{
			ResourceVersion: conn.Conn.ResourceVersion,
			Domain:          conn.Domain,
			Id:              conn.Id,
			Connector:       impl,
		})
		// Domain connectors are not stored, so the callback and refresh paths find them through the cache.
		s.connectors.SetDetached(conn.Id, connectors.Connector{
			Type:            conn.Conn.Type,
			ResourceVersion: conn.Conn.ResourceVersion,
			Connector:       impl,
			GrantTypes:      conn.Conn.GrantTypes,
		})
	}
	s.DomainConnectors = domainConnectors
	return nil
}

// mountO2 registers the fork's routes.
func (s *Server) mountO2(routes router.Mux) {
	routes.HandleCORS("/register", s.handleClientRegistration)
	routes.HandleCORS("/check-handler", s.checkHandler)
	routes.HandleCORS("/signup", s.handleSignup)
	routes.HandleCORS("/password_reset", s.handlePasswordReset)
	routes.HandleCORS("/signup-token", s.handleSignupToken)
	routes.HandleCORS("/reset-token", s.handlePasswordResetToken)
}

func (s *Server) absPath(pathItems ...string) string {
	return s.issuerURL.AbsPath(pathItems...)
}

func (s *Server) absURL(pathItems ...string) string {
	return s.issuerURL.AbsURL(pathItems...)
}

// getConnector returns a stored or domain connector by id.
func (s *Server) getConnector(ctx context.Context, id string) (connectors.Connector, error) {
	return s.connectors.Get(ctx, id)
}
