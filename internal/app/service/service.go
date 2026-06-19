// Package service is the connector's business logic: it adapts the framework's CA operations
// onto the ACME dns-persist-01 engine. It builds a fresh, stateless ACME client per webhook
// call from the supplied Connection, and (in auto mode only) invokes the DNS publisher. The
// protocol engine (internal/acme) stays DNS-free; the publisher is touched only here, gated by
// DCV mode.
package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/acme"
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/app/domain"
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/publisher"
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/publisher/route53"
)

const (
	// defaultDirectoryURL targets Let's Encrypt staging (dns-persist-01 is live there). Switch to
	// production or Pebble via the connection's Directory URL field — no code change.
	defaultDirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	defaultIssuerDomain = "letsencrypt.org"
	defaultAWSRegion    = "us-east-1"
)

// Service implements the connector's ConnectionService, OptionsService, and CertificateService.
type Service struct {
	// newPublisherFn overrides the DNS publisher factory in tests. Nil uses the real Route 53 factory.
	newPublisherFn func(ctx context.Context, conn domain.Connection) (publisher.Publisher, error)
}

// NewService constructs the connector service.
func NewService() *Service { return &Service{} }

// publisherFor returns the auto-mode DNS publisher, honouring a test override when set.
func (s *Service) publisherFor(ctx context.Context, conn domain.Connection) (publisher.Publisher, error) {
	if s.newPublisherFn != nil {
		return s.newPublisherFn(ctx, conn)
	}
	return s.newPublisher(ctx, conn)
}

func directoryURLOf(conn domain.Connection) string {
	if u := strings.TrimSpace(conn.Configuration.DirectoryURL); u != "" {
		return u
	}
	return defaultDirectoryURL
}

func issuerOf(conn domain.Connection) string {
	if d := strings.TrimSpace(conn.Configuration.IssuerDomain); d != "" {
		return d
	}
	return defaultIssuerDomain
}

// buildClient constructs an ACME client from the connection. The account key is required (the
// connector owns the ACME account; it is configured as an encrypted credential).
func buildClient(conn domain.Connection) (*acme.Client, error) {
	if strings.TrimSpace(conn.Credentials.AccountKey) == "" {
		return nil, errors.New("ACME account key is required — configure it in the connection")
	}
	key, err := acme.ParseAccountKey([]byte(conn.Credentials.AccountKey))
	if err != nil {
		return nil, fmt.Errorf("invalid ACME account key: %w", err)
	}
	return &acme.Client{
		DirectoryURL: directoryURLOf(conn),
		Key:          key,
		IssuerDomain: issuerOf(conn),
	}, nil
}

// ensureAccount registers (or returns the existing) ACME account, setting the client's account
// URL. newAccount is idempotent for a given key, so this is safe to call on every webhook.
func ensureAccount(ctx context.Context, client *acme.Client, conn domain.Connection) error {
	var contacts []string
	if c := strings.TrimSpace(conn.Configuration.Contact); c != "" {
		contacts = []string{c}
	}
	return client.Register(ctx, contacts)
}

// isAutoMode reports whether a DNS provider is selected (auto DCV). "none"/empty means DNS-persist
// (manual) mode where the customer publishes the standing record and the connector touches no DNS.
func isAutoMode(conn domain.Connection) bool {
	p := strings.ToLower(strings.TrimSpace(conn.Configuration.DNSProvider))
	return p != "" && p != "none"
}

// newPublisher builds the auto-mode DNS publisher from the connection (static keys if provided,
// else the default AWS chain). Only Route 53 is supported today.
func (s *Service) newPublisher(ctx context.Context, conn domain.Connection) (publisher.Publisher, error) {
	provider := strings.ToLower(strings.TrimSpace(conn.Configuration.DNSProvider))
	if provider != "" && provider != "route53" && provider != "aws_route_53" {
		return nil, fmt.Errorf("unsupported auto-mode DNS provider %q (only route53 is implemented)", conn.Configuration.DNSProvider)
	}
	if conn.Credentials.AccessKeyID != "" {
		return route53.NewWithStaticKeys(ctx, conn.Credentials.AccessKeyID, conn.Credentials.SecretAccessKey, defaultAWSRegion)
	}
	return route53.New(ctx)
}
