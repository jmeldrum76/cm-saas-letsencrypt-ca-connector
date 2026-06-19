package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/acme"
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/app/domain"
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/record"
	"go.uber.org/zap"
)

// TestConnection registers/reuses the ACME account, then:
//   - auto mode (a DNS provider selected): also validates the DNS provider credentials.
//   - manual / DNS-persist mode: returns the account URI + the exact standing record to hand to
//     the domain owner. If a Verification Domain is given, it checks DNS that the record is live.
func (s *Service) TestConnection(conn domain.Connection) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Bootstrap: if no account key was supplied, generate one, register the ACME account, and hand
	// the key back for the admin to paste in and save. This only fires on a blank field (initial
	// setup); once saved, the key is reused on every call. We warn loudly because generating a new
	// key after standing records exist creates a NEW account URI and orphans every published record.
	bootstrapped := false
	if strings.TrimSpace(conn.Credentials.AccountKey) == "" {
		key, err := acme.GenerateAccountKey()
		if err != nil {
			return "", err
		}
		pemBytes, err := key.PEM()
		if err != nil {
			return "", err
		}
		conn.Credentials.AccountKey = string(pemBytes)
		bootstrapped = true
	}

	client, err := buildClient(conn)
	if err != nil {
		return "", err
	}
	if err := ensureAccount(ctx, client, conn); err != nil {
		return "", err
	}
	uri := client.AccountURI()
	zap.L().Info("ACME account ready",
		zap.String("directoryUrl", directoryURLOf(conn)),
		zap.String("accountURI", uri),
		zap.String("dnsProvider", conn.Configuration.DNSProvider),
	)

	if bootstrapped {
		return fmt.Sprintf("No ACME Account Key was set, so the connector generated one and registered ACME account %s. "+
			"COPY the key below into the 'ACME Account Key' field and Save, then Test Connection again. "+
			"Back it up: generating a new key later starts a new account and orphans every standing record you have published.\n\n%s",
			uri, conn.Credentials.AccountKey), nil
	}

	// Auto mode: a DNS provider is selected — validate its credentials/zone too.
	if isAutoMode(conn) {
		zoneID := conn.Configuration.HostedZoneID
		if zoneID == "" {
			return "", errors.New("a DNS provider is selected but the Hosted Zone ID is empty")
		}
		pub, err := s.publisherFor(ctx, conn)
		if err != nil {
			return "", err
		}
		if err := pub.Validate(ctx, zoneID); err != nil {
			return "", fmt.Errorf("DNS provider check failed: %w", err)
		}
		return fmt.Sprintf("Connected. ACME account URI: %s. DNS provider (%s) verified — the connector will publish validation records automatically.",
			uri, conn.Configuration.DNSProvider), nil
	}

	// Manual / DNS-persist mode: with a Verification Domain, confirm the standing record is live.
	if vd := strings.TrimSpace(conn.Configuration.VerificationDomain); vd != "" {
		rec, err := record.Generate(record.Params{Domain: vd, IssuerDomain: issuerOf(conn), AccountURI: uri})
		if err != nil {
			return "", err
		}
		txts, lookupErr := net.DefaultResolver.LookupTXT(ctx, rec.FQDN)
		for _, t := range txts {
			if t == rec.Value {
				return fmt.Sprintf("Verified ✓ — the standing record for %s is live (%s). Certificates can be issued for this domain.", vd, rec.FQDN), nil
			}
		}
		detail := "no matching TXT record found"
		if lookupErr != nil {
			detail = lookupErr.Error()
		}
		return "", fmt.Errorf("standing record NOT found for %s (%s). Publish this TXT record at your DNS provider, then Test Connection again: %s",
			vd, detail, rec.ZoneFile())
	}

	// Manual mode, no verification domain yet: hand back the record to publish.
	tmpl, _ := record.Generate(record.Params{Domain: "<your-domain>", IssuerDomain: issuerOf(conn), AccountURI: uri})
	return fmt.Sprintf("Connected. DNS-persist mode. Give this one-time TXT record to the domain owner (replace <your-domain>): %s — then enter that domain in 'Verification Domain' and Test Connection to confirm it is live. ACME account URI: %s",
		tmpl.ZoneFile(), uri), nil
}
