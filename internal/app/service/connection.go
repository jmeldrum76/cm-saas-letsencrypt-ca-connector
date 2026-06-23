package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/app/domain"
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/record"
	"go.uber.org/zap"
)

// TestConnection registers/reuses the ACME account, then:
//   - auto mode (a DNS provider selected): validates the DNS provider credentials/zone.
//   - manual / DNS-persist mode: confirms every domain listed in Verification Domains has a live
//     _validation-persist record bound to THIS account. All must pass for a green success; any miss
//     returns a FAILED message naming the domains still outstanding (CM renders failure text, so the
//     operator sees exactly what to fix, then Re-Test). The operator pastes the domain list after the
//     customer publishes the records the onboarding utility produced.
func (s *Service) TestConnection(conn domain.Connection) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

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

	// Manual / DNS-persist mode: validate every listed domain's standing record.
	wantValue := issuerOf(conn) + "; accounturi=" + uri
	domains := parseDomainList(conn.Configuration.VerificationDomains)
	if len(domains) == 0 {
		// No domains to check yet — a valid connection. Succeeding here lets the CA account be
		// created/saved (CM runs Test Connection on save and rejects a failing one). To confirm a
		// customer's records, add their domains to Verification Domains and Test Connection again.
		return fmt.Sprintf("Connected — ACME account %s registered (DNS-persist / manual mode). Add the customer's domains to 'Verification Domains' and Test Connection to confirm their standing records. Standing record value: %q",
			uri, wantValue), nil
	}

	var missing []string
	verified := 0
	for _, d := range domains {
		rec, err := record.Generate(record.Params{Domain: d, IssuerDomain: issuerOf(conn), AccountURI: uri})
		if err != nil {
			missing = append(missing, d+" (invalid name)")
			continue
		}
		if recordLive(ctx, rec.FQDN, uri, issuerOf(conn)) {
			verified++
		} else {
			missing = append(missing, d)
		}
	}

	if len(missing) > 0 {
		return "", fmt.Errorf("standing record not live (or not yet propagated) for %d of %d domain(s): %s. "+
			"Publish _validation-persist.<domain> TXT with value %q for each, then Re-Test Connection. (%d of %d already verified.)",
			len(missing), len(domains), strings.Join(missing, ", "), wantValue, verified, len(domains))
	}
	return fmt.Sprintf("Verified ✓ — all %d domain(s) have a live standing record bound to this account. You can continue.", len(domains)), nil
}

// parseDomainList splits a pasted list (newlines, commas, semicolons, or spaces) into clean domains:
// it strips any leading "_validation-persist." label, a "*." wildcard prefix, surrounding whitespace
// and trailing dots, lowercases, and de-duplicates.
func parseDomainList(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t' || r == ';'
	})
	seen := map[string]bool{}
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		d := strings.ToLower(strings.Trim(strings.TrimSpace(f), "."))
		d = strings.TrimPrefix(d, record.Label+".")
		d = strings.TrimPrefix(d, "*.")
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// recordLive reports whether a live TXT record at fqdn binds the domain to our ACME account: it must
// name the issuer and carry accounturi=<our account URI>. Trailing policy/persistUntil tokens are
// ignored, so the same check passes for both plain and wildcard records.
func recordLive(ctx context.Context, fqdn, accountURI, issuer string) bool {
	txts, err := net.DefaultResolver.LookupTXT(ctx, fqdn)
	if err != nil {
		return false
	}
	issuer = strings.ToLower(strings.TrimSpace(issuer))
	want := "accounturi=" + strings.ToLower(accountURI)
	for _, t := range txts {
		norm := strings.ReplaceAll(strings.ToLower(t), " ", "")
		if strings.HasPrefix(norm, issuer+";") && strings.Contains(norm, want) {
			return true
		}
	}
	return false
}
