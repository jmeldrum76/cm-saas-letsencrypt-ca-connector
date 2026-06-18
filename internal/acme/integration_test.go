package acme_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/acme"
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/record"
)

// TestStagingDNSPersistChallenge exercises the real engine against Let's Encrypt staging:
// register an account, create an order, and inspect the dns-persist-01 challenge — capturing
// the issuer-domain-names value and confirming the account URI / generated record line up.
// It performs no challenge fulfilment and issues nothing.
//
// Gated behind ACME_STAGING=1 so the normal `go test` / CI run stays offline and deterministic.
//
//	ACME_STAGING=1 go test ./internal/acme/ -run TestStagingDNSPersistChallenge -v
func TestStagingDNSPersistChallenge(t *testing.T) {
	if os.Getenv("ACME_STAGING") == "" {
		t.Skip("set ACME_STAGING=1 to run the Let's Encrypt staging integration test")
	}

	dir := "https://acme-staging-v02.api.letsencrypt.org/directory"
	domain := "persist-probe.mimlab.io"
	if v := os.Getenv("ACME_TEST_DOMAIN"); v != "" {
		domain = v
	}

	key, err := acme.GenerateAccountKey()
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}
	client := &acme.Client{DirectoryURL: dir, Key: key, IssuerDomain: "letsencrypt.org"}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if err := client.Register(ctx, nil); err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Logf("account URI: %s", client.AccountURI())

	order, err := client.NewOrder(ctx, []string{domain})
	if err != nil {
		t.Fatalf("new order: %v", err)
	}
	t.Logf("order: %s (status %s)", order.URL, order.Status)
	if len(order.Authorizations) == 0 {
		t.Fatalf("order returned no authorizations")
	}

	authz, err := client.GetAuthorization(ctx, order.Authorizations[0])
	if err != nil {
		t.Fatalf("get authorization: %v", err)
	}

	ch, ok := acme.FindDNSPersistChallenge(authz)
	if !ok {
		t.Fatalf("staging did not offer a dns-persist-01 challenge for %s", domain)
	}
	t.Logf("dns-persist-01 challenge: status=%s accounturi=%s issuer-domain-names=%v", ch.Status, ch.AccountURI, ch.IssuerDomainNames)

	if len(ch.IssuerDomainNames) == 0 {
		t.Errorf("challenge carried no issuer-domain-names")
	}

	// The generated standing record should use this account's URI and an issuer the challenge honours.
	issuer := "letsencrypt.org"
	if len(ch.IssuerDomainNames) > 0 {
		issuer = ch.IssuerDomainNames[0]
	}
	rec, err := record.Generate(record.Params{
		Domain:       domain,
		IssuerDomain: issuer,
		AccountURI:   client.AccountURI(),
	})
	if err != nil {
		t.Fatalf("generate record: %v", err)
	}
	t.Logf("standing record to publish:\n  %s", rec.ZoneFile())

	if err := acme.ValidateIssuer(ch, issuer); err != nil {
		t.Errorf("ValidateIssuer rejected the challenge's own issuer %q: %v", issuer, err)
	}
}
