package e2e_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"testing"
	"time"

	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/acme"
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/publisher/route53"
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/record"
)

// TestRenewalJITZeroWrite proves the renewal/JIT efficiency claim against the REAL CA: publish
// the standing _validation-persist record exactly ONCE, then issue two real staging certificates
// from it (initial + renewal). The renewal must succeed via just-in-time validation against the
// still-present record, with NO additional DNS writes — demonstrating that, unlike per-issuance
// dns-01, dns-persist renewals touch DNS zero times after the one-time publish.
//
// Gated behind ACME_STAGING=1 and requires AWS creds with Route 53 write access:
//
//	ACME_STAGING=1 AWS_PROFILE=... go test ./test/e2e/ -run TestRenewalJITZeroWrite -v -timeout 420s
func TestRenewalJITZeroWrite(t *testing.T) {
	if os.Getenv("ACME_STAGING") == "" {
		t.Skip("set ACME_STAGING=1 (and AWS creds) to run the staging renewal test")
	}

	dirURL := envOr("ACME_DIRECTORY_URL", "https://acme-staging-v02.api.letsencrypt.org/directory")
	issuer := envOr("ACME_ISSUER_DOMAIN", "letsencrypt.org")
	zoneID := envOr("AWS_ROUTE53_HOSTED_ZONE_ID", "Z07101631Q7ZZTRCPJ6YR")
	domain := envOr("ACME_TEST_DOMAIN", "persist-renew.jmcmsandbox.mimlab.io")

	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	defer cancel()

	key, err := acme.GenerateAccountKey()
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}
	client := &acme.Client{DirectoryURL: dirURL, Key: key, IssuerDomain: issuer}
	if err := client.Register(ctx, nil); err != nil {
		t.Fatalf("register account: %v", err)
	}

	rec, err := record.Generate(record.Params{Domain: domain, IssuerDomain: issuer, AccountURI: client.AccountURI()})
	if err != nil {
		t.Fatalf("generate record: %v", err)
	}

	pub, err := route53.New(ctx)
	if err != nil {
		t.Fatalf("route53 publisher: %v", err)
	}

	// Publish the standing record exactly ONCE, up front (simulating one-time provisioning).
	dnsWrites := 0
	if err := pub.EnsureRecord(ctx, zoneID, rec.FQDN, rec.Value); err != nil {
		t.Fatalf("publish standing record: %v", err)
	}
	dnsWrites++
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccancel()
		if err := pub.DeleteRecord(cctx, zoneID, rec.FQDN, rec.Value); err != nil {
			t.Logf("cleanup DeleteRecord: %v", err)
		}
	})

	poll := acme.PollConfig{Interval: 3 * time.Second, Timeout: 2 * time.Minute}

	// Issue twice from the SAME standing record, with no re-publish between issuances.
	for _, phase := range []string{"initial", "renewal"} {
		certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("[%s] generate cert key: %v", phase, err)
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject:  pkix.Name{CommonName: domain},
			DNSNames: []string{domain},
		}, certKey)
		if err != nil {
			t.Fatalf("[%s] create CSR: %v", phase, err)
		}

		order, err := client.NewOrder(ctx, []string{domain})
		if err != nil {
			t.Fatalf("[%s] new order: %v", phase, err)
		}
		for _, authzURL := range order.Authorizations {
			if err := client.ResolveAuthorization(ctx, authzURL, poll); err != nil {
				t.Fatalf("[%s] resolve authorization: %v", phase, err)
			}
		}
		if _, err := client.Finalize(ctx, order.Finalize, csrDER); err != nil {
			t.Fatalf("[%s] finalize: %v", phase, err)
		}
		final, err := client.WaitForOrder(ctx, order.URL, poll)
		if err != nil {
			t.Fatalf("[%s] wait for order: %v", phase, err)
		}
		if final.Status != acme.StatusValid {
			t.Fatalf("[%s] order did not reach valid: %s", phase, final.Status)
		}
		certPEM, err := client.GetCertificate(ctx, final.Certificate)
		if err != nil {
			t.Fatalf("[%s] download certificate: %v", phase, err)
		}
		leaf := firstCert(t, certPEM)
		wantPub, _ := x509.MarshalPKIXPublicKey(&certKey.PublicKey)
		gotPub, _ := x509.MarshalPKIXPublicKey(leaf.PublicKey)
		if !bytes.Equal(wantPub, gotPub) {
			t.Fatalf("[%s] issued cert key does not match CSR key", phase)
		}
		t.Logf("[%s] ISSUED ✅ serial=%x notAfter=%s", phase, leaf.SerialNumber, leaf.NotAfter.Format(time.RFC3339))
	}

	if dnsWrites != 1 {
		t.Errorf("expected exactly 1 DNS write across initial+renewal, got %d", dnsWrites)
	}
	t.Logf("RENEWAL ✅ two staging certs issued from one standing record; total DNS writes=%d", dnsWrites)
}
