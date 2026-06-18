package e2e_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/acme"
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/publisher/route53"
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/record"
)

// TestEndToEndIssuance issues a REAL Let's Encrypt staging certificate via dns-persist-01:
// generate the standing record (Capability A), publish it to Route 53 (Capability B, simulating
// the customer publishing the record we handed them), then run the DNS-free engine through
// order -> JIT/accept -> finalize(BYO-CSR) -> download, and assert the issued cert's public key
// matches the caller's CSR key.
//
// Gated behind ACME_STAGING=1 and requires AWS credentials (e.g. AWS_PROFILE) with Route 53
// write access to the test zone:
//
//	ACME_STAGING=1 AWS_PROFILE=... go test ./test/e2e/ -run TestEndToEndIssuance -v
func TestEndToEndIssuance(t *testing.T) {
	if os.Getenv("ACME_STAGING") == "" {
		t.Skip("set ACME_STAGING=1 (and AWS creds) to run the staging+Route53 e2e issuance test")
	}

	dirURL := envOr("ACME_DIRECTORY_URL", "https://acme-staging-v02.api.letsencrypt.org/directory")
	issuer := envOr("ACME_ISSUER_DOMAIN", "letsencrypt.org")
	zoneID := envOr("AWS_ROUTE53_HOSTED_ZONE_ID", "Z07101631Q7ZZTRCPJ6YR")
	domain := envOr("ACME_TEST_DOMAIN", "persist-e2e.jmcmsandbox.mimlab.io")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// 1. Connector owns the ACME account.
	key, err := acme.GenerateAccountKey()
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}
	client := &acme.Client{DirectoryURL: dirURL, Key: key, IssuerDomain: issuer}
	if err := client.Register(ctx, nil); err != nil {
		t.Fatalf("register account: %v", err)
	}
	t.Logf("account URI: %s", client.AccountURI())

	// 2. Capability A: generate the exact standing record to hand to the domain owner.
	rec, err := record.Generate(record.Params{Domain: domain, IssuerDomain: issuer, AccountURI: client.AccountURI()})
	if err != nil {
		t.Fatalf("generate record: %v", err)
	}
	t.Logf("standing record: %s", rec.ZoneFile())

	// 3. Capability B: publish it (simulating the customer). Engine never does this itself.
	pub, err := route53.New(ctx)
	if err != nil {
		t.Fatalf("route53 publisher: %v", err)
	}
	if err := pub.EnsureRecord(ctx, zoneID, rec.FQDN, rec.Value); err != nil {
		t.Fatalf("publish record: %v", err)
	}
	t.Cleanup(func() {
		ctxCleanup, cancelCleanup := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancelCleanup()
		if err := pub.DeleteRecord(ctxCleanup, zoneID, rec.FQDN, rec.Value); err != nil {
			t.Logf("cleanup DeleteRecord: %v", err)
		}
	})

	// 4. EnsureRecord already waited for the change to reach Route 53 INSYNC, so the record is
	// live on the authoritative servers Let's Encrypt will query. No local DNS lookup needed.
	t.Logf("record published and INSYNC at Route 53")

	// 5. Engine: order -> resolve each authz (JIT or accept) -> finalize -> download. DNS-free.
	order, err := client.NewOrder(ctx, []string{domain})
	if err != nil {
		t.Fatalf("new order: %v", err)
	}
	for _, authzURL := range order.Authorizations {
		if err := client.ResolveAuthorization(ctx, authzURL, acme.PollConfig{Interval: 3 * time.Second, Timeout: 2 * time.Minute}); err != nil {
			t.Fatalf("resolve authorization: %v", err)
		}
	}

	// 6. BYO-CSR: caller's key + CSR. The connector submits it as-is.
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate cert key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}, certKey)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}

	if _, err := client.Finalize(ctx, order.Finalize, csrDER); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	final, err := client.WaitForOrder(ctx, order.URL, acme.PollConfig{Interval: 3 * time.Second, Timeout: 2 * time.Minute})
	if err != nil {
		t.Fatalf("wait for order: %v", err)
	}
	if final.Status != acme.StatusValid {
		t.Fatalf("order did not reach valid: status=%s", final.Status)
	}

	certPEM, err := client.GetCertificate(ctx, final.Certificate)
	if err != nil {
		t.Fatalf("download certificate: %v", err)
	}

	// 7. Assert the issued cert's public key matches the caller's CSR key (BYO-CSR).
	leaf := firstCert(t, certPEM)
	wantPub, _ := x509.MarshalPKIXPublicKey(&certKey.PublicKey)
	gotPub, _ := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if !bytes.Equal(wantPub, gotPub) {
		t.Fatalf("issued certificate public key does not match the CSR key (BYO-CSR violated)")
	}
	t.Logf("ISSUED ✅ subject=%s issuer=%s notAfter=%s", leaf.Subject.CommonName, leaf.Issuer.CommonName, leaf.NotAfter.Format(time.RFC3339))
}

func firstCert(t *testing.T, pemData []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatalf("certificate is not valid PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}
	return leaf
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
