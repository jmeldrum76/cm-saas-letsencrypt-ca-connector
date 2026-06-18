package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/acme"
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/app/domain"
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/publisher"
)

// TestManualModeMakesZeroDNSCalls is the headline guarantee: in manual mode the connector
// performs a full issuance (order -> JIT-valid authz -> finalize) without ever invoking the DNS
// publisher. The standing record is assumed to be published out-of-band by the customer.
func TestManualModeMakesZeroDNSCalls(t *testing.T) {
	srv := mockACMEServer(t)
	pub := newRecordingPublisher()
	svc := &Service{newPublisherFn: func(context.Context, domain.Connection) (publisher.Publisher, error) { return pub, nil }}

	conn := testConnection(t, srv.URL, domain.DCVModeManual)
	_, order, err := svc.RequestCertificate(conn, testCSR(t, "example.com"), domain.Product{}, "", 0, nil)
	if err != nil {
		t.Fatalf("RequestCertificate (manual): %v", err)
	}
	if order == nil || order.ID == "" {
		t.Fatalf("expected order details with an ID, got %+v", order)
	}
	if pub.ensureCalls.Load() != 0 {
		t.Errorf("manual mode invoked the DNS publisher %d time(s); want 0", pub.ensureCalls.Load())
	}
	if pub.writes.Load() != 0 {
		t.Errorf("manual mode made %d DNS write(s); want 0", pub.writes.Load())
	}
}

// TestAutoModePublishesOnceAcrossRenewals proves the renewal/JIT efficiency claim: auto mode
// publishes the standing record once and a second issuance (renewal) finds it present and makes
// no further DNS writes — strictly less DNS-coupled than per-issuance dns-01.
func TestAutoModePublishesOnceAcrossRenewals(t *testing.T) {
	srv := mockACMEServer(t)
	pub := newRecordingPublisher()
	svc := &Service{newPublisherFn: func(context.Context, domain.Connection) (publisher.Publisher, error) { return pub, nil }}

	conn := testConnection(t, srv.URL, domain.DCVModeAuto)
	conn.Configuration.DNSProvider = "route53"
	conn.Configuration.HostedZoneID = "ZTEST"
	csr := testCSR(t, "example.com")

	for i := 0; i < 2; i++ {
		if _, _, err := svc.RequestCertificate(conn, csr, domain.Product{}, "", 0, nil); err != nil {
			t.Fatalf("RequestCertificate (auto) run %d: %v", i+1, err)
		}
	}
	if got := pub.ensureCalls.Load(); got != 2 {
		t.Errorf("EnsureRecord should be called once per issuance (2 total), got %d", got)
	}
	if got := pub.writes.Load(); got != 1 {
		t.Errorf("auto mode should write the standing record exactly once across 2 issuances, got %d", got)
	}
}

// --- test helpers ---

func testConnection(t *testing.T, serverURL, mode string) domain.Connection {
	t.Helper()
	key, err := acme.GenerateAccountKey()
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}
	keyPEM, err := key.PEM()
	if err != nil {
		t.Fatalf("marshal account key: %v", err)
	}
	return domain.Connection{
		Configuration: domain.Configuration{
			DirectoryURL: serverURL + "/directory",
			IssuerDomain: "letsencrypt.org",
			DCVMode:      mode,
		},
		Credentials: domain.Credentials{AccountKey: string(keyPEM)},
	}
}

func testCSR(t *testing.T, dnsName string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CSR key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: dnsName},
		DNSNames: []string{dnsName},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// recordingPublisher is an in-memory, idempotent publisher.Publisher that counts calls and
// underlying writes so tests can assert DNS-call behaviour deterministically.
type recordingPublisher struct {
	mu          sync.Mutex
	store       map[string]bool
	ensureCalls atomic.Int64
	writes      atomic.Int64
}

func newRecordingPublisher() *recordingPublisher {
	return &recordingPublisher{store: make(map[string]bool)}
}

func (p *recordingPublisher) EnsureRecord(_ context.Context, _, fqdn, rdata string) error {
	p.ensureCalls.Add(1)
	key := fqdn + "|" + rdata
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.store[key] {
		p.store[key] = true
		p.writes.Add(1)
	}
	return nil
}

func (p *recordingPublisher) DeleteRecord(_ context.Context, _, fqdn, rdata string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.store, fqdn+"|"+rdata)
	return nil
}

// mockACMEServer is a minimal ACME server that completes the order flow offline: the single
// authorization reports "valid" (simulating a JIT hit on a present standing record), so no
// challenge fulfilment is needed and issuance proceeds to finalize.
func mockACMEServer(t *testing.T) *httptest.Server {
	t.Helper()
	var nonce int64
	next := func() string { return "nonce-" + strconv.FormatInt(atomic.AddInt64(&nonce, 1), 10) }
	base := func(r *http.Request) string { return "http://" + r.Host }

	mux := http.NewServeMux()
	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", next())
		_ = json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   base(r) + "/new-nonce",
			"newAccount": base(r) + "/new-account",
			"newOrder":   base(r) + "/new-order",
			"revokeCert": base(r) + "/revoke-cert",
			"keyChange":  base(r) + "/key-change",
		})
	})
	mux.HandleFunc("/new-nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", next())
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/new-account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", next())
		w.Header().Set("Location", base(r)+"/acct/1")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"valid"}`))
	})
	mux.HandleFunc("/new-order", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", next())
		w.Header().Set("Location", base(r)+"/order/1")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"status":"pending","authorizations":["%s/authz/1"],"finalize":"%s/finalize/1"}`, base(r), base(r))
	})
	mux.HandleFunc("/authz/1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", next())
		_, _ = w.Write([]byte(`{"status":"valid","identifier":{"type":"dns","value":"example.com"}}`))
	})
	mux.HandleFunc("/finalize/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", next())
		fmt.Fprintf(w, `{"status":"valid","certificate":"%s/cert/1"}`, base(r))
	})
	mux.HandleFunc("/order/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", next())
		fmt.Fprintf(w, `{"status":"valid","certificate":"%s/cert/1"}`, base(r))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}
