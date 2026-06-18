// Package publisher implements Capability B: optional, auto-mode-only publishing of the
// standing _validation-persist record. It is invoked ONLY from the handler/service layer (when
// DCV mode = auto) or the test harness — NEVER from internal/acme. The ACME protocol engine
// stays DNS-free; a CI check asserts internal/acme has no transitive import of this package or
// any DNS/cloud SDK.
//
// Even in auto mode this writes the standing record ONCE (idempotent EnsureRecord): subsequent
// issuances/renewals find it present and skip the write, validating via JIT — strictly less
// DNS-coupled than the per-issuance dns-01 model of the native connector.
package publisher

import "context"

// Publisher idempotently manages the standing _validation-persist TXT record on a DNS provider.
type Publisher interface {
	// EnsureRecord ensures a TXT record at fqdn contains rdata, publishing only if absent.
	// It must be safe to call repeatedly (idempotent) and must preserve any other TXT values
	// already present at the same name (multi-issuer support).
	EnsureRecord(ctx context.Context, zoneID, fqdn, rdata string) error
	// DeleteRecord removes rdata from the TXT record at fqdn (teardown / tests), leaving any
	// other values intact.
	DeleteRecord(ctx context.Context, zoneID, fqdn, rdata string) error
}
