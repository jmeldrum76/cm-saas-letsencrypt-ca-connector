package service

import (
	"regexp"
	"testing"

	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/app/domain"
)

// TestDeriveProfileIDUniqueAndValid guards the fix for the multi-CA collision: every CA account must
// get a distinct, stable, valid-UUID profileId so CM auto-registers each one's product option.
func TestDeriveProfileIDUniqueAndValid(t *testing.T) {
	uuidRe := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	withKey := func(k string) domain.Connection {
		return domain.Connection{Credentials: domain.Credentials{AccountKey: k}}
	}
	a := deriveProfileID(withKey("-----BEGIN EC PRIVATE KEY-----\nAAA\n-----END EC PRIVATE KEY-----"))
	b := deriveProfileID(withKey("-----BEGIN EC PRIVATE KEY-----\nBBB\n-----END EC PRIVATE KEY-----"))
	a2 := deriveProfileID(withKey("-----BEGIN EC PRIVATE KEY-----\nAAA\n-----END EC PRIVATE KEY-----"))

	if a == b {
		t.Fatal("different account keys must yield different profileIds (the multi-CA collision)")
	}
	if a != a2 {
		t.Fatal("same account key must yield the same profileId (must be stable across calls)")
	}
	for _, id := range []string{a, b} {
		if !uuidRe.MatchString(id) {
			t.Fatalf("profileId %q is not a valid v1-format UUID", id)
		}
	}
}
