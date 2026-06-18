package acme_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestEngineDependencyIsolation enforces the project's core invariant: the DNS-free ACME
// protocol engine (internal/acme) must have NO transitive dependency on the DNS publisher or
// any cloud/DNS SDK. If this fails, some change made the engine DNS-coupled and the
// dns-persist-01 "issuance never depends on DNS access" guarantee is at risk.
//
// It inspects the engine's PRODUCTION import graph (go list -deps, no -test), so test-only
// imports are intentionally excluded.
func TestEngineDependencyIsolation(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH; skipping dependency-isolation check")
	}

	out, err := exec.Command(goBin, "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps failed: %v\n%s", err, out)
	}

	forbidden := []string{
		"cm-saas-letsencrypt-ca-connector/internal/publisher",
		"github.com/aws/",
		"aws-sdk-go",
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, bad := range forbidden {
			if strings.Contains(dep, bad) {
				t.Errorf("internal/acme must stay DNS-free but depends on %q (matched %q)", dep, bad)
			}
		}
	}
}
