package acme

import (
	"strings"
	"testing"
)

// TestParseAccountKeyFlattened verifies a PEM whose line breaks were collapsed to spaces (as a
// single-line form field does) is repaired and parsed.
func TestParseAccountKeyFlattened(t *testing.T) {
	key, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	good, err := key.PEM()
	if err != nil {
		t.Fatal(err)
	}
	// Flatten: every newline becomes a space (what a single-line input produces on paste).
	flat := strings.ReplaceAll(string(good), "\n", " ")
	repaired, err := ParseAccountKey([]byte(flat))
	if err != nil {
		t.Fatalf("flattened PEM should parse, got: %v", err)
	}
	// CRITICAL: the repaired key must be the SAME key (same account), not a corrupted/different one.
	if repaired.priv.D.Cmp(key.priv.D) != 0 ||
		repaired.priv.PublicKey.X.Cmp(key.priv.PublicKey.X) != 0 ||
		repaired.priv.PublicKey.Y.Cmp(key.priv.PublicKey.Y) != 0 {
		t.Fatal("repaired flattened key differs from the original — repair corrupted the key")
	}
	// A genuinely broken value must still error.
	if _, err := ParseAccountKey([]byte("not a key")); err == nil {
		t.Fatal("expected error for non-PEM input")
	}
	// The unflattened key must still parse (no regression).
	if _, err := ParseAccountKey(good); err != nil {
		t.Fatalf("normal PEM should still parse, got: %v", err)
	}
}
