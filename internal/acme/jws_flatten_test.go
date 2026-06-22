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
	if _, err := ParseAccountKey([]byte(flat)); err != nil {
		t.Fatalf("flattened PEM should parse, got: %v", err)
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
