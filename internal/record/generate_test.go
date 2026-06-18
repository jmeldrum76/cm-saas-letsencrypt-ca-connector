package record

import "testing"

const (
	testIssuer  = "letsencrypt.org"
	testAcctURI = "https://acme-v02.api.letsencrypt.org/acme/acct/1234567890"
)

func TestGenerate(t *testing.T) {
	tests := []struct {
		name      string
		params    Params
		wantFQDN  string
		wantValue string
	}{
		{
			// Verbatim from the Let's Encrypt dns-persist-01 announcement (basic record).
			name:      "basic FQDN",
			params:    Params{Domain: "example.com", IssuerDomain: testIssuer, AccountURI: testAcctURI},
			wantFQDN:  "_validation-persist.example.com",
			wantValue: "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1234567890",
		},
		{
			// Verbatim wildcard example: a "*." identifier implies policy=wildcard.
			name:      "wildcard via star prefix",
			params:    Params{Domain: "*.example.com", IssuerDomain: testIssuer, AccountURI: testAcctURI},
			wantFQDN:  "_validation-persist.example.com",
			wantValue: "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1234567890; policy=wildcard",
		},
		{
			name:      "wildcard via explicit flag",
			params:    Params{Domain: "example.com", IssuerDomain: testIssuer, AccountURI: testAcctURI, Wildcard: true},
			wantFQDN:  "_validation-persist.example.com",
			wantValue: "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1234567890; policy=wildcard",
		},
		{
			// Verbatim persistUntil example from the announcement.
			name:      "persistUntil",
			params:    Params{Domain: "example.com", IssuerDomain: testIssuer, AccountURI: testAcctURI, PersistUntil: 1767225600},
			wantFQDN:  "_validation-persist.example.com",
			wantValue: "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1234567890; persistUntil=1767225600",
		},
		{
			name:      "wildcard and persistUntil ordering",
			params:    Params{Domain: "*.example.com", IssuerDomain: testIssuer, AccountURI: testAcctURI, PersistUntil: 1767225600},
			wantFQDN:  "_validation-persist.example.com",
			wantValue: "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1234567890; policy=wildcard; persistUntil=1767225600",
		},
		{
			name:      "normalizes case and trailing dot",
			params:    Params{Domain: "Example.COM.", IssuerDomain: "LetsEncrypt.org", AccountURI: testAcctURI},
			wantFQDN:  "_validation-persist.example.com",
			wantValue: "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1234567890",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Generate(tc.params)
			if err != nil {
				t.Fatalf("Generate() unexpected error: %v", err)
			}
			if got.FQDN != tc.wantFQDN {
				t.Errorf("FQDN = %q, want %q", got.FQDN, tc.wantFQDN)
			}
			if got.Type != "TXT" {
				t.Errorf("Type = %q, want TXT", got.Type)
			}
			if got.Value != tc.wantValue {
				t.Errorf("Value = %q, want %q", got.Value, tc.wantValue)
			}
		})
	}
}

func TestGenerateZoneFile(t *testing.T) {
	r, err := Generate(Params{Domain: "example.com", IssuerDomain: testIssuer, AccountURI: testAcctURI})
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	want := `_validation-persist.example.com. IN TXT "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1234567890"`
	if got := r.ZoneFile(); got != want {
		t.Errorf("ZoneFile() = %q, want %q", got, want)
	}
}

func TestGenerateValidation(t *testing.T) {
	tests := []struct {
		name   string
		params Params
	}{
		{"missing domain", Params{IssuerDomain: testIssuer, AccountURI: testAcctURI}},
		{"missing issuer", Params{Domain: "example.com", AccountURI: testAcctURI}},
		{"missing account uri", Params{Domain: "example.com", IssuerDomain: testIssuer}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Generate(tc.params); err == nil {
				t.Errorf("Generate() expected error, got nil")
			}
		})
	}
}
