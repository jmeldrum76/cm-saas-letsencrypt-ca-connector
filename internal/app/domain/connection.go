package domain

// Connection holds the ACME account configuration and credentials supplied by CM
// (Certificate Manager) on every webhook call.
type Connection struct {
	Configuration Configuration `json:"configuration"`
	Credentials   Credentials   `json:"credentials"`
}

// DCV (domain control validation) modes.
const (
	// DCVModeManual: the connector generates the standing _validation-persist record and the
	// customer publishes it on any DNS provider themselves. The connector makes zero DNS calls.
	DCVModeManual = "manual"
	// DCVModeAuto: the connector holds DNS provider credentials and publishes the standing
	// record once (idempotent), then issues. Strictly less DNS-coupled than per-issuance dns-01.
	DCVModeAuto = "auto"
)

// Configuration holds non-secret connection settings (mapped from the manifest UI).
type Configuration struct {
	// DirectoryURL is the ACME directory endpoint. Switchable across Pebble, LE staging,
	// LE production, or a custom URL without code changes.
	DirectoryURL string `json:"directoryUrl"`
	// IssuerDomain is validated against the dns-persist-01 challenge issuer-domain-names
	// before a challenge is accepted (e.g. "letsencrypt.org").
	IssuerDomain string `json:"issuerDomain"`
	// Contact is an optional ACME account contact (e.g. "mailto:ops@example.com").
	Contact string `json:"contact"`
	// DCVMode selects how domain control is satisfied: DCVModeManual or DCVModeAuto.
	DCVMode string `json:"dcvMode"`
	// DNSProvider names the auto-mode publisher (e.g. "route53"). Empty in manual mode.
	DNSProvider string `json:"dnsProvider"`
	// HostedZoneID is the auto-mode DNS hosted zone (e.g. a Route 53 zone ID). Empty in manual mode.
	HostedZoneID string `json:"hostedZoneId"`
}

// Credentials holds secret material. Every field is marked x-encrypted in the manifest.
type Credentials struct {
	// AccountKey is the PEM-encoded ECDSA P-256 ACME account private key. The connector owns
	// the ACME account; reusing this key keeps the account URI stable across renewals
	// (RFC 8555 §7.3.5 key rollover preserves the URI).
	AccountKey string `json:"accountKey"`
	// AccessKeyID and SecretAccessKey are auto-mode DNS provider credentials. Empty in manual mode.
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
}
