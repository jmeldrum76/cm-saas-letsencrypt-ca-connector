package service

import (
	"crypto/sha1"
	"fmt"
	"strings"

	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/app/domain"
)

// productOptionName is the single issuance profile this connector exposes. ACME has no
// per-request product selection, so one option suffices.
const productOptionName = "Let's Encrypt (dns-persist-01)"

// GetOptions returns the available issuance profiles. There are no import options (ACME accounts
// do not enumerate previously issued certificates). The product's profileId is derived per CA
// account (see deriveProfileID) so multiple CA accounts of this connector each register cleanly.
func (s *Service) GetOptions(conn domain.Connection) ([]domain.ProductOption, []domain.ImportOption, error) {
	return []domain.ProductOption{
		{
			Name:  productOptionName,
			Types: []domain.ProductType{domain.ProductTypeSsl},
			Details: domain.ProductDetails{
				ProfileID:          deriveProfileID(conn),
				ProfileName:        productOptionName,
				TrustType:          "public",
				SignatureAlgorithm: "SHA256withECDSA",
				AllowedKeySizes:    []string{"2048", "3072", "4096"},
			},
		},
	}, nil, nil
}

// deriveProfileID returns a stable UUID unique to this CA account. NOTE: CM does NOT auto-register a
// Connector-CA product option — it caches the getOptions product on the account, but the
// issuing-template-visible product option must be registered explicitly via the caProduct API
// (see scripts/register-ca-product.sh; verified live — a fresh CA with a unique id still had no
// registered product until the API call). We still give each CA a distinct profileId (the DigiCert
// connector returns real per-product IDs from its API; ACME has none, so we derive one from the
// account key + directory) so a CA's cached and registered product option stay self-consistent and
// never collide across accounts. Bytes are formatted with valid v1 version/variant bits.
func deriveProfileID(conn domain.Connection) string {
	seed := strings.TrimSpace(conn.Credentials.AccountKey) + "|" + directoryURLOf(conn)
	sum := sha1.Sum([]byte(seed))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x10 // version 1 nibble
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ValidateProduct validates a selected product before issuance. The single ACME profile needs
// no validation, so this always succeeds.
func (s *Service) ValidateProduct(_ domain.Connection, _ string, _ domain.Product) ([]domain.ProductError, error) {
	return nil, nil
}
