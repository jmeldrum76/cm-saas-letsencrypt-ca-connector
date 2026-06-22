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

// deriveProfileID returns a stable UUID unique to this CA account. CM uses the getOptions profileId
// verbatim as the product-option identifier when it auto-registers the selectable product, so a
// value shared across CA accounts collides and only the first account ever registers — the rest
// silently get no product and never appear in the Issuing Template picker. The DigiCert connector
// avoids this by returning real per-product IDs queried from its API; ACME has no such API, so we
// derive a distinct, deterministic id from the account's own identity (its ACME account key +
// directory). The bytes are formatted with valid v1 version/variant bits so CM accepts it as a UUID.
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
