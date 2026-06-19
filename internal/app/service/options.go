package service

import (
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/app/domain"
)

// productOptionName is the single issuance profile this connector exposes. ACME has no
// per-request product selection, so one option suffices.
const productOptionName = "Let's Encrypt (dns-persist-01)"

// GetOptions returns the available issuance profiles. There are no import options (ACME accounts
// do not enumerate previously issued certificates).
func (s *Service) GetOptions(_ domain.Connection) ([]domain.ProductOption, []domain.ImportOption, error) {
	return []domain.ProductOption{
		{
			Name:  productOptionName,
			Types: []domain.ProductType{domain.ProductTypeSsl},
			Details: domain.ProductDetails{
				// ProfileID must be a valid v1-format UUID: CM uses it verbatim as the
				// certificateAuthorityProductOption UUID when registering the selectable product
				// option. A non-UUID string gets hashed into a malformed UUID (bad version/variant
				// bits), so registration silently fails and the product list stays empty.
				ProfileID:          "5eb6c7a7-772b-11f1-8e76-7b297abb22b2",
				ProfileName:        productOptionName,
				TrustType:          "public",
				SignatureAlgorithm: "SHA256withECDSA",
				AllowedKeySizes:    []string{"2048", "3072", "4096"},
			},
		},
	}, nil, nil
}

// ValidateProduct validates a selected product before issuance. The single ACME profile needs
// no validation, so this always succeeds.
func (s *Service) ValidateProduct(_ domain.Connection, _ string, _ domain.Product) ([]domain.ProductError, error) {
	return nil, nil
}
