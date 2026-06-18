package domain

// ProductType categorizes the certificate product.
type ProductType string

const (
	ProductTypeSsl ProductType = "SSL"
)

// Product holds user-selected configuration for certificate issuance.
// ACME issuance needs no per-request user input, so this is currently empty.
type Product struct {
}

// ProductError reports a validation failure for a product attribute.
type ProductError struct {
	AttributeName  string `json:"attributeName"`
	AttributeValue string `json:"attributeValue"`
}

// ProductDetails stores metadata about a certificate profile.
type ProductDetails struct {
	ProfileID          string   `json:"profileId"`
	ProfileName        string   `json:"profileName"`
	TrustType          string   `json:"trustType"`
	SignatureAlgorithm string   `json:"signatureAlgorithm"`
	AllowedKeySizes    []string `json:"allowedKeySizes"`
}

// ProductOption represents a selectable certificate product (an ACME issuance profile).
type ProductOption struct {
	Name    string         `json:"name"`
	Types   []ProductType  `json:"types"`
	Details ProductDetails `json:"productDetails"`
}

// ImportSettings holds profile-specific settings for certificate import.
type ImportSettings struct {
	ProfileID string `json:"profileId"`
}

// ImportOption represents a selectable import source.
type ImportOption struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Settings    ImportSettings `json:"settings"`
}
