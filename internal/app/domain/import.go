package domain

// ImportConfiguration holds user-configurable settings for certificate import.
type ImportConfiguration struct {
	IncludeExpiredCertificates bool `json:"includeExpiredCertificates"`
}

// ImportStatus indicates whether more pages of certificates are available.
type ImportStatus string

const (
	ImportStatusCompleted   ImportStatus = "COMPLETED"
	ImportStatusUncompleted ImportStatus = "UNCOMPLETED"
)

// ImportCertificate holds a single imported certificate with its chain.
// Certificate and Chain contain base64-encoded DER data.
type ImportCertificate struct {
	ID          string   `json:"id"`
	Certificate string   `json:"certificate"`
	Chain       []string `json:"chain"`
}

// ImportDetails is the response for the importCertificates endpoint.
type ImportDetails struct {
	ImportStatus               ImportStatus        `json:"status"`
	LastProcessedCertificateID string              `json:"lastProcessedCertificateId"`
	ImportCertificates         []ImportCertificate `json:"certificates"`
}
