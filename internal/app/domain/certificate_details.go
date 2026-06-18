package domain

// CertificateStatus represents the state of a certificate in the issuance lifecycle.
type CertificateStatus string

const (
	CertificateStatusPending   CertificateStatus = "PENDING"
	CertificateStatusRequested CertificateStatus = "REQUESTED"
	CertificateStatusIssued    CertificateStatus = "ISSUED"
	CertificateStatusFailed    CertificateStatus = "FAILED"
)

// CertificateDetails holds the certificate data returned by checkCertificate.
// Certificate and Chain contain base64-encoded DER data (not PEM).
type CertificateDetails struct {
	ID           string            `json:"id"`
	Status       CertificateStatus `json:"status"`
	Certificate  string            `json:"certificate"`
	Chain        []string          `json:"chain"`
	ErrorMessage string            `json:"errorMessage"`
}
