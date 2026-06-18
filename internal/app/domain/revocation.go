package domain

// RevocationStatus indicates the outcome of a revocation request.
type RevocationStatus string

const (
	RevocationStatusSubmitted RevocationStatus = "SUBMITTED"
	RevocationStatusFailed    RevocationStatus = "FAILED"
)

// CertificateRevocationData identifies the certificate to revoke.
// At least one identifier field must be provided.
type CertificateRevocationData struct {
	SerialNumber            string `json:"serialNumber"`
	CaCertificateIdentifier string `json:"caCertificateIdentifier"`
	CaOrderIdentifier       string `json:"caOrderIdentifier"`
	Fingerprint             string `json:"fingerprint"`
	IssuerDN                string `json:"issuerDN"`
	CertificateContent      string `json:"certificateContent"`
}

// RevocationDetails is the response for the revokeCertificate endpoint.
type RevocationDetails struct {
	Status       RevocationStatus `json:"revocationStatus"`
	ErrorMessage *string          `json:"errorMessage"`
}
