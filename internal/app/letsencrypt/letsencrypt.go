// Package letsencrypt implements the 8 CA connector webhook handlers and the service
// interfaces they depend on. Handlers are thin: bind the JSON request, call a service
// method, return the JSON response. All business logic lives behind the service interfaces.
package letsencrypt

import (
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/app/domain"
)

// ConnectionService validates connectivity/configuration to the ACME CA.
type ConnectionService interface {
	TestConnection(connection domain.Connection) error
}

// OptionsService retrieves and validates issuance product options.
type OptionsService interface {
	GetOptions(connection domain.Connection) ([]domain.ProductOption, []domain.ImportOption, error)
	ValidateProduct(connection domain.Connection, name string, product domain.Product) ([]domain.ProductError, error)
}

// CertificateService handles the certificate lifecycle with the ACME CA.
type CertificateService interface {
	RequestCertificate(connection domain.Connection, pkcs10Request string, product domain.Product, productOptionName string, validitySeconds int, productDetails *domain.ProductDetails) (*domain.CertificateDetails, *domain.OrderDetails, error)
	CheckOrder(connection domain.Connection, id string) (*domain.OrderDetails, error)
	CheckCertificate(connection domain.Connection, id string) (*domain.CertificateDetails, error)
	RetrieveCertificates(connection domain.Connection, option domain.ImportOption, configuration domain.ImportConfiguration, startCursor string, batchSize int) (*domain.ImportDetails, error)
	RevokeCertificate(connection domain.Connection, data domain.CertificateRevocationData, reason int) (*domain.RevocationDetails, error)
}

// WebhookService aggregates the service interfaces and provides the handler methods.
type WebhookService struct {
	Connections ConnectionService
	Options     OptionsService
	Certificate CertificateService
}

// NewWebhookService creates a new WebhookService.
func NewWebhookService(connections ConnectionService, options OptionsService, certificate CertificateService) *WebhookService {
	return &WebhookService{
		Connections: connections,
		Options:     options,
		Certificate: certificate,
	}
}
