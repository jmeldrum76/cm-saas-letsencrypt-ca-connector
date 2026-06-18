package letsencrypt

import (
	"fmt"
	"net/http"

	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/app/domain"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// ImportCertificatesRequest is the request payload for importCertificates.
type ImportCertificatesRequest struct {
	Connection                 domain.Connection          `json:"connection"`
	Option                     domain.ImportOption        `json:"option"`
	Configuration              domain.ImportConfiguration `json:"configuration"`
	LastProcessedCertificateID string                     `json:"lastProcessedCertificateId"`
	BatchSize                  int                        `json:"batchSize"`
}

// HandleImportCertificates performs paginated import of certificates from the CA.
// ACME accounts do not enumerate previously issued certificates, so the implementation
// returns an empty COMPLETED page (there is no source to import from).
func (svc *WebhookService) HandleImportCertificates(c echo.Context) error {
	req := ImportCertificatesRequest{}
	if err := c.Bind(&req); err != nil {
		zap.L().Error("invalid request, failed to unmarshal json", zap.Error(err))
		return c.String(http.StatusBadRequest, fmt.Sprintf("failed to unmarshal json: %s", err.Error()))
	}

	res, err := svc.Certificate.RetrieveCertificates(
		req.Connection,
		req.Option,
		req.Configuration,
		req.LastProcessedCertificateID,
		req.BatchSize,
	)
	if err != nil {
		zap.L().Error("failed to retrieve certificates", zap.Error(err))
		return c.String(http.StatusBadRequest, fmt.Sprintf("failed to retrieve certificates: %s", err.Error()))
	}

	return c.JSON(http.StatusOK, res)
}
