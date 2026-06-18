package letsencrypt

import (
	"fmt"
	"net/http"

	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/app/domain"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// CheckCertificateRequest is the request payload for checkCertificate. ID is the ACME order URL.
type CheckCertificateRequest struct {
	Connection domain.Connection `json:"connection"`
	ID         string            `json:"id"`
}

// HandleCheckCertificate downloads an issued certificate (PEM chain -> base64 DER) from the ACME CA.
func (svc *WebhookService) HandleCheckCertificate(c echo.Context) error {
	req := CheckCertificateRequest{}
	if err := c.Bind(&req); err != nil {
		zap.L().Error("invalid request, failed to unmarshal json", zap.Error(err))
		return c.String(http.StatusBadRequest, fmt.Sprintf("failed to unmarshal json: %s", err.Error()))
	}

	cert, err := svc.Certificate.CheckCertificate(req.Connection, req.ID)
	if err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}

	return c.JSON(http.StatusOK, cert)
}
