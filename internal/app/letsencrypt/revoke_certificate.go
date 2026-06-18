package letsencrypt

import (
	"fmt"
	"net/http"

	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/app/domain"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// RevokeCertificateRequest is the request payload for revokeCertificate.
type RevokeCertificateRequest struct {
	Connection                domain.Connection                `json:"connection"`
	CertificateRevocationData domain.CertificateRevocationData `json:"certificateRevocationData"`
	Reason                    int                              `json:"reason"`
}

// RevokeCertificateResponse contains the revocation outcome.
type RevokeCertificateResponse struct {
	RevocationStatus domain.RevocationStatus `json:"revocationStatus"`
	ErrorMessage     *string                 `json:"errorMessage"`
}

// HandleRevokeCertificate revokes a certificate via the ACME revokeCert endpoint.
func (svc *WebhookService) HandleRevokeCertificate(c echo.Context) error {
	req := RevokeCertificateRequest{}
	if err := c.Bind(&req); err != nil {
		zap.L().Error("invalid request, failed to unmarshal json", zap.Error(err))
		return c.String(http.StatusBadRequest, fmt.Sprintf("failed to unmarshal json: %s", err.Error()))
	}

	resp, err := svc.Certificate.RevokeCertificate(
		req.Connection,
		req.CertificateRevocationData,
		req.Reason,
	)
	if err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}

	return c.JSON(http.StatusOK, &RevokeCertificateResponse{
		RevocationStatus: resp.Status,
		ErrorMessage:     resp.ErrorMessage,
	})
}
