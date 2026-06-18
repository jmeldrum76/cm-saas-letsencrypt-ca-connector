package letsencrypt

import (
	"fmt"
	"net/http"

	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/app/domain"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// RequestCertificateRequest is the request payload for requestCertificate.
// Pkcs10Request is the caller-provided CSR (PEM). The connector submits it as-is and never
// regenerates the key, so the returned certificate matches the caller's private key.
type RequestCertificateRequest struct {
	Connection        domain.Connection      `json:"connection"`
	ValiditySeconds   int                    `json:"validitySeconds"`
	ProductOptionName string                 `json:"productOptionName"`
	Product           domain.Product         `json:"product"`
	Pkcs10Request     string                 `json:"pkcs10Request"`
	ProductDetails    *domain.ProductDetails `json:"productDetails"`
}

// RequestCertificateResponse contains the certificate and/or order details.
// For ACME, issuance is asynchronous: OrderDetails.ID carries the ACME order URL, which CM
// later passes to checkOrder/checkCertificate.
type RequestCertificateResponse struct {
	CertificateDetails *domain.CertificateDetails `json:"certificateDetails"`
	OrderDetails       *domain.OrderDetails       `json:"orderDetails"`
}

// HandleRequestCertificate submits the CM-provided CSR to the ACME CA for issuance.
func (svc *WebhookService) HandleRequestCertificate(c echo.Context) error {
	req := RequestCertificateRequest{}
	if err := c.Bind(&req); err != nil {
		zap.L().Error("invalid request, failed to unmarshal json", zap.Error(err))
		return c.String(http.StatusBadRequest, fmt.Sprintf("failed to unmarshal json: %s", err.Error()))
	}

	cert, order, err := svc.Certificate.RequestCertificate(
		req.Connection,
		req.Pkcs10Request,
		req.Product,
		req.ProductOptionName,
		req.ValiditySeconds,
		req.ProductDetails,
	)
	if err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}

	return c.JSON(http.StatusOK, &RequestCertificateResponse{
		CertificateDetails: cert,
		OrderDetails:       order,
	})
}
