package letsencrypt

import (
	"fmt"
	"net/http"

	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/app/domain"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// ValidateProductRequest is the request payload for validateProduct.
type ValidateProductRequest struct {
	Connection  domain.Connection `json:"connection"`
	ProductName string            `json:"name"`
	Product     domain.Product    `json:"product"`
}

// ValidateProductResponse contains any validation errors.
type ValidateProductResponse struct {
	Errors []domain.ProductError `json:"errors"`
}

// HandleValidateProduct validates the selected product configuration before issuance.
func (svc *WebhookService) HandleValidateProduct(c echo.Context) error {
	req := ValidateProductRequest{}
	if err := c.Bind(&req); err != nil {
		zap.L().Error("invalid request, failed to unmarshal json", zap.Error(err))
		return c.String(http.StatusBadRequest, fmt.Sprintf("failed to unmarshal json: %s", err.Error()))
	}

	productErrors, err := svc.Options.ValidateProduct(req.Connection, req.ProductName, req.Product)
	if err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}

	return c.JSON(http.StatusOK, &ValidateProductResponse{Errors: productErrors})
}
