package letsencrypt

import (
	"fmt"
	"net/http"

	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/app/domain"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// CheckOrderRequest is the request payload for checkOrder. ID is the ACME order URL.
type CheckOrderRequest struct {
	Connection domain.Connection `json:"connection"`
	ID         string            `json:"id"`
}

// HandleCheckOrder polls the status of a pending ACME order.
func (svc *WebhookService) HandleCheckOrder(c echo.Context) error {
	req := CheckOrderRequest{}
	if err := c.Bind(&req); err != nil {
		zap.L().Error("invalid request, failed to unmarshal json", zap.Error(err))
		return c.String(http.StatusBadRequest, fmt.Sprintf("failed to unmarshal json: %s", err.Error()))
	}

	order, err := svc.Certificate.CheckOrder(req.Connection, req.ID)
	if err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}

	return c.JSON(http.StatusOK, order)
}
