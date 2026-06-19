package letsencrypt

import (
	"fmt"
	"net/http"

	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/app/domain"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// TestConnectionRequest is the request payload for testConnection.
type TestConnectionRequest struct {
	Connection domain.Connection `json:"connection"`
}

// TestConnectionStatus indicates the outcome of a connection test.
type TestConnectionStatus string

const (
	TestConnectionSuccess TestConnectionStatus = "SUCCESS"
	TestConnectionFailed  TestConnectionStatus = "FAILED"
)

// TestConnectionResponse is the response for testConnection.
type TestConnectionResponse struct {
	Result  TestConnectionStatus `json:"result"`
	Message string               `json:"message"`
}

// HandleTestConnection registers/reuses the ACME account and validates the directory.
func (svc *WebhookService) HandleTestConnection(c echo.Context) error {
	req := TestConnectionRequest{}
	if err := c.Bind(&req); err != nil {
		zap.L().Error("invalid request, failed to unmarshal json", zap.Error(err))
		return c.String(http.StatusBadRequest, fmt.Sprintf("failed to unmarshal json: %s", err.Error()))
	}

	res := TestConnectionResponse{Result: TestConnectionFailed}

	msg, err := svc.Connections.TestConnection(req.Connection)
	if err != nil {
		zap.L().Error("error connecting to ACME directory", zap.String("error", err.Error()))
		res.Message = fmt.Sprintf("failed to connect to ACME directory: %s", err.Error())
	} else {
		res.Result = TestConnectionSuccess
		res.Message = msg
		zap.L().Info("successfully connected to ACME directory")
	}

	return c.JSON(http.StatusOK, res)
}
