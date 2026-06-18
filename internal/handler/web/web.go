// Package web hosts the Echo HTTP server, route registration, and the payload-encryption
// middleware that decrypts vSatellite-encrypted request bodies. This file is the CA-connector
// variant: the WebhookService interface and routes cover all 8 CA endpoints.
package web

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"os"

	"github.com/labstack/echo/v4"
	"go.uber.org/fx"
	"go.uber.org/zap"
	"gopkg.in/square/go-jose.v2"
)

// WebhookService defines the 8 CA connector operation handlers.
type WebhookService interface {
	HandleTestConnection(c echo.Context) error
	HandleGetOptions(c echo.Context) error
	HandleValidateProduct(c echo.Context) error
	HandleRequestCertificate(c echo.Context) error
	HandleCheckOrder(c echo.Context) error
	HandleCheckCertificate(c echo.Context) error
	HandleImportCertificates(c echo.Context) error
	HandleRevokeCertificate(c echo.Context) error
}

// ConfigureHTTPServers creates the HTTP server for the connector.
func ConfigureHTTPServers(lifecycle fx.Lifecycle, shutdowner fx.Shutdowner) (*echo.Echo, error) {
	e := echo.New()

	lifecycle.Append(fx.Hook{
		OnStart: func(_ context.Context) error {
			go func() {
				if err := e.Start(":8080"); err != nil && err != http.ErrServerClosed {
					zap.L().Error("failed to start echo server", zap.Error(err))
					if err = shutdowner.Shutdown(); err != nil {
						zap.L().Error("fx shutdown error", zap.Error(err))
					}
				}
			}()
			return nil
		},
		OnStop: func(ctx context.Context) error {
			return e.Shutdown(ctx)
		},
	})

	return e, nil
}

// RegisterHandlers adds the method handlers for the supported routes.
func RegisterHandlers(e *echo.Echo, whService WebhookService) error {
	e.GET("/healthz", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	g := e.Group("/v1")
	addPayloadEncryptionMiddleware(g)
	g.POST("/testconnection", whService.HandleTestConnection)
	g.POST("/getoptions", whService.HandleGetOptions)
	g.POST("/validateproduct", whService.HandleValidateProduct)
	g.POST("/requestcertificate", whService.HandleRequestCertificate)
	g.POST("/checkorder", whService.HandleCheckOrder)
	g.POST("/checkcertificate", whService.HandleCheckCertificate)
	g.POST("/importcertificates", whService.HandleImportCertificates)
	g.POST("/revokecertificate", whService.HandleRevokeCertificate)

	return nil
}

func addPayloadEncryptionMiddleware(g *echo.Group) {
	privateKeyPemData, err := os.ReadFile("/keys/payload-encryption-key.pem")
	if err != nil {
		zap.L().Warn("payload encryption key not found - running without encryption (expected for local development)", zap.Error(err))
		return
	}
	p, _ := pem.Decode(privateKeyPemData)
	if p == nil {
		zap.L().Error("payload encryption key not in PEM format")
		return
	}
	pk, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		zap.L().Error("payload encryption key not properly encoded", zap.Error(err))
		return
	}
	zap.L().Info("adding payload encryption middleware")
	g.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			body, err := io.ReadAll(req.Body)
			if err != nil {
				zap.L().Error("failed to read request body", zap.Error(err))
				return err
			}
			zap.L().Info("received request",
				zap.String("path", req.URL.Path),
				zap.Int("bodySize", len(body)),
			)
			object, err := jose.ParseEncrypted(string(body))
			if err != nil {
				zap.L().Error("failed to parse encrypted payload", zap.Error(err))
				return err
			}
			decrypted, err := object.Decrypt(pk)
			if err != nil {
				zap.L().Error("failed to decrypt payload", zap.Error(err))
				return err
			}
			zap.L().Info("payload decrypted",
				zap.Int("decryptedSize", len(decrypted)),
			)
			req.Body = io.NopCloser(bytes.NewReader(decrypted))
			return next(c)
		}
	})
}
