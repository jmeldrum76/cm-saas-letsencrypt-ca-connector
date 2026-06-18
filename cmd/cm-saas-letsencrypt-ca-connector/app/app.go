package app

import (
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/app/letsencrypt"
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/app/service"
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/handler/web"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New creates and configures the application.
//
// Wiring: the single *service.Service backs all three connector service interfaces
// (Connection/Options/Certificate). The letsencrypt.WebhookService aggregates them and is
// exposed to the HTTP layer as web.WebhookService.
func New() *fx.App {
	var logger *zap.Logger

	app := fx.New(
		// Route fx's own lifecycle logs through zap (structured JSON) instead of the default
		// console logger, so startup logs don't interleave with the connector's zap output.
		fx.WithLogger(func(log *zap.Logger) fxevent.Logger {
			return &fxevent.ZapLogger{Logger: log}
		}),
		fx.Provide(
			configureLogger,
			web.ConfigureHTTPServers,
			// Provide the single stateless service once, then expose it as each interface seam.
			service.NewService,
			func(s *service.Service) letsencrypt.ConnectionService { return s },
			func(s *service.Service) letsencrypt.OptionsService { return s },
			func(s *service.Service) letsencrypt.CertificateService { return s },
			fx.Annotate(letsencrypt.NewWebhookService, fx.As(new(web.WebhookService))),
		),
		fx.Invoke(
			web.RegisterHandlers,
		),
		fx.Populate(&logger),
	)

	logger.Info("cm-saas-letsencrypt-ca-connector starting")

	return app
}

func configureLogger() (*zap.Logger, error) {
	loggerConfig := zap.NewProductionConfig()
	loggerConfig.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	loggerConfig.EncoderConfig = zap.NewProductionEncoderConfig()
	loggerConfig.EncoderConfig.TimeKey = "time"
	loggerConfig.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	loggerConfig.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
	logger, err := loggerConfig.Build()
	if err != nil {
		return nil, err
	}
	zap.ReplaceGlobals(logger)
	zap.RedirectStdLog(zap.L())
	return zap.L(), nil
}
