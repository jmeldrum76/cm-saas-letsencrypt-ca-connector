package service

import (
	"context"
	"time"

	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/app/domain"
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/record"
	"go.uber.org/zap"
)

// TestConnection loads the account key, validates the ACME directory, and registers/reuses the
// account. On success it logs the account URI and a copy-ready standing-record template the
// operator can hand to a domain owner (manual mode).
func (s *Service) TestConnection(conn domain.Connection) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := buildClient(conn)
	if err != nil {
		return err
	}
	if err := ensureAccount(ctx, client, conn); err != nil {
		return err
	}

	tmpl, _ := record.Generate(record.Params{
		Domain:       "<your-domain>",
		IssuerDomain: issuerOf(conn),
		AccountURI:   client.AccountURI(),
	})
	zap.L().Info("ACME account ready",
		zap.String("directoryUrl", directoryURLOf(conn)),
		zap.String("accountURI", client.AccountURI()),
		zap.String("dcvMode", conn.Configuration.DCVMode),
		zap.String("standingRecordTemplate", tmpl.ZoneFile()),
	)
	return nil
}
