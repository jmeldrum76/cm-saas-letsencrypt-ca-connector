package service

import (
	"context"
	"fmt"
	"time"

	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/app/domain"
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/record"
	"go.uber.org/zap"
)

// TestConnection loads the account key, validates the ACME directory, and registers/reuses the
// account. On success it returns (and logs) the account URI plus a copy-ready standing-record
// template — the value a customer takes to their DNS provider for DNS-persist validation.
func (s *Service) TestConnection(conn domain.Connection) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := buildClient(conn)
	if err != nil {
		return "", err
	}
	if err := ensureAccount(ctx, client, conn); err != nil {
		return "", err
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

	if isAutoMode(conn) {
		return fmt.Sprintf("Connected. ACME account URI: %s. Automated DNS mode — the connector will publish the %s record for you.",
			client.AccountURI(), record.Label), nil
	}
	return fmt.Sprintf("Connected. ACME account URI: %s. DNS-persist mode — publish this TXT record at your DNS provider once per domain (replace <your-domain>): %s",
		client.AccountURI(), tmpl.ZoneFile()), nil
}
