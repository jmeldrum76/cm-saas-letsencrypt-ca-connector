package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/acme"
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/app/domain"
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/record"
	"go.uber.org/zap"
)

// RequestCertificate submits the CM-provided CSR to the ACME CA. It parses the CSR for DNS
// identifiers (never regenerating the key), optionally publishes the standing record once in
// auto mode, then runs newOrder -> resolve each authorization (JIT or accept) -> finalize, and
// returns the ACME order URL as the request ID for checkOrder/checkCertificate to poll.
func (s *Service) RequestCertificate(conn domain.Connection, pkcs10Request string, _ domain.Product, _ string, _ int, _ *domain.ProductDetails) (*domain.CertificateDetails, *domain.OrderDetails, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	client, err := buildClient(conn)
	if err != nil {
		return nil, nil, err
	}
	if err := ensureAccount(ctx, client, conn); err != nil {
		return nil, nil, fmt.Errorf("register ACME account: %w", err)
	}

	csrDER, dnsNames, err := parseCSR(pkcs10Request)
	if err != nil {
		return nil, nil, err
	}
	if len(dnsNames) == 0 {
		return nil, nil, errors.New("CSR contains no DNS names to order")
	}

	// Auto mode only: publish the standing record once per identifier (idempotent). The protocol
	// engine below never touches DNS — manual mode reaches it with zero DNS calls.
	if isAutoMode(conn) {
		if err := s.ensureStandingRecords(ctx, conn, client, dnsNames); err != nil {
			return nil, nil, err
		}
	}

	order, err := client.NewOrder(ctx, dnsNames)
	if err != nil {
		return nil, nil, err
	}
	for _, authzURL := range order.Authorizations {
		if err := client.ResolveAuthorization(ctx, authzURL, acme.DefaultPoll); err != nil {
			return nil, nil, err
		}
	}
	if _, err := client.Finalize(ctx, order.Finalize, csrDER); err != nil {
		return nil, nil, err
	}

	zap.L().Info("certificate order submitted",
		zap.String("order", order.URL),
		zap.Strings("identifiers", dnsNames),
		zap.String("dcvMode", conn.Configuration.DCVMode),
	)
	return nil, &domain.OrderDetails{ID: order.URL, Status: domain.OrderStatusProcessing}, nil
}

// ensureStandingRecords publishes the _validation-persist record for each identifier (auto mode).
func (s *Service) ensureStandingRecords(ctx context.Context, conn domain.Connection, client *acme.Client, dnsNames []string) error {
	zoneID := conn.Configuration.HostedZoneID
	if zoneID == "" {
		return errors.New("auto mode requires a DNS hosted zone ID")
	}
	pub, err := s.publisherFor(ctx, conn)
	if err != nil {
		return err
	}
	issuer := issuerOf(conn)
	for _, name := range dnsNames {
		rec, err := record.Generate(record.Params{Domain: name, IssuerDomain: issuer, AccountURI: client.AccountURI()})
		if err != nil {
			return err
		}
		if err := pub.EnsureRecord(ctx, zoneID, rec.FQDN, rec.Value); err != nil {
			return fmt.Errorf("publish standing record for %s: %w", name, err)
		}
		zap.L().Info("standing record ensured", zap.String("fqdn", rec.FQDN))
	}
	return nil
}

// CheckOrder polls the ACME order (by URL) and maps its status for CM.
func (s *Service) CheckOrder(conn domain.Connection, id string) (*domain.OrderDetails, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client, err := buildClient(conn)
	if err != nil {
		return nil, err
	}
	if err := ensureAccount(ctx, client, conn); err != nil {
		return nil, err
	}
	order, err := client.GetOrder(ctx, id)
	if err != nil {
		return nil, err
	}

	od := &domain.OrderDetails{ID: id}
	switch order.Status {
	case acme.StatusValid:
		od.Status = domain.OrderStatusCompleted
		od.CertificateID = id
	case acme.StatusInvalid:
		od.Status = domain.OrderStatusFailed
		if order.Error != nil {
			od.ErrorMessage = order.Error.Error()
		}
	default:
		od.Status = domain.OrderStatusProcessing
	}
	return od, nil
}

// CheckCertificate downloads the issued certificate (by order URL) and returns it as base64 DER.
func (s *Service) CheckCertificate(conn domain.Connection, id string) (*domain.CertificateDetails, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client, err := buildClient(conn)
	if err != nil {
		return nil, err
	}
	if err := ensureAccount(ctx, client, conn); err != nil {
		return nil, err
	}
	order, err := client.GetOrder(ctx, id)
	if err != nil {
		return nil, err
	}

	cd := &domain.CertificateDetails{ID: id}
	switch order.Status {
	case acme.StatusValid:
		if order.Certificate == "" {
			cd.Status = domain.CertificateStatusRequested
			return cd, nil
		}
		pemChain, err := client.GetCertificate(ctx, order.Certificate)
		if err != nil {
			return nil, err
		}
		leaf, chain, err := parseCertificateData(string(pemChain))
		if err != nil {
			return nil, err
		}
		cd.Status = domain.CertificateStatusIssued
		cd.Certificate = leaf
		cd.Chain = chain
	case acme.StatusInvalid:
		cd.Status = domain.CertificateStatusFailed
		if order.Error != nil {
			cd.ErrorMessage = order.Error.Error()
		}
	default:
		cd.Status = domain.CertificateStatusPending
	}
	return cd, nil
}

// RetrieveCertificates is a no-op: ACME accounts cannot enumerate previously issued certificates,
// so there is nothing to import. Returns an empty COMPLETED page.
func (s *Service) RetrieveCertificates(_ domain.Connection, _ domain.ImportOption, _ domain.ImportConfiguration, _ string, _ int) (*domain.ImportDetails, error) {
	return &domain.ImportDetails{ImportStatus: domain.ImportStatusCompleted}, nil
}

// RevokeCertificate revokes a certificate via the ACME revokeCert endpoint. ACME revokes by the
// certificate itself, so the revocation data must carry the certificate content.
func (s *Service) RevokeCertificate(conn domain.Connection, data domain.CertificateRevocationData, reason int) (*domain.RevocationDetails, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if data.CertificateContent == "" {
		return failedRevocation("ACME revocation requires the certificate content"), nil
	}
	certDER, err := decodeCertToDER(data.CertificateContent)
	if err != nil {
		return failedRevocation(err.Error()), nil
	}

	client, err := buildClient(conn)
	if err != nil {
		return nil, err
	}
	if err := ensureAccount(ctx, client, conn); err != nil {
		return nil, err
	}
	if err := client.RevokeCert(ctx, certDER, reason); err != nil {
		return failedRevocation(err.Error()), nil
	}
	return &domain.RevocationDetails{Status: domain.RevocationStatusSubmitted}, nil
}

func failedRevocation(msg string) *domain.RevocationDetails {
	return &domain.RevocationDetails{Status: domain.RevocationStatusFailed, ErrorMessage: &msg}
}
