package service

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// parseCertificateData converts a PEM (or base64 DER) certificate chain into the format Venafi
// expects: the leaf as base64-encoded DER, and the remaining chain certs as base64 DER strings.
func parseCertificateData(certData string) (leaf string, chain []string, err error) {
	if certs, perr := parseCertificatePEM([]byte(certData)); perr == nil && len(certs) > 0 {
		leaf = base64.StdEncoding.EncodeToString(certs[0].Raw)
		for i := 1; i < len(certs); i++ {
			chain = append(chain, base64.StdEncoding.EncodeToString(certs[i].Raw))
		}
		return leaf, chain, nil
	}

	if der, derr := base64.StdEncoding.DecodeString(certData); derr == nil {
		if cert, cerr := x509.ParseCertificate(der); cerr == nil {
			return base64.StdEncoding.EncodeToString(cert.Raw), nil, nil
		}
	}
	return "", nil, errors.New("failed to parse certificate data: not valid PEM or base64 DER")
}

func parseCertificatePEM(certBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := certBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificate PEM blocks found")
	}
	return certs, nil
}

// decodeCertToDER returns the DER bytes of a single certificate supplied as PEM or base64 DER.
func decodeCertToDER(certData string) ([]byte, error) {
	if block, _ := pem.Decode([]byte(certData)); block != nil {
		return block.Bytes, nil
	}
	if der, err := base64.StdEncoding.DecodeString(certData); err == nil {
		return der, nil
	}
	return nil, errors.New("certificate is not valid PEM or base64 DER")
}
