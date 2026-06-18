package service

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// parseCSR accepts the CM-provided CSR (PEM with headers, or base64 DER) and returns its DER
// bytes (for ACME finalize) plus the DNS identifiers to order. The key is never regenerated —
// the DER is submitted as-is so the issued certificate matches the caller's private key.
func parseCSR(csrData string) (der []byte, dnsNames []string, err error) {
	if block, _ := pem.Decode([]byte(csrData)); block != nil {
		der = block.Bytes
	} else if raw, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(csrData)); decErr == nil {
		der = raw
	} else {
		return nil, nil, errors.New("CSR is not valid PEM or base64 DER")
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CSR: %w", err)
	}

	names := append([]string(nil), csr.DNSNames...)
	if len(names) == 0 && csr.Subject.CommonName != "" {
		names = append(names, csr.Subject.CommonName)
	}
	return der, dedupeLower(names), nil
}

func dedupeLower(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		key := strings.ToLower(strings.TrimSpace(s))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out
}
