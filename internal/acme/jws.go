package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
)

// AccountKey is the ECDSA P-256 ACME account key. The connector owns this key; reusing it
// keeps the account URI stable across renewals. It is the highest-value secret in the system.
type AccountKey struct {
	priv *ecdsa.PrivateKey
}

// GenerateAccountKey creates a new ECDSA P-256 account key.
func GenerateAccountKey() (*AccountKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate account key: %w", err)
	}
	return &AccountKey{priv: priv}, nil
}

// ParseAccountKey loads a PEM-encoded EC private key (SEC1 "EC PRIVATE KEY" or PKCS#8).
func ParseAccountKey(pemData []byte) (*AccountKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("acme: account key is not valid PEM")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		priv, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("acme: parse EC private key: %w", err)
		}
		return &AccountKey{priv: priv}, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("acme: parse PKCS#8 key: %w", err)
		}
		priv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("acme: account key must be ECDSA")
		}
		return &AccountKey{priv: priv}, nil
	default:
		return nil, fmt.Errorf("acme: unsupported account key PEM type %q", block.Type)
	}
}

// PEM marshals the account key as a SEC1 "EC PRIVATE KEY" PEM block.
func (k *AccountKey) PEM() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(k.priv)
	if err != nil {
		return nil, fmt.Errorf("acme: marshal account key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// coord renders a P-256 coordinate as a fixed 32-byte big-endian base64url string.
func coord(i interface{ FillBytes([]byte) []byte }) string {
	buf := make([]byte, 32)
	i.FillBytes(buf)
	return b64(buf)
}

// jwk returns the public JWK for the account key (RFC 7517), with deterministic key ordering
// so its thumbprint is stable.
func (k *AccountKey) jwk() map[string]string {
	return map[string]string{
		"crv": "P-256",
		"kty": "EC",
		"x":   coord(k.priv.PublicKey.X),
		"y":   coord(k.priv.PublicKey.Y),
	}
}

// signJWS builds a flattened ACME JWS (RFC 8555 §6.2). When kid != "" the protected header
// carries kid (used for all requests after account registration); otherwise it embeds the jwk
// (newAccount only). A nil payload produces a POST-as-GET request (empty-string payload).
func (k *AccountKey) signJWS(payload []byte, nonce, url, kid string) ([]byte, error) {
	protected := map[string]any{
		"alg":   "ES256",
		"nonce": nonce,
		"url":   url,
	}
	if kid != "" {
		protected["kid"] = kid
	} else {
		protected["jwk"] = k.jwk()
	}
	ph, err := json.Marshal(protected)
	if err != nil {
		return nil, err
	}

	protected64 := b64(ph)
	payload64 := ""
	if payload != nil {
		payload64 = b64(payload)
	}

	hash := sha256.Sum256([]byte(protected64 + "." + payload64))
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, hash[:])
	if err != nil {
		return nil, fmt.Errorf("acme: sign jws: %w", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[0:32])
	s.FillBytes(sig[32:64])

	return json.Marshal(map[string]string{
		"protected": protected64,
		"payload":   payload64,
		"signature": b64(sig),
	})
}
