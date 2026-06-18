package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// RevokeCert revokes a certificate (DER bytes) using the account key (RFC 8555 §7.6). reason is
// an RFC 5280 reason code; 0 (unspecified) is omitted.
func (c *Client) RevokeCert(ctx context.Context, certDER []byte, reason int) error {
	dir, err := c.Directory(ctx)
	if err != nil {
		return err
	}
	payload := map[string]any{"certificate": b64(certDER)}
	if reason > 0 {
		payload["reason"] = reason
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	status, respBody, _, err := c.post(ctx, dir.RevokeCert, body)
	if err != nil {
		return fmt.Errorf("acme: revoke: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("acme: revoke unexpected status %d: %s", status, string(respBody))
	}
	return nil
}
