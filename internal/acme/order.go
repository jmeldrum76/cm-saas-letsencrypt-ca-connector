package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// NewOrder submits a newOrder for the given DNS identifiers (CSR SANs) and returns the order
// with its URL populated from the Location header.
func (c *Client) NewOrder(ctx context.Context, dnsNames []string) (*Order, error) {
	dir, err := c.Directory(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]Identifier, 0, len(dnsNames))
	for _, name := range dnsNames {
		ids = append(ids, Identifier{Type: "dns", Value: name})
	}
	body, err := json.Marshal(map[string]any{"identifiers": ids})
	if err != nil {
		return nil, err
	}
	status, respBody, headers, err := c.post(ctx, dir.NewOrder, body)
	if err != nil {
		return nil, fmt.Errorf("acme: newOrder: %w", err)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return nil, fmt.Errorf("acme: newOrder unexpected status %d: %s", status, string(respBody))
	}
	o := &Order{}
	if err := json.Unmarshal(respBody, o); err != nil {
		return nil, fmt.Errorf("acme: parse order: %w", err)
	}
	o.URL = headers.Get("Location")
	return o, nil
}

// GetOrder fetches an order by URL (POST-as-GET).
func (c *Client) GetOrder(ctx context.Context, url string) (*Order, error) {
	status, body, _, err := c.postAsGet(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("acme: get order: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("acme: get order unexpected status %d: %s", status, string(body))
	}
	o := &Order{}
	if err := json.Unmarshal(body, o); err != nil {
		return nil, fmt.Errorf("acme: parse order: %w", err)
	}
	o.URL = url
	return o, nil
}

// GetAuthorization fetches an authorization by URL (POST-as-GET).
func (c *Client) GetAuthorization(ctx context.Context, url string) (*Authorization, error) {
	status, body, _, err := c.postAsGet(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("acme: get authorization: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("acme: get authorization unexpected status %d: %s", status, string(body))
	}
	authz := &Authorization{}
	if err := json.Unmarshal(body, authz); err != nil {
		return nil, fmt.Errorf("acme: parse authorization: %w", err)
	}
	return authz, nil
}

// AcceptChallenge signals readiness to validate by POSTing an empty object to the challenge URL.
// For dns-persist-01 the standing record is published out-of-band; this never creates a record.
func (c *Client) AcceptChallenge(ctx context.Context, challengeURL string) (*Challenge, error) {
	status, body, _, err := c.post(ctx, challengeURL, []byte("{}"))
	if err != nil {
		return nil, fmt.Errorf("acme: accept challenge: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("acme: accept challenge unexpected status %d: %s", status, string(body))
	}
	ch := &Challenge{}
	if err := json.Unmarshal(body, ch); err != nil {
		return nil, fmt.Errorf("acme: parse challenge: %w", err)
	}
	return ch, nil
}

// Finalize submits the CSR (DER) to the order's finalize URL and returns the updated order.
func (c *Client) Finalize(ctx context.Context, finalizeURL string, csrDER []byte) (*Order, error) {
	body, err := json.Marshal(map[string]string{"csr": b64(csrDER)})
	if err != nil {
		return nil, err
	}
	status, respBody, _, err := c.post(ctx, finalizeURL, body)
	if err != nil {
		return nil, fmt.Errorf("acme: finalize: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("acme: finalize unexpected status %d: %s", status, string(respBody))
	}
	o := &Order{}
	if err := json.Unmarshal(respBody, o); err != nil {
		return nil, fmt.Errorf("acme: parse finalized order: %w", err)
	}
	return o, nil
}

// GetCertificate downloads the issued certificate chain (PEM) via POST-as-GET.
func (c *Client) GetCertificate(ctx context.Context, certURL string) ([]byte, error) {
	status, body, _, err := c.postAsGet(ctx, certURL)
	if err != nil {
		return nil, fmt.Errorf("acme: get certificate: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("acme: get certificate unexpected status %d: %s", status, string(body))
	}
	return body, nil
}
