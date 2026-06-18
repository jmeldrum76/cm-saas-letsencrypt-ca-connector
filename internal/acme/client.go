package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Client is a minimal ACME client bound to one account key and one directory. After Register
// or LookupAccount, AccountURL (the kid) is set and used to sign all subsequent requests.
type Client struct {
	DirectoryURL string
	Key          *AccountKey
	// IssuerDomain is the expected issuer domain validated against a dns-persist-01 challenge's
	// issuer-domain-names before the challenge is accepted (e.g. "letsencrypt.org").
	IssuerDomain string
	// AccountURL is the ACME account URL (kid). Empty until Register/LookupAccount succeeds.
	AccountURL string
	// HTTPClient is optional; a 30s-timeout client is used when nil.
	HTTPClient *http.Client

	mu    sync.Mutex
	dir   *Directory
	nonce string
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// Directory lazily fetches and caches the ACME directory resource.
func (c *Client) Directory(ctx context.Context) (*Directory, error) {
	c.mu.Lock()
	if c.dir != nil {
		d := c.dir
		c.mu.Unlock()
		return d, nil
	}
	c.mu.Unlock()

	if c.DirectoryURL == "" {
		return nil, errors.New("acme: directory URL is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.DirectoryURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("acme: fetch directory: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("acme: directory status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	d := &Directory{}
	if err := json.Unmarshal(body, d); err != nil {
		return nil, fmt.Errorf("acme: parse directory: %w", err)
	}
	c.mu.Lock()
	c.dir = d
	c.mu.Unlock()
	return d, nil
}

func (c *Client) setNonce(n string) {
	c.mu.Lock()
	c.nonce = n
	c.mu.Unlock()
}

// getNonce returns a cached replay nonce if available, else fetches a fresh one via newNonce.
func (c *Client) getNonce(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.nonce != "" {
		n := c.nonce
		c.nonce = ""
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()

	dir, err := c.Directory(ctx)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, dir.NewNonce, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("acme: get nonce: %w", err)
	}
	resp.Body.Close()
	n := resp.Header.Get("Replay-Nonce")
	if n == "" {
		return "", errors.New("acme: newNonce returned no Replay-Nonce header")
	}
	return n, nil
}

// post sends a signed JWS request. A nil payload yields a POST-as-GET (empty payload). It
// captures the response Replay-Nonce and retries once on a badNonce problem.
func (c *Client) post(ctx context.Context, url string, payload []byte) (int, []byte, http.Header, error) {
	if _, err := c.Directory(ctx); err != nil {
		return 0, nil, nil, err
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		nonce, err := c.getNonce(ctx)
		if err != nil {
			return 0, nil, nil, err
		}
		signed, err := c.Key.signJWS(payload, nonce, url, c.AccountURL)
		if err != nil {
			return 0, nil, nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(signed))
		if err != nil {
			return 0, nil, nil, err
		}
		req.Header.Set("Content-Type", "application/jose+json")
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient().Do(req)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("acme: POST %s: %w", url, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if n := resp.Header.Get("Replay-Nonce"); n != "" {
			c.setNonce(n)
		}

		if resp.StatusCode >= 400 {
			prob := parseProblem(body, resp.StatusCode)
			if attempt == 0 && strings.Contains(prob.Type, "badNonce") {
				lastErr = prob
				continue
			}
			return resp.StatusCode, body, resp.Header, prob
		}
		return resp.StatusCode, body, resp.Header, nil
	}
	return 0, nil, nil, lastErr
}

// postAsGet performs an authenticated POST-as-GET (RFC 8555 §6.3).
func (c *Client) postAsGet(ctx context.Context, url string) (int, []byte, http.Header, error) {
	return c.post(ctx, url, nil)
}
