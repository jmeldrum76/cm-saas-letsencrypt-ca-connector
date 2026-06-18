package acme

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// Register creates (or returns the existing) ACME account for the client's key and records the
// account URL (kid). Contacts are optional "mailto:" URIs. Reusing the same key returns the
// same account, keeping the account URI stable.
func (c *Client) Register(ctx context.Context, contacts []string) error {
	dir, err := c.Directory(ctx)
	if err != nil {
		return err
	}
	payload := map[string]any{"termsOfServiceAgreed": true}
	if len(contacts) > 0 {
		payload["contact"] = contacts
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	status, respBody, headers, err := c.post(ctx, dir.NewAccount, body)
	if err != nil {
		return fmt.Errorf("acme: newAccount: %w", err)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return fmt.Errorf("acme: newAccount unexpected status %d: %s", status, string(respBody))
	}
	loc := headers.Get("Location")
	if loc == "" {
		return errors.New("acme: newAccount returned no Location (account URL)")
	}
	c.AccountURL = loc
	return nil
}

// LookupAccount finds the existing account for the client's key without creating one
// (onlyReturnExisting). It fails if no account exists for the key.
func (c *Client) LookupAccount(ctx context.Context) error {
	dir, err := c.Directory(ctx)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{"onlyReturnExisting": true})
	if err != nil {
		return err
	}
	status, respBody, headers, err := c.post(ctx, dir.NewAccount, body)
	if err != nil {
		return fmt.Errorf("acme: lookup account: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("acme: lookup account unexpected status %d: %s", status, string(respBody))
	}
	loc := headers.Get("Location")
	if loc == "" {
		return errors.New("acme: lookup account returned no Location (account URL)")
	}
	c.AccountURL = loc
	return nil
}

// AccountURI returns the registered ACME account URL (kid), or "" if not yet registered.
func (c *Client) AccountURI() string { return c.AccountURL }
