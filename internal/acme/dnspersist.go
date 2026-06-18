package acme

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// FindDNSPersistChallenge returns the dns-persist-01 challenge from an authorization, if present.
func FindDNSPersistChallenge(authz *Authorization) (*Challenge, bool) {
	for i := range authz.Challenges {
		if authz.Challenges[i].Type == ChallengeDNSPersist01 {
			return &authz.Challenges[i], true
		}
	}
	return nil, false
}

// ValidateIssuer confirms the challenge advertises the configured issuer domain in its
// issuer-domain-names. We never blindly trust the order; the operator's configured issuer must
// be one the CA will honour for the standing record.
func ValidateIssuer(ch *Challenge, issuerDomain string) error {
	want := strings.ToLower(strings.TrimSpace(issuerDomain))
	if want == "" {
		return errors.New("acme: configured issuer domain is empty")
	}
	for _, d := range ch.IssuerDomainNames {
		if strings.EqualFold(strings.TrimSpace(d), want) {
			return nil
		}
	}
	return fmt.Errorf("acme: dns-persist-01 issuer-domain-names %v do not include configured issuer %q", ch.IssuerDomainNames, issuerDomain)
}

// ResolveAuthorization brings a single authorization to "valid" using dns-persist-01, assuming
// the standing _validation-persist record has already been published out-of-band. It performs
// NO DNS operations. The flow:
//
//   - status "valid"   → just-in-time validation already hit the standing record; done.
//   - status "pending" → locate the dns-persist-01 challenge, validate the issuer domain,
//                        POST to the challenge to signal readiness, then poll until valid.
//   - status "invalid" → the standing record is missing/invalid; return an actionable error.
func (c *Client) ResolveAuthorization(ctx context.Context, authzURL string, poll PollConfig) error {
	authz, err := c.GetAuthorization(ctx, authzURL)
	if err != nil {
		return err
	}

	switch authz.Status {
	case StatusValid:
		return nil // JIT validation already succeeded against the standing record
	case StatusInvalid:
		return c.authzRecordError(authz)
	case StatusPending, StatusProcessing:
		// proceed below
	default:
		return fmt.Errorf("acme: authorization for %s in unexpected status %q", authz.Identifier.Value, authz.Status)
	}

	ch, ok := FindDNSPersistChallenge(authz)
	if !ok {
		return fmt.Errorf("acme: authorization for %s does not offer a %s challenge (offered: %s)",
			authz.Identifier.Value, ChallengeDNSPersist01, challengeTypes(authz))
	}
	if err := ValidateIssuer(ch, c.IssuerDomain); err != nil {
		return err
	}
	if _, err := c.AcceptChallenge(ctx, ch.URL); err != nil {
		return err
	}

	final, err := c.waitForAuthz(ctx, authzURL, poll)
	if err != nil {
		return err
	}
	if final.Status == StatusValid {
		return nil
	}
	return c.authzRecordError(final)
}

// authzRecordError turns a failed authorization into an actionable "publish the standing record"
// message, naming the exact expected record.
func (c *Client) authzRecordError(authz *Authorization) error {
	var detail string
	if ch, ok := FindDNSPersistChallenge(authz); ok && ch.Error != nil {
		detail = ": " + ch.Error.Error()
	}
	return fmt.Errorf("acme: domain control validation failed for %s%s — publish the standing %s.%s TXT record "+
		"(issuer %q, accounturi %s) and retry",
		authz.Identifier.Value, detail, "_validation-persist", authz.Identifier.Value, c.IssuerDomain, c.AccountURL)
}

func challengeTypes(authz *Authorization) string {
	types := make([]string, 0, len(authz.Challenges))
	for i := range authz.Challenges {
		types = append(types, authz.Challenges[i].Type)
	}
	return strings.Join(types, ", ")
}

// PollConfig bounds how long the engine polls an authorization or order for a terminal state.
type PollConfig struct {
	Interval time.Duration
	Timeout  time.Duration
}

// DefaultPoll is a reasonable bounded poll for synchronous use (tests, auto mode). In the
// framework split, CM re-invokes checkOrder/checkCertificate instead of long polling.
var DefaultPoll = PollConfig{Interval: 2 * time.Second, Timeout: 60 * time.Second}

func (p PollConfig) withDefaults() PollConfig {
	if p.Interval <= 0 {
		p.Interval = DefaultPoll.Interval
	}
	if p.Timeout <= 0 {
		p.Timeout = DefaultPoll.Timeout
	}
	return p
}

func (c *Client) waitForAuthz(ctx context.Context, authzURL string, poll PollConfig) (*Authorization, error) {
	poll = poll.withDefaults()
	deadline := time.Now().Add(poll.Timeout)
	for {
		authz, err := c.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, err
		}
		if authz.Status != StatusPending && authz.Status != StatusProcessing {
			return authz, nil
		}
		if time.Now().After(deadline) {
			return authz, fmt.Errorf("acme: timed out waiting for authorization %s to validate (last status %q)", authz.Identifier.Value, authz.Status)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(poll.Interval):
		}
	}
}

// WaitForOrder polls an order until it leaves pending/processing (e.g. reaches valid after
// finalize) or the poll budget is exhausted.
func (c *Client) WaitForOrder(ctx context.Context, orderURL string, poll PollConfig) (*Order, error) {
	poll = poll.withDefaults()
	deadline := time.Now().Add(poll.Timeout)
	for {
		order, err := c.GetOrder(ctx, orderURL)
		if err != nil {
			return nil, err
		}
		if order.Status != StatusPending && order.Status != StatusProcessing {
			return order, nil
		}
		if time.Now().After(deadline) {
			return order, fmt.Errorf("acme: timed out waiting for order to complete (last status %q)", order.Status)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(poll.Interval):
		}
	}
}
