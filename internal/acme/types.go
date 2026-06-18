// Package acme is a minimal ACME (RFC 8555) client that models the dns-persist-01 challenge
// (draft-ietf-acme-dns-persist) explicitly. It is intentionally DNS-free and publisher-free:
// it only ever VALIDATES against an already-present standing record. It must never import
// internal/publisher or any DNS/cloud SDK — a CI check enforces this.
package acme

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ChallengeDNSPersist01 is the challenge type defined by draft-ietf-acme-dns-persist.
const ChallengeDNSPersist01 = "dns-persist-01"

// ACME resource statuses (RFC 8555).
const (
	StatusPending     = "pending"
	StatusProcessing  = "processing"
	StatusValid       = "valid"
	StatusInvalid     = "invalid"
	StatusReady       = "ready"
	StatusDeactivated = "deactivated"
	StatusExpired     = "expired"
)

// Directory is the ACME directory resource (RFC 8555 §7.1.1).
type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
	Meta       struct {
		TermsOfService          string   `json:"termsOfService"`
		Website                 string   `json:"website"`
		CAAIdentities           []string `json:"caaIdentities"`
		ExternalAccountRequired bool     `json:"externalAccountRequired"`
	} `json:"meta"`
}

// Identifier is an ACME order identifier (RFC 8555 §7.1.4).
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Order is an ACME order resource (RFC 8555 §7.1.3). URL is the order's own location and is
// populated from the response Location header, not the JSON body.
type Order struct {
	Status         string       `json:"status"`
	Expires        string       `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate,omitempty"`
	Error          *Problem     `json:"error,omitempty"`

	URL string `json:"-"`
}

// Authorization is an ACME authorization resource (RFC 8555 §7.1.4).
type Authorization struct {
	Status     string      `json:"status"`
	Identifier Identifier  `json:"identifier"`
	Challenges []Challenge `json:"challenges"`
	Wildcard   bool        `json:"wildcard,omitempty"`
	Expires    string      `json:"expires,omitempty"`
}

// Challenge is an ACME challenge object. For dns-persist-01 it additionally carries the draft
// fields AccountURI and IssuerDomainNames.
type Challenge struct {
	Type   string   `json:"type"`
	URL    string   `json:"url"`
	Status string   `json:"status"`
	Token  string   `json:"token,omitempty"`
	Error  *Problem `json:"error,omitempty"`

	// dns-persist-01 (draft-ietf-acme-dns-persist) fields:
	AccountURI        string   `json:"accounturi,omitempty"`
	IssuerDomainNames []string `json:"issuer-domain-names,omitempty"`
}

// Problem is an RFC 7807 / RFC 8555 §6.7 problem document.
type Problem struct {
	Type        string      `json:"type"`
	Detail      string      `json:"detail"`
	Status      int         `json:"status"`
	Identifier  *Identifier `json:"identifier,omitempty"`
	Subproblems []Problem   `json:"subproblems,omitempty"`
}

// Error renders the problem in an actionable form.
func (p *Problem) Error() string {
	if p == nil {
		return "<nil acme problem>"
	}
	var b strings.Builder
	if p.Type != "" {
		b.WriteString(p.Type)
	}
	if p.Detail != "" {
		if b.Len() > 0 {
			b.WriteString(": ")
		}
		b.WriteString(p.Detail)
	}
	for i := range p.Subproblems {
		sp := &p.Subproblems[i]
		b.WriteString(" [")
		if sp.Identifier != nil {
			fmt.Fprintf(&b, "%s: ", sp.Identifier.Value)
		}
		b.WriteString(sp.Error())
		b.WriteString("]")
	}
	if b.Len() == 0 {
		return "unknown acme problem"
	}
	return b.String()
}

// parseProblem extracts a Problem from a response body, tolerating non-JSON bodies.
func parseProblem(body []byte, status int) *Problem {
	p := &Problem{}
	if err := json.Unmarshal(body, p); err != nil || (p.Type == "" && p.Detail == "") {
		return &Problem{Status: status, Detail: strings.TrimSpace(string(body))}
	}
	if p.Status == 0 {
		p.Status = status
	}
	return p
}
