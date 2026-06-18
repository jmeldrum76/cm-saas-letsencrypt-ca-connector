// Package record implements Capability A: deterministic generation of the dns-persist-01
// "_validation-persist" TXT record the domain owner must publish. It is pure assembly from
// values the connector already holds (issuer domain, ACME account URI, scope) and performs
// NO DNS access. It is safe to import from anywhere, including the DNS-free ACME engine.
//
// Format (RFC 8659 issue-value syntax, per draft-ietf-acme-dns-persist and the Let's Encrypt
// announcement):
//
//	_validation-persist.<domain>. IN TXT "<issuer>; accounturi=<uri>[; policy=wildcard][; persistUntil=<ts>]"
package record

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Label is the fixed DNS label prefixed to the registered domain.
const Label = "_validation-persist"

// Params are the inputs needed to render a record. All string inputs are trimmed; Domain and
// IssuerDomain are lowercased (DNS is case-insensitive).
type Params struct {
	// Domain is the identifier from the order/CSR. It may be a bare FQDN ("example.com") or a
	// wildcard ("*.example.com"); a "*." prefix implies wildcard scope.
	Domain string
	// IssuerDomain is the CA's issuer domain (e.g. "letsencrypt.org"). It must match one of the
	// challenge's issuer-domain-names. Validation of that match happens in the ACME engine.
	IssuerDomain string
	// AccountURI is this connector's ACME account URL (the kid).
	AccountURI string
	// Wildcard forces the policy=wildcard parameter. It is also set automatically when Domain
	// carries a "*." prefix.
	Wildcard bool
	// PersistUntil, when > 0, emits persistUntil=<unix_ts> (a base-10 integer). 0 omits it.
	PersistUntil int64
}

// Record is a generated TXT record ready to hand to the domain owner or publish via a Publisher.
type Record struct {
	FQDN  string // e.g. "_validation-persist.example.com"
	Type  string // always "TXT"
	Value string // the concatenated rdata string (what goes in a DNS provider's TXT value)
}

// Generate renders the standing _validation-persist record for the given parameters.
func Generate(p Params) (Record, error) {
	base := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(p.Domain), "*.")), "."))
	wildcard := p.Wildcard || strings.HasPrefix(strings.TrimSpace(p.Domain), "*.")
	issuer := strings.ToLower(strings.TrimSpace(p.IssuerDomain))
	accountURI := strings.TrimSpace(p.AccountURI)

	if base == "" {
		return Record{}, errors.New("record: domain is required")
	}
	if issuer == "" {
		return Record{}, errors.New("record: issuer domain is required")
	}
	if accountURI == "" {
		return Record{}, errors.New("record: account URI is required")
	}

	fields := []string{issuer, "accounturi=" + accountURI}
	if wildcard {
		fields = append(fields, "policy=wildcard")
	}
	if p.PersistUntil > 0 {
		fields = append(fields, "persistUntil="+strconv.FormatInt(p.PersistUntil, 10))
	}

	return Record{
		FQDN:  Label + "." + base,
		Type:  "TXT",
		Value: strings.Join(fields, "; "),
	}, nil
}

// ZoneFile renders the record as a single-line zone-file entry, suitable for showing the
// operator copy-ready text to hand to the domain owner (manual mode).
func (r Record) ZoneFile() string {
	return fmt.Sprintf("%s. IN TXT %q", r.FQDN, r.Value)
}
