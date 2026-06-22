package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/acme"
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/record"
	"golang.org/x/net/publicsuffix"
)

const (
	dirStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
	dirProd    = "https://acme-v02.api.letsencrypt.org/directory"
	issuer     = "letsencrypt.org"
)

func dirURL(prod bool) string {
	if prod {
		return dirProd
	}
	return dirStaging
}

func recordValue(uri string) string { return issuer + "; accounturi=" + uri }

// normalizeContact prepends the mailto: scheme Let's Encrypt requires when the operator enters a
// bare email address.
func normalizeContact(c string) string {
	c = strings.TrimSpace(c)
	if c == "" || strings.HasPrefix(strings.ToLower(c), "mailto:") {
		return c
	}
	return "mailto:" + c
}

// clientForKeyPEM parses a PEM account key and registers (idempotent) so the account URI resolves.
func clientForKeyPEM(ctx context.Context, keyPEM []byte, prod bool, contact string) (*acme.Client, error) {
	key, err := acme.ParseAccountKey(keyPEM)
	if err != nil {
		return nil, err
	}
	c := &acme.Client{DirectoryURL: dirURL(prod), Key: key, IssuerDomain: issuer}
	var contacts []string
	if contact != "" {
		contacts = []string{contact}
	}
	if err := c.Register(ctx, contacts); err != nil {
		return nil, fmt.Errorf("register/resolve ACME account: %w", err)
	}
	return c, nil
}

// splitDomains parses a comma/space/newline separated list, stripping a leading _validation-persist.
// label and "*." prefix, lowercasing, trimming trailing dots, and de-duplicating.
func splitDomains(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r' || r == ';'
	})
	seen := map[string]bool{}
	out := []string{}
	for _, f := range fields {
		d := strings.ToLower(strings.Trim(strings.TrimSpace(f), "."))
		d = strings.TrimPrefix(d, record.Label+".")
		d = strings.TrimPrefix(d, "*.")
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// recordLive reports whether a TXT record at fqdn binds the domain to this account (names the issuer
// and carries accounturi=<uri>). Trailing policy/persistUntil tokens are ignored.
func recordLive(ctx context.Context, fqdn, accountURI string) bool {
	txts, err := net.DefaultResolver.LookupTXT(ctx, fqdn)
	if err != nil {
		return false
	}
	want := "accounturi=" + strings.ToLower(accountURI)
	for _, t := range txts {
		norm := strings.ReplaceAll(strings.ToLower(t), " ", "")
		if strings.HasPrefix(norm, issuer+";") && strings.Contains(norm, want) {
			return true
		}
	}
	return false
}

// --- structured results shared by the CLI and the web API ---

type RecordLine struct {
	FQDN  string `json:"fqdn"`
	Value string `json:"value"`
}

type DomainResult struct {
	Domain string `json:"domain"`
	Live   bool   `json:"live"`
}

type PlanRecord struct {
	FQDN   string   `json:"fqdn"`
	Value  string   `json:"value"`
	Covers []string `json:"covers"`
	Live   *bool    `json:"live,omitempty"`
}

type ZonePlan struct {
	Zone    string       `json:"zone"`
	Records []PlanRecord `json:"records"`
}

// --- operations (used by both CLI subcommands and web handlers) ---

// opNewAccount generates a fresh account key, registers it, and returns the PEM and account URI.
func opNewAccount(ctx context.Context, prod bool, contact string) (pemStr, uri string, err error) {
	key, err := acme.GenerateAccountKey()
	if err != nil {
		return "", "", err
	}
	pemBytes, err := key.PEM()
	if err != nil {
		return "", "", err
	}
	c := &acme.Client{DirectoryURL: dirURL(prod), Key: key, IssuerDomain: issuer}
	var contacts []string
	if cc := normalizeContact(contact); cc != "" {
		contacts = []string{cc}
	}
	if err := c.Register(ctx, contacts); err != nil {
		return "", "", fmt.Errorf("register ACME account: %w", err)
	}
	return string(pemBytes), c.AccountURI(), nil
}

// opRecords resolves the account URI for keyPEM and builds the standing record for each domain.
func opRecords(ctx context.Context, keyPEM []byte, domains []string, wildcard, prod bool) (uri string, recs []RecordLine, err error) {
	c, err := clientForKeyPEM(ctx, keyPEM, prod, "")
	if err != nil {
		return "", nil, err
	}
	uri = c.AccountURI()
	for _, d := range domains {
		rec, gerr := record.Generate(record.Params{Domain: d, IssuerDomain: issuer, AccountURI: uri, Wildcard: wildcard})
		if gerr != nil {
			return "", nil, fmt.Errorf("%s: %w", d, gerr)
		}
		recs = append(recs, RecordLine{FQDN: rec.FQDN, Value: rec.Value})
	}
	return uri, recs, nil
}

// opEmail resolves the account URI for keyPEM, builds the records, and renders a ready-to-send
// vendor-agnostic email the operator can forward to a domain owner.
func opEmail(ctx context.Context, keyPEM []byte, domains []string, wildcard, prod bool) (uri, email string, err error) {
	uri, recs, err := opRecords(ctx, keyPEM, domains, wildcard, prod)
	if err != nil {
		return "", "", err
	}
	return uri, buildCustomerEmail(recs, wildcard), nil
}

// buildCustomerEmail renders the email body. It stays vendor-agnostic (the three fields every DNS
// provider has) and reassures that the record is a one-time, harmless validation marker.
func buildCustomerEmail(recs []RecordLine, wildcard bool) string {
	var b strings.Builder
	b.WriteString("Subject: Action needed - add one DNS TXT record per domain (one-time; enables auto-renewing certificates)\n\n")
	b.WriteString("Hi,\n\n")
	b.WriteString("To issue and then AUTOMATICALLY RENEW the TLS/SSL certificate(s) for your domain(s), please add one DNS TXT record per domain wherever your DNS is managed. This is a ONE-TIME setup - once it is in place, certificates renew on their own with no further DNS changes.\n\n")
	b.WriteString("This record is only a validation marker. It does NOT affect your website, email, or any existing DNS.\n\n")
	b.WriteString("Record(s) to create:\n\n")
	for i, r := range recs {
		domain := strings.TrimPrefix(r.FQDN, record.Label+".")
		fmt.Fprintf(&b, "%d) Domain: %s\n", i+1, domain)
		b.WriteString("   Type:  TXT\n")
		fmt.Fprintf(&b, "   Name:  %s   (if your provider asks for the full name, use: %s)\n", record.Label, r.FQDN)
		fmt.Fprintf(&b, "   Value: %s\n", r.Value)
		b.WriteString("   TTL:   300 (or your provider's default)\n\n")
	}
	b.WriteString("Please note (applies to any DNS provider):\n")
	b.WriteString("- The Value is a single line. Paste it exactly, keeping the whole string together (spaces and semicolons included).\n")
	b.WriteString("- If your provider shows a plain value box, do NOT add quotation marks; some providers add them for you.\n")
	b.WriteString("- Please do not delete this record - it must stay in place so renewals keep working.\n")
	if wildcard {
		b.WriteString("- This record also covers all sub-domains (*.your-domain) for wildcard certificates.\n")
	}
	b.WriteString("\nReply once it is added and we will confirm everything checks out. Thank you!\n")
	b.WriteString("\nP.S. Where DNS records live in common providers: AWS Route 53 -> Hosted zones -> your domain -> Create record. Cloudflare -> DNS -> Records -> Add record. GoDaddy -> Domain -> DNS -> Add. Azure DNS -> your DNS zone -> Record sets -> Add.\n")
	return b.String()
}

// opValidate resolves the account URI for keyPEM and DNS-checks each domain's standing record.
func opValidate(ctx context.Context, keyPEM []byte, domains []string, prod bool) (uri string, results []DomainResult, err error) {
	c, err := clientForKeyPEM(ctx, keyPEM, prod, "")
	if err != nil {
		return "", nil, err
	}
	uri = c.AccountURI()
	for _, d := range domains {
		rec, gerr := record.Generate(record.Params{Domain: d, IssuerDomain: issuer, AccountURI: uri})
		live := gerr == nil && recordLive(ctx, rec.FQDN, uri)
		results = append(results, DomainResult{Domain: d, Live: live})
	}
	return uri, results, nil
}

// opPlan reads a certificate's SANs, collapses them to the minimal record set grouped by DNS zone,
// and (optionally) DNS-checks each planned record.
func opPlan(ctx context.Context, certData, keyPEM []byte, prod, validate bool) (uri string, zones []ZonePlan, sanCount int, err error) {
	names, err := certSANsFromBytes(certData)
	if err != nil {
		return "", nil, 0, err
	}
	if len(names) == 0 {
		return "", nil, 0, fmt.Errorf("no DNS names found in the certificate")
	}
	c, err := clientForKeyPEM(ctx, keyPEM, prod, "")
	if err != nil {
		return "", nil, 0, err
	}
	uri = c.AccountURI()

	plans := collapse(names)
	byZone := map[string]*ZonePlan{}
	order := []string{}
	for _, p := range plans {
		base := strings.TrimPrefix(p.host, record.Label+".")
		zone, zerr := publicsuffix.EffectiveTLDPlusOne(base)
		if zerr != nil || zone == "" {
			zone = base
		}
		zp := byZone[zone]
		if zp == nil {
			zp = &ZonePlan{Zone: zone}
			byZone[zone] = zp
			order = append(order, zone)
		}
		for _, wildcard := range p.specs() {
			rec, gerr := record.Generate(record.Params{Domain: base, IssuerDomain: issuer, AccountURI: uri, Wildcard: wildcard})
			if gerr != nil {
				return "", nil, 0, gerr
			}
			pr := PlanRecord{FQDN: rec.FQDN, Value: rec.Value, Covers: p.covers}
			if validate {
				live := recordLive(ctx, rec.FQDN, uri)
				pr.Live = &live
			}
			zp.Records = append(zp.Records, pr)
		}
	}
	sort.Strings(order)
	for _, z := range order {
		zones = append(zones, *byZone[z])
	}
	return uri, zones, len(names), nil
}

// --- certificate SANs + collapse logic ---

func certSANsFromBytes(data []byte) ([]string, error) {
	der := data
	if block, _ := pem.Decode(data); block != nil {
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	seen := map[string]bool{}
	names := []string{}
	add := func(n string) {
		n = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(n, ".")))
		if n != "" && !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	for _, d := range cert.DNSNames {
		add(d)
	}
	add(cert.Subject.CommonName)
	return names, nil
}

type hostPlan struct {
	host     string   // _validation-persist.<base>
	exact    bool     // needs the plain value (covers the base itself)
	wildcard bool     // needs the policy=wildcard value (covers *.base)
	covers   []string // SAN names this host's record(s) account for
}

// specs returns the wildcard flags for the record(s) this host needs (false=plain, true=wildcard).
func (p hostPlan) specs() []bool {
	out := []bool{}
	if p.exact {
		out = append(out, false)
	}
	if p.wildcard {
		out = append(out, true)
	}
	return out
}

// collapse turns a SAN list into the minimal set of record hosts. A wildcard SAN (*.X) yields a
// wildcard record at X and absorbs any explicit single-label child a.X (covered by the wildcard
// cert). Everything else gets its own host.
func collapse(names []string) []hostPlan {
	set := map[string]bool{}
	for _, n := range names {
		set[strings.ToLower(strings.TrimSuffix(n, "."))] = true
	}
	wbase := map[string]bool{}
	for n := range set {
		if strings.HasPrefix(n, "*.") {
			wbase[n[2:]] = true
		}
	}
	plans := map[string]*hostPlan{}
	get := func(base string) *hostPlan {
		p := plans[base]
		if p == nil {
			p = &hostPlan{host: record.Label + "." + base}
			plans[base] = p
		}
		return p
	}
	keys := make([]string, 0, len(set))
	for n := range set {
		keys = append(keys, n)
	}
	sort.Strings(keys)
	for _, n := range keys {
		if strings.HasPrefix(n, "*.") {
			base := n[2:]
			p := get(base)
			p.wildcard = true
			p.covers = append(p.covers, n)
			continue
		}
		parent := parentOf(n)
		if parent != "" && wbase[parent] {
			get(parent).covers = append(get(parent).covers, n+" (via *."+parent+")")
			continue
		}
		p := get(n)
		p.exact = true
		p.covers = append(p.covers, n)
	}
	bases := make([]string, 0, len(plans))
	for b := range plans {
		bases = append(bases, b)
	}
	sort.Strings(bases)
	out := make([]hostPlan, 0, len(bases))
	for _, b := range bases {
		out = append(out, *plans[b])
	}
	return out
}

// parentOf returns the parent domain (first label stripped) only if it still has a dot, so a
// single-label child a.foo.com -> foo.com, but foo.com -> "" (its parent "com" is not a domain).
func parentOf(fqdn string) string {
	i := strings.Index(fqdn, ".")
	if i < 0 {
		return ""
	}
	parent := fqdn[i+1:]
	if !strings.Contains(parent, ".") {
		return ""
	}
	return parent
}
