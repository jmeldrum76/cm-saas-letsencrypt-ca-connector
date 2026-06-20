// Command dnspersist is the onboarding utility for the Let's Encrypt dns-persist-01 CA connector.
// It generates or loads an ACME account, emits the standing _validation-persist records to hand to a
// customer, validates that those records are live in DNS, and turns an existing certificate's SANs
// into a minimal record plan. It reuses the connector's own record + acme packages, so its output is
// exactly what the connector validates and issues against.
//
// The account key (PEM) is the per-customer identity; its account URI is stamped into every record.
// -prod targets Let's Encrypt production (default is staging).
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/acme"
	"github.com/cmsaas-connectors/cm-saas-letsencrypt-ca-connector/internal/record"
	"golang.org/x/net/publicsuffix"
)

const (
	dirStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
	dirProd    = "https://acme-v02.api.letsencrypt.org/directory"
	issuer     = "letsencrypt.org"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "new-account":
		err = cmdNewAccount(os.Args[2:])
	case "records", "add-domains":
		err = cmdRecords(os.Args[2:])
	case "validate":
		err = cmdValidate(os.Args[2:])
	case "plan":
		err = cmdPlan(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `dnspersist — Let's Encrypt dns-persist-01 onboarding utility

Usage:
  dnspersist new-account [-out key.pem] [-contact mailto:you@ex.com] [-prod]
      Generate a NEW account key, register it, print the account URI + record value.

  dnspersist records     -key key.pem -domains a.com,b.com [-wildcard] [-prod]
      Print the standing TXT records to send a customer for those domains.

  dnspersist add-domains -key key.pem -domains c.com [-wildcard] [-prod]
      Alias of records, for adding domains to an EXISTING account (same URI).

  dnspersist validate    -key key.pem -domains a.com,b.com [-prod]
      DNS-check that each domain's standing record is live and bound to this account.

  dnspersist plan        -cert leaf.pem -key key.pem [-validate] [-prod]
      Read an existing certificate's SANs and print the MINIMAL record plan,
      grouped by DNS zone (wildcards collapse covered subdomains).

-prod targets Let's Encrypt production (default: staging).
`)
}

// --- shared helpers ---

func dirURL(prod bool) string {
	if prod {
		return dirProd
	}
	return dirStaging
}

func loadKey(path string) (*acme.AccountKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", path, err)
	}
	return acme.ParseAccountKey(data)
}

// clientForKey builds an ACME client and registers (idempotent) so the account URI resolves.
func clientForKey(ctx context.Context, key *acme.AccountKey, prod bool, contact string) (*acme.Client, error) {
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

// splitDomains parses a comma/space/newline separated list, stripping any leading _validation-persist.
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

func recordValue(uri string) string { return issuer + "; accounturi=" + uri }

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

// --- subcommands ---

func cmdNewAccount(args []string) error {
	fs := flag.NewFlagSet("new-account", flag.ExitOnError)
	out := fs.String("out", "acme-account.pem", "file to write the generated PEM private key")
	contact := fs.String("contact", "", "optional ACME account contact, e.g. mailto:you@example.com")
	prod := fs.Bool("prod", false, "target Let's Encrypt production (default staging)")
	_ = fs.Parse(args)

	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s already exists — refusing to overwrite an existing account key", *out)
	}
	key, err := acme.GenerateAccountKey()
	if err != nil {
		return err
	}
	pemBytes, err := key.PEM()
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, pemBytes, 0o600); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c, err := clientForKey(ctx, key, *prod, *contact)
	if err != nil {
		return err
	}
	uri := c.AccountURI()

	fmt.Printf("Generated ACME account key  -> %s   (KEEP SAFE — back it up; losing it orphans every record)\n", *out)
	fmt.Printf("Directory                   -> %s\n", dirURL(*prod))
	fmt.Printf("Account URI                 -> %s\n", uri)
	fmt.Printf("\nStanding record VALUE (identical for every domain on this account):\n  %s\n", recordValue(uri))
	fmt.Printf("\nNext:  dnspersist records -key %s -domains <customer domains>\n", *out)
	return nil
}

func cmdRecords(args []string) error {
	fs := flag.NewFlagSet("records", flag.ExitOnError)
	keyPath := fs.String("key", "", "account key PEM (required)")
	domains := fs.String("domains", "", "comma/space separated domains (required)")
	wildcard := fs.Bool("wildcard", false, "emit policy=wildcard records (cover *.<domain>)")
	prod := fs.Bool("prod", false, "target production")
	_ = fs.Parse(args)
	if *keyPath == "" || *domains == "" {
		return fmt.Errorf("-key and -domains are required")
	}
	key, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c, err := clientForKey(ctx, key, *prod, "")
	if err != nil {
		return err
	}
	uri := c.AccountURI()

	ds := splitDomains(*domains)
	fmt.Printf("# Account URI: %s\n# Publish these TXT records — one per domain, each in that domain's DNS zone:\n\n", uri)
	for _, d := range ds {
		rec, err := record.Generate(record.Params{Domain: d, IssuerDomain: issuer, AccountURI: uri, Wildcard: *wildcard})
		if err != nil {
			return fmt.Errorf("%s: %w", d, err)
		}
		fmt.Printf("%s.\tIN TXT\t%q\n", rec.FQDN, rec.Value)
	}
	fmt.Printf("\n# When the customer has published them:  dnspersist validate -key %s -domains %s\n", *keyPath, *domains)
	return nil
}

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	keyPath := fs.String("key", "", "account key PEM (required)")
	domains := fs.String("domains", "", "comma/space separated domains (required)")
	prod := fs.Bool("prod", false, "target production")
	_ = fs.Parse(args)
	if *keyPath == "" || *domains == "" {
		return fmt.Errorf("-key and -domains are required")
	}
	key, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c, err := clientForKey(ctx, key, *prod, "")
	if err != nil {
		return err
	}
	uri := c.AccountURI()

	ds := splitDomains(*domains)
	ok := 0
	for _, d := range ds {
		rec, err := record.Generate(record.Params{Domain: d, IssuerDomain: issuer, AccountURI: uri})
		if err != nil {
			fmt.Printf("  x  %s  (invalid: %v)\n", d, err)
			continue
		}
		if recordLive(ctx, rec.FQDN, uri) {
			fmt.Printf("  OK %s\n", d)
			ok++
		} else {
			fmt.Printf("  x  %s  (no live _validation-persist record bound to this account)\n", d)
		}
	}
	fmt.Printf("\n%d of %d domain(s) verified.\n", ok, len(ds))
	if ok != len(ds) {
		return fmt.Errorf("%d domain(s) not yet live", len(ds)-ok)
	}
	return nil
}

func cmdPlan(args []string) error {
	fs := flag.NewFlagSet("plan", flag.ExitOnError)
	certPath := fs.String("cert", "", "existing certificate PEM or DER to read SANs from (required)")
	keyPath := fs.String("key", "", "account key PEM (required, to stamp the account URI)")
	prod := fs.Bool("prod", false, "target production")
	doValidate := fs.Bool("validate", false, "also DNS-check each planned record")
	_ = fs.Parse(args)
	if *certPath == "" || *keyPath == "" {
		return fmt.Errorf("-cert and -key are required")
	}
	names, err := certSANs(*certPath)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return fmt.Errorf("no DNS names found in the certificate")
	}
	key, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c, err := clientForKey(ctx, key, *prod, "")
	if err != nil {
		return err
	}
	uri := c.AccountURI()

	plans := collapse(names)
	// Group by registrable domain (zone).
	zones := map[string][]hostPlan{}
	zoneOrder := []string{}
	for _, p := range plans {
		base := strings.TrimPrefix(p.host, record.Label+".")
		zone, zerr := publicsuffix.EffectiveTLDPlusOne(base)
		if zerr != nil || zone == "" {
			zone = base
		}
		if _, ok := zones[zone]; !ok {
			zoneOrder = append(zoneOrder, zone)
		}
		zones[zone] = append(zones[zone], p)
	}
	sort.Strings(zoneOrder)

	recCount := 0
	for _, p := range plans {
		if p.exact {
			recCount++
		}
		if p.wildcard {
			recCount++
		}
	}
	fmt.Printf("# DNS-persist plan for account %s\n", uri)
	fmt.Printf("# %d SAN(s) -> %d record(s) across %d zone(s)\n\n", len(names), recCount, len(zoneOrder))

	fail := 0
	for _, zone := range zoneOrder {
		fmt.Printf("Zone %s:\n", zone)
		for _, p := range zones[zone] {
			base := strings.TrimPrefix(p.host, record.Label+".")
			specs := []struct {
				wildcard bool
			}{}
			if p.exact {
				specs = append(specs, struct{ wildcard bool }{false})
			}
			if p.wildcard {
				specs = append(specs, struct{ wildcard bool }{true})
			}
			for _, sp := range specs {
				rec, err := record.Generate(record.Params{Domain: base, IssuerDomain: issuer, AccountURI: uri, Wildcard: sp.wildcard})
				if err != nil {
					return err
				}
				status := ""
				if *doValidate {
					if recordLive(ctx, rec.FQDN, uri) {
						status = "   [live]"
					} else {
						status = "   [MISSING]"
						fail++
					}
				}
				fmt.Printf("  %s.\tIN TXT\t%q%s\n", rec.FQDN, rec.Value, status)
			}
			fmt.Printf("      covers: %s\n", strings.Join(p.covers, ", "))
		}
		fmt.Println()
	}
	if *doValidate && fail > 0 {
		return fmt.Errorf("%d planned record(s) not live yet", fail)
	}
	return nil
}

// --- cert SANs + collapse logic ---

func certSANs(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cert %s: %w", path, err)
	}
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
