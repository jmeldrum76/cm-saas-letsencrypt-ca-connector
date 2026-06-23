// Command dnspersist is the onboarding utility for the Let's Encrypt dns-persist-01 CA connector.
// It generates or loads an ACME account, emits the standing _validation-persist records to hand to a
// customer, validates that those records are live in DNS, and turns an existing certificate's SANs
// into a minimal record plan. It runs as a CLI or, via `serve`, as a small self-contained web app.
//
// All operations live in core.go and are shared by the CLI and the web API, so a record this tool
// emits is exactly what the connector validates and issues against.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
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
	case "onboard":
		err = cmdOnboard(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
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
      Read an existing certificate's SANs and print the MINIMAL record plan, by zone.

  dnspersist onboard     -cmkey <CM_API_KEY> -name "Customer" -key key.pem [-app] [-prod]
      Create everything in CM via the API: Connector CA account (sealed key) -> product option
      -> issuing template -> optional application. Makes a validated customer issue-ready.

  dnspersist serve       [-addr 127.0.0.1:8088] [-prod]
      Start the web UI (same operations in a browser). Binds to localhost by default.

-prod targets Let's Encrypt production (default: staging).
`)
}

func ctx60() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 60*time.Second)
}

func cmdNewAccount(args []string) error {
	fs := flag.NewFlagSet("new-account", flag.ExitOnError)
	out := fs.String("out", "acme-account.pem", "file to write the generated PEM private key")
	contact := fs.String("contact", "", "optional ACME account contact, e.g. mailto:you@example.com")
	prod := fs.Bool("prod", false, "target Let's Encrypt production (default staging)")
	_ = fs.Parse(args)

	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s already exists — refusing to overwrite an existing account key", *out)
	}
	ctx, cancel := ctx60()
	defer cancel()
	pemStr, uri, err := opNewAccount(ctx, *prod, *contact)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, []byte(pemStr), 0o600); err != nil {
		return err
	}
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
	emailOut := fs.Bool("email", false, "print a ready-to-send customer email instead of raw records")
	prod := fs.Bool("prod", false, "target production")
	_ = fs.Parse(args)
	if *keyPath == "" || *domains == "" {
		return fmt.Errorf("-key and -domains are required")
	}
	keyPEM, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	ctx, cancel := ctx60()
	defer cancel()
	if *emailOut {
		_, body, err := opEmail(ctx, keyPEM, splitDomains(*domains), *wildcard, *prod)
		if err != nil {
			return err
		}
		fmt.Print(body)
		return nil
	}
	uri, recs, err := opRecords(ctx, keyPEM, splitDomains(*domains), *wildcard, *prod)
	if err != nil {
		return err
	}
	fmt.Printf("# Account URI: %s\n# Publish these TXT records — one per domain, each in that domain's DNS zone:\n\n", uri)
	for _, r := range recs {
		fmt.Printf("%s.\tIN TXT\t%q\n", r.FQDN, r.Value)
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
	keyPEM, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	ctx, cancel := ctx60()
	defer cancel()
	_, results, err := opValidate(ctx, keyPEM, splitDomains(*domains), *prod)
	if err != nil {
		return err
	}
	ok := 0
	for _, r := range results {
		if r.Live {
			fmt.Printf("  OK %s\n", r.Domain)
			ok++
		} else {
			fmt.Printf("  x  %s  (no live _validation-persist record bound to this account)\n", r.Domain)
		}
	}
	fmt.Printf("\n%d of %d domain(s) verified.\n", ok, len(results))
	if ok != len(results) {
		return fmt.Errorf("%d domain(s) not yet live", len(results)-ok)
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
	certData, err := os.ReadFile(*certPath)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	ctx, cancel := ctx60()
	defer cancel()
	uri, zones, sanCount, err := opPlan(ctx, certData, keyPEM, *prod, *doValidate)
	if err != nil {
		return err
	}
	recCount := 0
	for _, z := range zones {
		recCount += len(z.Records)
	}
	fmt.Printf("# DNS-persist plan for account %s\n", uri)
	fmt.Printf("# %d SAN(s) -> %d record(s) across %d zone(s)\n\n", sanCount, recCount, len(zones))
	fail := 0
	for _, z := range zones {
		fmt.Printf("Zone %s:\n", z.Zone)
		for _, r := range z.Records {
			status := ""
			if r.Live != nil {
				if *r.Live {
					status = "   [live]"
				} else {
					status = "   [MISSING]"
					fail++
				}
			}
			fmt.Printf("  %s.\tIN TXT\t%q%s\n", r.FQDN, r.Value, status)
			fmt.Printf("      covers: %s\n", strings.Join(r.Covers, ", "))
		}
		fmt.Println()
	}
	if *doValidate && fail > 0 {
		return fmt.Errorf("%d planned record(s) not live yet", fail)
	}
	return nil
}

func cmdOnboard(args []string) error {
	fs := flag.NewFlagSet("onboard", flag.ExitOnError)
	cmKey := fs.String("cmkey", "", "CM API key (required)")
	name := fs.String("name", "", "base name for the CA / template / application (required)")
	keyPath := fs.String("key", "", "ACME account key PEM (omit with -genkey)")
	genKey := fs.Bool("genkey", false, "generate a new Let's Encrypt account key instead of providing one")
	out := fs.String("out", "", "where to write a generated key (default <name>-acct.pem)")
	domains := fs.String("domains", "", "scope the template's CN/SAN regex to these domains (comma/space separated); default any")
	plugin := fs.String("plugin", "", "connector plugin id (default: the dns-persist connector)")
	app := fs.Bool("app", false, "also create an application with the template assigned")
	prod := fs.Bool("prod", false, "target production directory")
	_ = fs.Parse(args)
	if *cmKey == "" || *name == "" {
		return fmt.Errorf("-cmkey and -name are required")
	}
	if *keyPath == "" && !*genKey {
		return fmt.Errorf("provide -key <pem> or -genkey to generate one")
	}
	var accountKeyPEM string
	if *genKey {
		ctx, cancel := ctx60()
		pemStr, uri, gerr := opNewAccount(ctx, *prod, "")
		cancel()
		if gerr != nil {
			return fmt.Errorf("generate Let's Encrypt account: %w", gerr)
		}
		accountKeyPEM = pemStr
		dest := *out
		if dest == "" {
			dest = strings.ReplaceAll(*name, " ", "-") + "-acct.pem"
		}
		if err := os.WriteFile(dest, []byte(pemStr), 0o600); err != nil {
			return err
		}
		fmt.Printf("Generated Let's Encrypt account key -> %s   (URI %s)   KEEP SAFE — back it up.\n\n", dest, uri)
	} else {
		b, err := os.ReadFile(*keyPath)
		if err != nil {
			return err
		}
		accountKeyPEM = string(b)
	}
	r, err := runOnboard(*cmKey, *plugin, *name, accountKeyPEM, dirURL(*prod), splitDomains(*domains), *app)
	if err != nil {
		return err
	}
	fmt.Printf("CA account        %s   (%s)\n", *name, r.CAID)
	fmt.Printf("product option    %s\n", r.ProductOptionID)
	fmt.Printf("issuing template  %s   (%s)\n", r.TemplateName, r.TemplateID)
	if r.AppID != "" {
		fmt.Printf("application       %s   (%s)\n", r.AppName, r.AppID)
	}
	fmt.Println("\nReady to issue — the CA and template are now selectable in CM.")
	return nil
}
