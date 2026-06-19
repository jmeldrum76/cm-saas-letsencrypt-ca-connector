// Package route53 is the AWS Route 53 implementation of publisher.Publisher. It is the first
// auto-mode adapter; the same Publisher shape supports Azure / Cloudflare / GCP / F5 later.
// Credentials come from the standard AWS chain (static keys from the manifest, or SSO for dev)
// via config.LoadDefaultConfig.
package route53

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
)

const recordTTL = 60

// Publisher publishes standing records to AWS Route 53.
type Publisher struct {
	client *route53.Client
}

// New builds a Route 53 publisher from the default AWS config chain (env vars, shared config /
// SSO profile, etc.). optFns can inject a profile or static credentials.
func New(ctx context.Context, optFns ...func(*config.LoadOptions) error) (*Publisher, error) {
	cfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return nil, fmt.Errorf("route53: load aws config: %w", err)
	}
	return &Publisher{client: route53.NewFromConfig(cfg)}, nil
}

// NewWithStaticKeys builds a publisher from explicit access key / secret (the manifest path).
func NewWithStaticKeys(ctx context.Context, accessKeyID, secretAccessKey, region string) (*Publisher, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")),
	}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	return New(ctx, opts...)
}

// NewWithClient injects a Route 53 client (tests).
func NewWithClient(client *route53.Client) *Publisher { return &Publisher{client: client} }

// EnsureRecord publishes rdata at fqdn only if not already present, preserving other values.
func (p *Publisher) EnsureRecord(ctx context.Context, zoneID, fqdn, rdata string) error {
	name := ensureDot(fqdn)
	want := quoteTXT(rdata)

	existing, err := p.existingTXT(ctx, zoneID, name)
	if err != nil {
		return err
	}
	values := make([]r53types.ResourceRecord, 0, len(existing)+1)
	for _, rr := range existing {
		if aws.ToString(rr.Value) == want {
			return nil // already present — idempotent no-op (JIT will validate)
		}
		values = append(values, rr)
	}
	values = append(values, r53types.ResourceRecord{Value: aws.String(want)})
	changeID, err := p.change(ctx, zoneID, name, values, r53types.ChangeActionUpsert)
	if err != nil {
		return err
	}
	return p.waitForSync(ctx, changeID)
}

// DeleteRecord removes rdata from fqdn, leaving any other values intact.
func (p *Publisher) DeleteRecord(ctx context.Context, zoneID, fqdn, rdata string) error {
	name := ensureDot(fqdn)
	want := quoteTXT(rdata)

	existing, err := p.existingTXT(ctx, zoneID, name)
	if err != nil {
		return err
	}
	if len(existing) == 0 {
		return nil
	}
	remaining := make([]r53types.ResourceRecord, 0, len(existing))
	found := false
	for _, rr := range existing {
		if aws.ToString(rr.Value) == want {
			found = true
			continue
		}
		remaining = append(remaining, rr)
	}
	if !found {
		return nil
	}
	if len(remaining) == 0 {
		_, err = p.change(ctx, zoneID, name, existing, r53types.ChangeActionDelete)
		return err
	}
	_, err = p.change(ctx, zoneID, name, remaining, r53types.ChangeActionUpsert)
	return err
}

// Validate performs a read-only check that the credentials can reach the hosted zone.
func (p *Publisher) Validate(ctx context.Context, zoneID string) error {
	_, err := p.client.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		MaxItems:     aws.Int32(1),
	})
	if err != nil {
		return fmt.Errorf("route53: validate hosted zone %s: %w", zoneID, err)
	}
	return nil
}

// existingTXT returns the TXT resource records at name, or nil if the record set is absent.
func (p *Publisher) existingTXT(ctx context.Context, zoneID, name string) ([]r53types.ResourceRecord, error) {
	out, err := p.client.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(zoneID),
		StartRecordName: aws.String(name),
		StartRecordType: r53types.RRTypeTxt,
		MaxItems:        aws.Int32(1),
	})
	if err != nil {
		return nil, fmt.Errorf("route53: list records: %w", err)
	}
	for i := range out.ResourceRecordSets {
		rrs := out.ResourceRecordSets[i]
		if rrs.Type == r53types.RRTypeTxt && strings.EqualFold(aws.ToString(rrs.Name), name) {
			return rrs.ResourceRecords, nil
		}
	}
	return nil, nil
}

func (p *Publisher) change(ctx context.Context, zoneID, name string, values []r53types.ResourceRecord, action r53types.ChangeAction) (string, error) {
	out, err := p.client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch: &r53types.ChangeBatch{
			Changes: []r53types.Change{{
				Action: action,
				ResourceRecordSet: &r53types.ResourceRecordSet{
					Name:            aws.String(name),
					Type:            r53types.RRTypeTxt,
					TTL:             aws.Int64(recordTTL),
					ResourceRecords: values,
				},
			}},
		},
	})
	if err != nil {
		return "", fmt.Errorf("route53: change %s %s: %w", action, name, err)
	}
	if out.ChangeInfo == nil {
		return "", nil
	}
	return aws.ToString(out.ChangeInfo.Id), nil
}

// waitForSync blocks until a Route 53 change reaches INSYNC (propagated to all of the zone's
// authoritative servers), so the standing record is live on the servers Let's Encrypt queries
// before issuance proceeds. This is network-independent — it polls the Route 53 API, not DNS.
func (p *Publisher) waitForSync(ctx context.Context, changeID string) error {
	changeID = strings.TrimPrefix(changeID, "/change/")
	if changeID == "" {
		return nil
	}
	deadline := time.Now().Add(2 * time.Minute)
	for {
		out, err := p.client.GetChange(ctx, &route53.GetChangeInput{Id: aws.String(changeID)})
		if err != nil {
			return fmt.Errorf("route53: get change %s: %w", changeID, err)
		}
		if out.ChangeInfo != nil && out.ChangeInfo.Status == r53types.ChangeStatusInsync {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("route53: change %s did not reach INSYNC within timeout", changeID)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

// quoteTXT wraps an rdata string as a single DNS character-string (TXT values are quoted).
func quoteTXT(rdata string) string {
	return `"` + strings.ReplaceAll(rdata, `"`, `\"`) + `"`
}

func ensureDot(fqdn string) string {
	if strings.HasSuffix(fqdn, ".") {
		return fqdn
	}
	return fqdn + "."
}
