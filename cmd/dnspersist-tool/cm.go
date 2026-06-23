package main

// CM (CyberArk Certificate Manager / Venafi Cloud) onboarding client. This lets the utility do
// everything the CM UI wizard does — create the Connector CA account, register its product option
// (which the UI does NOT do for connectors), create the issuing template, and optionally an
// application — so a validated customer can be made issue-ready in one step. The utility is
// operator-run, so it legitimately uses the operator's CM API key (unlike the connector, which must
// never hold one). Endpoints/payloads mirror the proven scripts (register-ca-account.py, cm-issue.sh).

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/box"
)

const (
	cmBase          = "https://api.venafi.cloud"
	defaultPluginID = "37ec5f37-6b75-11f1-9ea5-20c33ba661e3"
	cmProductName   = "Let's Encrypt (dns-persist-01)"
)

type cmClient struct {
	key      string
	pluginID string
	http     *http.Client
}

func newCMClient(key, pluginID string) *cmClient {
	if pluginID == "" {
		pluginID = defaultPluginID
	}
	return &cmClient{key: key, pluginID: pluginID, http: &http.Client{Timeout: 40 * time.Second}}
}

func (c *cmClient) do(method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, cmBase+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("tppl-api-key", c.key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("CM %s %s -> HTTP %d: %s", method, path, resp.StatusCode, truncate(string(data), 400))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// sealBox implements libsodium crypto_box_seal (anonymous SealedBox): an ephemeral keypair, a
// blake2b(ephPub||recipientPub) nonce, then crypto_box, with the ephemeral public key prepended.
// CM's edge unseals it with the matching secret key. Matches pynacl SealedBox used by the scripts.
func sealBox(message []byte, recipientPubB64 string) (string, error) {
	rpkBytes, err := base64.StdEncoding.DecodeString(recipientPubB64)
	if err != nil || len(rpkBytes) != 32 {
		return "", fmt.Errorf("invalid recipient public key (want 32 bytes base64): %v", err)
	}
	var rpk [32]byte
	copy(rpk[:], rpkBytes)
	epk, esk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	h, err := blake2b.New(24, nil)
	if err != nil {
		return "", err
	}
	h.Write(epk[:])
	h.Write(rpk[:])
	var nonce [24]byte
	copy(nonce[:], h.Sum(nil))
	sealed := box.Seal(epk[:], message, &nonce, &rpk, esk) // ephemeral_pk || box
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// --- CM resource shapes (only the fields we read) ---

type caAccountsResp struct {
	Accounts []struct {
		Account struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		} `json:"account"`
		ProductOptions []struct {
			ID string `json:"id"`
		} `json:"productOptions"`
	} `json:"accounts"`
}

func (c *cmClient) edgeInfo() (edgeID, dekID, pub string, err error) {
	var er struct {
		EdgeInstances []struct {
			ID              string `json:"id"`
			EncryptionKeyID string `json:"encryptionKeyId"`
		} `json:"edgeInstances"`
	}
	if err = c.do("GET", "/v1/edgeinstances", nil, &er); err != nil {
		return
	}
	idx := -1
	for i := range er.EdgeInstances {
		if er.EdgeInstances[i].EncryptionKeyID != "" {
			idx = i
			break
		}
	}
	if idx < 0 {
		if len(er.EdgeInstances) == 0 {
			return "", "", "", fmt.Errorf("no edge instances (vSatellite) found")
		}
		idx = 0
	}
	edgeID, dekID = er.EdgeInstances[idx].ID, er.EdgeInstances[idx].EncryptionKeyID
	var kr struct {
		Key string `json:"key"`
	}
	if err = c.do("GET", "/v1/edgeencryptionkeys/"+dekID, nil, &kr); err != nil {
		return
	}
	return edgeID, dekID, kr.Key, nil
}

func (c *cmClient) teamID() (string, error) {
	var tr struct {
		Teams []struct {
			ID string `json:"id"`
		} `json:"teams"`
	}
	if err := c.do("GET", "/v1/teams", nil, &tr); err != nil {
		return "", err
	}
	if len(tr.Teams) == 0 {
		return "", fmt.Errorf("no teams found to own the application")
	}
	return tr.Teams[0].ID, nil
}

// findAccount returns the CA account id and its product-option count for a CA name (key).
func (c *cmClient) findAccount(name string) (id string, productOptions int, err error) {
	var ar caAccountsResp
	if err = c.do("GET", "/v1/certificateauthorities/CONNECTOR/accounts", nil, &ar); err != nil {
		return
	}
	for _, a := range ar.Accounts {
		if a.Account.Key == name {
			return a.Account.ID, len(a.ProductOptions), nil
		}
	}
	return "", 0, nil
}

// createCA creates a CONNECTOR CA account with the account key SEALED for the edge. Returns its id.
func (c *cmClient) createCA(name, accountKeyPEM, directoryURL string, prod bool) (string, error) {
	if id, _, _ := c.findAccount(name); id != "" {
		return id, nil // idempotent: reuse an existing CA of the same name
	}
	edgeID, dekID, pub, err := c.edgeInfo()
	if err != nil {
		return "", err
	}
	sealed, err := sealBox([]byte(accountKeyPEM), pub)
	if err != nil {
		return "", err
	}
	payload := map[string]any{
		"pluginId":       c.pluginID,
		"key":            name,
		"dekId":          dekID,
		"edgeInstanceId": edgeID,
		"caAccountConfiguration": map[string]any{
			"certificateAuthority": "CONNECTOR",
			"configuration":        map[string]any{"directoryUrl": directoryURL, "dnsProvider": "none"},
		},
		"credentials": map[string]any{
			"certificateAuthority": "CONNECTOR",
			"credentials":          map[string]any{"accountKey": sealed},
		},
	}
	if err := c.do("POST", "/v1/certificateauthorities/CONNECTOR/accounts", payload, nil); err != nil {
		return "", err
	}
	id, _, err := c.findAccount(name)
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", fmt.Errorf("CA account %q was not found after creation", name)
	}
	return id, nil
}

// accountProductOptionID returns the id of an account's first registered product option, or "".
func (c *cmClient) accountProductOptionID(accountID string) (string, error) {
	var ar caAccountsResp
	if err := c.do("GET", "/v1/certificateauthorities/CONNECTOR/accounts", nil, &ar); err != nil {
		return "", err
	}
	for _, a := range ar.Accounts {
		if a.Account.ID == accountID && len(a.ProductOptions) > 0 {
			return a.ProductOptions[0].ID, nil
		}
	}
	return "", nil
}

// registerProduct registers the product option (the step CM's UI skips for connectors). Idempotent.
func (c *cmClient) registerProduct(accountID string) (string, error) {
	if id, _ := c.accountProductOptionID(accountID); id != "" {
		return id, nil
	}
	body := map[string]any{"caProduct": map[string]any{"certificateAuthority": "CONNECTOR", "productName": cmProductName}}
	var out struct {
		ID string `json:"id"`
	}
	if err := c.do("POST", "/v1/certificateauthorities/CONNECTOR/accounts/"+accountID+"/productoptions", body, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// templateIDByName returns the id of an issuing template with the given name, or "".
func (c *cmClient) templateIDByName(name string) (string, error) {
	var tr struct {
		CertificateIssuingTemplates []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"certificateIssuingTemplates"`
	}
	if err := c.do("GET", "/v1/certificateissuingtemplates", nil, &tr); err != nil {
		return "", err
	}
	for _, t := range tr.CertificateIssuingTemplates {
		if t.Name == name {
			return t.ID, nil
		}
	}
	return "", nil
}

// createTemplate creates an issuing template bound to the product option. Returns the template id.
// Idempotent: reuses an existing template of the same name.
func (c *cmClient) createTemplate(name, productOptionID string) (string, error) {
	if id, _ := c.templateIDByName(name); id != "" {
		return id, nil
	}
	body := map[string]any{
		"name":                                name,
		"certificateAuthority":                "CONNECTOR",
		"certificateAuthorityProductOptionId": productOptionID,
		"product":                             map[string]any{"certificateAuthority": "CONNECTOR", "productName": cmProductName, "validityPeriod": "P90D"},
		"keyTypes":                            []map[string]any{{"keyType": "RSA", "keyLengths": []int{2048, 3072, 4096}}},
		"keyReuse":                            false,
		"csrUploadAllowed":                    true,
		"keyGeneratedByVenafiAllowed":         true,
		"subjectCNRegexes":                    []string{".*"},
		"subjectORegexes":                     []string{".*"},
		"subjectOURegexes":                    []string{".*"},
		"subjectLRegexes":                     []string{".*"},
		"subjectSTRegexes":                    []string{".*"},
		"subjectCValues":                      []string{".*"},
		"sanRegexes":                          []string{".*"},
	}
	if err := c.do("POST", "/v1/certificateissuingtemplates", body, nil); err != nil {
		return "", err
	}
	id, err := c.templateIDByName(name)
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", fmt.Errorf("issuing template %q not found after creation", name)
	}
	return id, nil
}

// createApplication creates an application and assigns the issuing template to it. Returns its id.
func (c *cmClient) createApplication(name, templateName, templateID string) (string, error) {
	team, err := c.teamID()
	if err != nil {
		return "", err
	}
	body := map[string]any{
		"name":                                 name,
		"ownerIdsAndTypes":                     []map[string]any{{"ownerId": team, "ownerType": "TEAM"}},
		"certificateIssuingTemplateAliasIdMap": map[string]string{templateName: templateID},
	}
	var out struct {
		Applications []struct {
			ID string `json:"id"`
		} `json:"applications"`
		ID string `json:"id"`
	}
	if err := c.do("POST", "/outagedetection/v1/applications", body, &out); err != nil {
		return "", err
	}
	if len(out.Applications) > 0 {
		return out.Applications[0].ID, nil
	}
	return out.ID, nil
}

// onboardResult is the structured outcome of a full onboard (shared by the CLI and web API).
type onboardResult struct {
	CAID            string `json:"caId"`
	ProductOptionID string `json:"productOptionId"`
	TemplateName    string `json:"templateName"`
	TemplateID      string `json:"templateId"`
	AppName         string `json:"appName,omitempty"`
	AppID           string `json:"appId,omitempty"`
	// Set only when the account key was generated by this onboard (so the operator can save it).
	GeneratedKeyPEM string `json:"generatedKeyPem,omitempty"`
	AccountURI      string `json:"accountUri,omitempty"`
}

// runOnboard does the full CM onboarding for a validated customer: create CA account (sealed key) ->
// register product option -> create issuing template -> optionally create an application. Every step
// is idempotent, so re-running with the same name is safe. directoryURL selects staging/production.
func runOnboard(cmKey, pluginID, name, accountKeyPEM, directoryURL string, createApp bool) (*onboardResult, error) {
	c := newCMClient(cmKey, pluginID)
	r := &onboardResult{}
	var err error
	if r.CAID, err = c.createCA(name, accountKeyPEM, directoryURL, false); err != nil {
		return nil, fmt.Errorf("create CA account: %w", err)
	}
	if r.ProductOptionID, err = c.registerProduct(r.CAID); err != nil {
		return nil, fmt.Errorf("register product option: %w", err)
	}
	r.TemplateName = name + " template"
	if r.TemplateID, err = c.createTemplate(r.TemplateName, r.ProductOptionID); err != nil {
		return nil, fmt.Errorf("create issuing template: %w", err)
	}
	if createApp {
		r.AppName = name + " app"
		if r.AppID, err = c.createApplication(r.AppName, r.TemplateName, r.TemplateID); err != nil {
			return nil, fmt.Errorf("create application: %w", err)
		}
	}
	return r, nil
}
