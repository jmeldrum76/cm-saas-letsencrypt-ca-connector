package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"time"
)

//go:embed index.html
var indexHTML []byte

// cmdServe starts the web UI. It binds to localhost by default; private keys are handled in memory
// per request and never written to disk server-side. Front it with TLS + auth if exposed beyond
// localhost (e.g. an internal AWS host).
func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8088", "listen address (localhost-only by default)")
	_ = fs.Parse(args)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})
	mux.HandleFunc("/api/new-account", apiNewAccount)
	mux.HandleFunc("/api/records", apiRecords)
	mux.HandleFunc("/api/email", apiEmail)
	mux.HandleFunc("/api/validate", apiValidate)
	mux.HandleFunc("/api/plan", apiPlan)
	mux.HandleFunc("/api/onboard", apiOnboard)

	fmt.Printf("dnspersist web UI: http://%s\n", *addr)
	fmt.Println("Keys are generated/used in memory only and never stored server-side.")
	fmt.Println("If you expose this beyond localhost, put it behind TLS + authentication.")
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
		return false
	}
	return true
}

func apiNewAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Prod    bool   `json:"prod"`
		Contact string `json:"contact"`
	}
	if !decode(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	pemStr, uri, err := opNewAccount(ctx, req.Prod, req.Contact)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"pem": pemStr, "uri": uri, "value": recordValue(uri)})
}

func apiRecords(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key      string `json:"key"`
		Domains  string `json:"domains"`
		Wildcard bool   `json:"wildcard"`
		Prod     bool   `json:"prod"`
	}
	if !decode(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	uri, recs, err := opRecords(ctx, []byte(req.Key), splitDomains(req.Domains), req.Wildcard, req.Prod)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"uri": uri, "records": recs})
}

func apiEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key      string `json:"key"`
		Domains  string `json:"domains"`
		Wildcard bool   `json:"wildcard"`
		Prod     bool   `json:"prod"`
	}
	if !decode(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	uri, email, err := opEmail(ctx, []byte(req.Key), splitDomains(req.Domains), req.Wildcard, req.Prod)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"uri": uri, "email": email})
}

func apiOnboard(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CMKey  string `json:"cmKey"`
		Name   string `json:"name"`
		Key    string `json:"key"`
		GenKey bool   `json:"genKey"`
		App    bool   `json:"app"`
		Prod   bool   `json:"prod"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.CMKey == "" || req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "CM API key and customer name are required"})
		return
	}
	if req.Key == "" && !req.GenKey {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "paste an account key, or check 'generate a new account key'"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	key, genPEM, genURI := req.Key, "", ""
	if req.GenKey {
		pemStr, uri, err := opNewAccount(ctx, req.Prod, "")
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "generate account: " + err.Error()})
			return
		}
		key, genPEM, genURI = pemStr, pemStr, uri
	}
	res, err := runOnboard(req.CMKey, "", req.Name, key, dirURL(req.Prod), req.App)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	res.GeneratedKeyPEM = genPEM
	res.AccountURI = genURI
	writeJSON(w, http.StatusOK, res)
}

func apiValidate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key     string `json:"key"`
		Domains string `json:"domains"`
		Prod    bool   `json:"prod"`
	}
	if !decode(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	uri, results, err := opValidate(ctx, []byte(req.Key), splitDomains(req.Domains), req.Prod)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"uri": uri, "results": results})
}

func apiPlan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Cert     string `json:"cert"`
		Key      string `json:"key"`
		Prod     bool   `json:"prod"`
		Validate bool   `json:"validate"`
	}
	if !decode(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	uri, zones, sanCount, err := opPlan(ctx, []byte(req.Cert), []byte(req.Key), req.Prod, req.Validate)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"uri": uri, "zones": zones, "sanCount": sanCount})
}
