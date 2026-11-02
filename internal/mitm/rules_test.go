package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
)

var gitReadOnly = []broker.RequestRule{
	{Action: broker.RuleDeny, Query: map[string]string{"service": "git-receive-pack"}},
	{Action: broker.RuleAllow, Methods: []string{"GET", "HEAD"}},
	{Action: broker.RuleAllow, Methods: []string{"POST"}, Path: "/*/git-upload-pack"},
}

// The whole path through the proxy, for both ingresses: a clone reaches the
// upstream, a push never does, and the audit row names the sandbox.
func TestMITMRulesCloneButNotPush(t *testing.T) {
	for _, tc := range []struct {
		name  string
		start func(http.Handler) *httptest.Server
	}{
		{"https", httptest.NewTLSServer},
		{"plain http", httptest.NewServer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reached atomic.Int64
			upstream := tc.start(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached.Add(1)
				_, _ = io.WriteString(w, "from upstream")
			}))
			defer upstream.Close()
			target, _ := url.Parse(upstream.URL)

			sr := validTokenResolver("av_sess_box", &brokercore.ProxyScope{
				VaultID: "v1", VaultName: "sandboxes", VaultRole: "proxy", SessionActor: "box:agent-7",
			})
			cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
				target.Hostname(): {result: &brokercore.InjectResult{MatchedName: "github-git", MatchedHost: target.Hostname(), Rules: gitReadOnly}},
			}}
			sink := &recordingSink{}
			proxyURL, roots, p := setupProxy(t, sr, cp, func(o *Options) { o.LogSink = sink })
			if tc.name == "https" {
				trustUpstream(t, p, upstream)
			}
			client := newTrustingClient(proxyURL, url.UserPassword("av_sess_box", "sandboxes"), roots)

			do := func(method, path string) *http.Response {
				t.Helper()
				var body io.Reader
				if method == http.MethodPost {
					body = strings.NewReader("0000")
				}
				req, err := http.NewRequest(method, upstream.URL+path, body)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("%s %s: %v", method, path, err)
				}
				return resp
			}

			for _, c := range [][2]string{{"GET", "/o/r.git/info/refs?service=git-upload-pack"}, {"POST", "/o/r.git/git-upload-pack"}} {
				resp := do(c[0], c[1])
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("clone %s %s: %d", c[0], c[1], resp.StatusCode)
				}
			}
			if got := reached.Load(); got != 2 {
				t.Fatalf("the upstream saw %d requests of the clone, want 2", got)
			}

			for _, c := range [][2]string{{"GET", "/o/r.git/info/refs?service=git-receive-pack"}, {"POST", "/o/r.git/git-receive-pack"}, {"PUT", "/o/r"}} {
				resp := do(c[0], c[1])
				var body struct {
					Error string `json:"error"`
				}
				_ = json.NewDecoder(resp.Body).Decode(&body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusForbidden || body.Error != "rule_denied" {
					t.Fatalf("push %s %s: %d %q", c[0], c[1], resp.StatusCode, body.Error)
				}
				if resp.Header.Get(brokercore.ProxyErrorHeader) != "true" {
					t.Fatalf("%s %s: the refusal doesn't say it's the proxy's", c[0], c[1])
				}
			}
			if got := reached.Load(); got != 2 {
				t.Fatalf("a refused request reached the upstream: %d requests", got)
			}

			rows := sink.waitForRows(t, 5)
			for _, row := range rows {
				if row.ActorType != brokercore.ActorTypeSession || row.ActorID != "box:agent-7" {
					t.Errorf("%s %s: actor %s/%s", row.Method, row.Path, row.ActorType, row.ActorID)
				}
			}
			denied := 0
			for _, row := range rows {
				if row.ErrorCode == "rule_denied" {
					denied++
					if row.Status != http.StatusForbidden || row.MatchedService != "github-git" {
						t.Errorf("denied row: %+v", row)
					}
				}
			}
			if denied != 3 {
				t.Fatalf("%d denied rows, want 3", denied)
			}
		})
	}
}

func TestMITMRulesMethodOverrideRefused(t *testing.T) {
	var reached atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	sr := validTokenResolver("t", &brokercore.ProxyScope{VaultID: "v", VaultName: "n", SessionActor: "vm:a"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		target.Hostname(): {result: &brokercore.InjectResult{MatchedName: "s", Rules: gitReadOnly}},
	}}
	proxyURL, roots, _ := setupProxy(t, sr, cp)
	client := newTrustingClient(proxyURL, url.User("t"), roots)
	req, _ := http.NewRequest("GET", upstream.URL+"/o/r", nil)
	req.Header.Set("X-HTTP-Method-Override", "DELETE")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || reached.Load() != 0 {
		t.Fatalf("status %d, reached %d", resp.StatusCode, reached.Load())
	}
}

// A refusal doesn't depend on whether the credential resolves.
func TestMITMRulesRefuseBeforeCredentialError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	sr := validTokenResolver("t", &brokercore.ProxyScope{VaultID: "v", VaultName: "n", SessionActor: "vm:a"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{
		target.Hostname(): {result: &brokercore.InjectResult{MatchedName: "s", Rules: gitReadOnly}, err: brokercore.ErrCredentialMissing},
	}}
	proxyURL, roots, _ := setupProxy(t, sr, cp)
	client := newTrustingClient(proxyURL, url.User("t"), roots)
	req, _ := http.NewRequest("POST", upstream.URL+"/o/r.git/git-receive-pack", strings.NewReader("x"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

// A service with no rules is what it was.
func TestMITMNoRulesForwardsAnything(t *testing.T) {
	var reached atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	sr := validTokenResolver("t", &brokercore.ProxyScope{VaultID: "v", VaultName: "n", AgentID: "a"})
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{target.Hostname(): {result: &brokercore.InjectResult{MatchedName: "s"}}}}
	proxyURL, roots, _ := setupProxy(t, sr, cp)
	client := newTrustingClient(proxyURL, url.User("t"), roots)
	req, _ := http.NewRequest("DELETE", upstream.URL+"/o/r", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || reached.Load() != 1 {
		t.Fatalf("status %d, reached %d", resp.StatusCode, reached.Load())
	}
}

// trustUpstream makes the proxy trust a test server's certificate.
func trustUpstream(t *testing.T, p *Proxy, upstream *httptest.Server) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	p.upstream.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
}
