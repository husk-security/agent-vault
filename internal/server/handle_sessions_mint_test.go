package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

// proxyAgentToken makes an instance-level agent with only `proxy` on the vaults named.
func proxyAgentToken(t *testing.T, ms *mockStore, name string, vaultIDs ...string) string {
	t.Helper()
	id := name + "-id"
	ms.agents[name] = &store.Agent{ID: id, Name: name, Role: "no-access", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	sess := &store.Session{ID: name + "-token", AgentID: id, ExpiresAt: tp(time.Now().Add(time.Hour)), CreatedAt: time.Now()}
	ms.sessions[sess.ID] = sess
	for _, v := range vaultIDs {
		ms.GrantVaultRole(context.Background(), id, "agent", v, "proxy")
	}
	return sess.ID
}

func call(t *testing.T, srv *Server, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	return rec
}

func TestProxyAgentMintsAndRevokesItsOwn(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))
	token := proxyAgentToken(t, ms, "harness", "root-ns-id")

	rec := call(t, srv, http.MethodPost, "/v1/sessions", token, `{"vault":"default","label":"box:agent-7","ttl_seconds":600}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("mint: %d %s", rec.Code, rec.Body.String())
	}
	var resp scopedSessionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.ID == "" || resp.Token == "" {
		t.Fatalf("mint answered %+v", resp)
	}
	child := ms.sessions[resp.Token]
	if child == nil || child.Label != "box:agent-7" || child.VaultRole != "proxy" || child.CreatedByActorID != "harness-id" || child.CreatedByActorType != "agent" {
		t.Fatalf("child: %+v", child)
	}

	// A label is what names it in the audit log.
	if rec := call(t, srv, http.MethodPost, "/v1/sessions", token, `{"vault":"default"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("no label: %d", rec.Code)
	}

	// Another agent with the same grant can't end it.
	other := proxyAgentToken(t, ms, "other-agent", "root-ns-id")
	if rec := call(t, srv, http.MethodDelete, "/v1/sessions/"+resp.ID+"?vault=default", other, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("other agent's revoke: %d", rec.Code)
	}
	if ms.sessions[resp.Token] == nil {
		t.Fatal("another agent revoked it")
	}

	if rec := call(t, srv, http.MethodDelete, "/v1/sessions/"+resp.ID+"?vault=default", token, ""); rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
	}
	if ms.sessions[resp.Token] != nil {
		t.Fatal("still there after revoke")
	}
}

// What's minted stays worth less than what minted it.
func TestMintedSessionCannotMint(t *testing.T) {
	ms, token := setupMockStoreWithScopedSession(t, "default", "root-ns-id")
	srv := newTestServer(withStore(ms))
	if rec := call(t, srv, http.MethodPost, "/v1/sessions", token, `{"vault":"default","label":"x"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("a scoped session minted: %d", rec.Code)
	}
}

func TestProxyAgentHasNoSayOnOtherVaults(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	ms.vaults["elsewhere"] = &store.Vault{ID: "elsewhere-id", Name: "elsewhere"}
	srv := newTestServer(withStore(ms))
	token := proxyAgentToken(t, ms, "harness", "root-ns-id")
	if rec := call(t, srv, http.MethodPost, "/v1/sessions", token, `{"vault":"elsewhere","label":"x"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("mint on a vault with no grant: %d", rec.Code)
	}
}

// Minting doesn't reach anything else a member can do.
func TestProxyAgentStillCannotManage(t *testing.T) {
	ms, _ := setupMockStoreWithSession(t)
	srv := newTestServer(withStore(ms))
	token := proxyAgentToken(t, ms, "harness", "root-ns-id")
	for _, c := range [][3]string{
		{http.MethodGet, "/v1/sessions?vault=default", ""},
		{http.MethodGet, "/v1/vaults/default/logs", ""},
		{http.MethodPost, "/v1/credentials", `{"vault":"default","credentials":{"X":"y"}}`},
		{http.MethodGet, "/v1/credentials?vault=default&reveal=true&key=X", ""},
		{http.MethodPut, "/v1/vaults/default/services", `{"services":[]}`},
	} {
		if rec := call(t, srv, c[0], c[1], token, c[2]); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s: %d", c[0], c[1], rec.Code)
		}
	}
}

func TestLogsShowSessionLabelAsName(t *testing.T) {
	name := actorName(map[string]string{}, store.RequestLog{ActorType: "session", ActorID: "vm:agent-3"})
	if name != "vm:agent-3" {
		t.Fatalf("name %q", name)
	}
	agent := actorName(map[string]string{"agent:id": "harness"}, store.RequestLog{ActorType: "agent", ActorID: "id"})
	if agent != "harness" {
		t.Fatalf("name %q", agent)
	}
}
