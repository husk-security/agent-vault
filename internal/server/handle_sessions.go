package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Infisical/agent-vault/internal/store"
)

type scopedSessionRequest struct {
	Vault      string `json:"vault"`
	VaultRole  string `json:"vault_role"`
	TTLSeconds *int   `json:"ttl_seconds,omitempty"`
	Label      string `json:"label,omitempty"`
}

type scopedSessionResponse struct {
	ID        string `json:"id"` // what DELETE /v1/sessions/{id} takes
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	AVAddr    string `json:"av_addr,omitempty"`
}

// scopedSessionView is the JSON projection returned by GET /v1/sessions.
// The raw token is intentionally absent — it is shown only at creation
// time and never re-readable. Rows are referenced by `id` (the public_id).
type scopedSessionView struct {
	ID        string                  `json:"id"`
	Label     string                  `json:"label,omitempty"`
	VaultRole string                  `json:"vault_role"`
	CreatedBy *scopedSessionActorView `json:"created_by,omitempty"`
	CreatedAt string                  `json:"created_at"`
	ExpiresAt string                  `json:"expires_at,omitempty"`
}

type scopedSessionActorView struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	DisplayName string `json:"display_name"`
}

// maxScopedSessionLabel caps the label length stored on a scoped session.
// Labels are user-supplied free-form text shown in the Tokens UI, so we
// keep them short to avoid table layout issues.
const maxScopedSessionLabel = 100

// sanitizeScopedSessionLabel trims surrounding whitespace and strips
// ASCII control characters. Mirrors truncateDeviceLabel's policy for
// user-session device labels, except it does not silently truncate —
// the caller checks rune count and rejects with 400.
func sanitizeScopedSessionLabel(label string) string {
	label = strings.TrimSpace(label)
	if label == "" {
		return ""
	}
	cleaned := make([]rune, 0, len(label))
	for _, r := range label {
		if r < 0x20 || r == 0x7f {
			continue
		}
		cleaned = append(cleaned, r)
	}
	return string(cleaned)
}

func (s *Server) handleScopedSession(w http.ResponseWriter, r *http.Request) {
	var req scopedSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Vault == "" {
		jsonError(w, http.StatusBadRequest, "Vault is required")
		return
	}

	// Tokens are minted with role `proxy` only; minting at member/admin
	// is intentionally not exposed via this endpoint right now. The
	// member+ floor on the caller is enforced by requireVaultMember
	// below for users/agents and scoped sessions alike.
	if req.VaultRole != "" && req.VaultRole != "proxy" {
		jsonError(w, http.StatusBadRequest, "vault_role must be 'proxy'")
		return
	}

	// Validate TTL bounds if provided.
	if req.TTLSeconds != nil {
		ttl := time.Duration(*req.TTLSeconds) * time.Second
		if ttl < scopedSessionMinTTL || ttl > scopedSessionMaxTTL {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf(
				"ttl_seconds must be between %d and %d",
				int(scopedSessionMinTTL.Seconds()), int(scopedSessionMaxTTL.Seconds()),
			))
			return
		}
	}

	// Trim and strip control chars before length-checking. Control chars
	// (\n, \t, etc.) would break the Tokens table layout — the same
	// concern truncateDeviceLabel addresses for user-session device
	// labels. Length is measured in runes, not bytes, so a CJK or emoji
	// label that fits the frontend's maxLength={100} also passes here.
	req.Label = sanitizeScopedSessionLabel(req.Label)
	if utf8.RuneCountInString(req.Label) > maxScopedSessionLabel {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf(
			"label must be at most %d characters", maxScopedSessionLabel,
		))
		return
	}

	ctx := r.Context()

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", req.Vault))
		return
	}

	// Caller must be at least a vault `member`, or an agent token at `proxy`
	// (see requireSessionMinter). A proxy-role user or a scoped session can
	// ONLY proxy requests through Agent Vault: no new tokens, even at proxy role.
	proxyAgent, err := s.requireSessionMinter(w, r, ns.ID)
	if err != nil {
		return
	}
	// What a proxy agent mints stands in for it in the audit log, so it has to say who for.
	if proxyAgent != nil && req.Label == "" {
		jsonError(w, http.StatusBadRequest, "label is required")
		return
	}
	parentSess := sessionFromContext(ctx)

	// vault_role is locked to "proxy" by the validator above, and any
	// member+ caller trivially satisfies that, so no role-cap check is
	// needed here. If non-proxy minting is ever re-enabled, restore
	// capRequestedRole (or equivalent) to gate role escalation.
	cappedRole := "proxy"

	// Compute expiry: use ttl_seconds if provided, otherwise default 24h.
	var expiresAt *time.Time
	if req.TTLSeconds != nil {
		t := time.Now().Add(time.Duration(*req.TTLSeconds) * time.Second)
		expiresAt = &t
	} else {
		t := time.Now().Add(scopedSessionDefaultTTL)
		expiresAt = &t
	}

	// Resolve the calling actor so the Tokens UI can show "minted by X".
	// A nil actor here means the caller is itself a vault-scoped session
	// (e.g. an agent token or a previously-minted scoped token); we leave
	// the created_by fields blank in that case rather than failing the mint.
	var createdByID, createdByType string
	if actor, err := s.actorFromSession(ctx, parentSess); err == nil && actor != nil {
		createdByID = actor.ID
		createdByType = actor.Type
	}

	sess, err := s.store.CreateScopedSession(ctx, store.CreateScopedSessionParams{
		VaultID:            ns.ID,
		VaultRole:          cappedRole,
		ExpiresAt:          expiresAt,
		Label:              req.Label,
		CreatedByActorID:   createdByID,
		CreatedByActorType: createdByType,
	})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create scoped session")
		return
	}

	jsonOK(w, scopedSessionResponse{
		ID:        sess.PublicID,
		Token:     sess.ID,
		ExpiresAt: formatExpiresAt(sess.ExpiresAt),
		AVAddr:    s.baseURL,
	})
}

// handleListScopedSessions returns the active vault-scoped tokens for a
// vault, sorted most recent first. Requires vault `member` or higher: the
// list view exposes the email/name of whoever minted each token via
// created_by.display_name, which is more identifying than what a
// proxy-only caller should see.
// The raw token is never returned — rows are referenced by public_id.
func (s *Server) handleListScopedSessions(w http.ResponseWriter, r *http.Request) {
	vaultName := r.URL.Query().Get("vault")
	if vaultName == "" {
		jsonError(w, http.StatusBadRequest, "vault is required")
		return
	}

	ctx := r.Context()
	ns, err := s.store.GetVault(ctx, vaultName)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", vaultName))
		return
	}

	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}

	rows, err := s.store.ListScopedSessionsByVault(ctx, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list scoped sessions")
		return
	}

	displayNames := make(map[string]string, len(rows))
	out := make([]scopedSessionView, 0, len(rows))
	for _, sess := range rows {
		view := scopedSessionView{
			ID:        sess.PublicID,
			Label:     sess.Label,
			VaultRole: sess.VaultRole,
			CreatedAt: formatExpiresAt(&sess.CreatedAt),
			ExpiresAt: formatExpiresAt(sess.ExpiresAt),
		}
		if sess.CreatedByActorID != "" && sess.CreatedByActorType != "" {
			cacheKey := sess.CreatedByActorType + ":" + sess.CreatedByActorID
			displayName, ok := displayNames[cacheKey]
			if !ok {
				if actor, err := s.actorByID(ctx, sess.CreatedByActorID, sess.CreatedByActorType); err == nil {
					displayName = actor.DisplayLabel()
				} else {
					displayName = sess.CreatedByActorID
				}
				displayNames[cacheKey] = displayName
			}
			view.CreatedBy = &scopedSessionActorView{
				ID:          sess.CreatedByActorID,
				Type:        sess.CreatedByActorType,
				DisplayName: displayName,
			}
		}
		out = append(out, view)
	}
	jsonOK(w, map[string]interface{}{"sessions": out})
}

// requireSessionMinter lets an instance-level agent token with only `proxy` on
// the vault mint and revoke scoped sessions, and otherwise asks for `member` as
// upstream does. This is what per-sandbox identity needs: the harness can hand
// each sandbox its own short-lived, revocable, labelled token without being able
// to read or change the vault's credentials, which `member` would allow. It gives
// nothing the agent doesn't have, since a child can only do what the agent's own
// token does, and a child can't mint. Returns the agent when that's the rule that
// applied, nil when the caller is a member.
func (s *Server) requireSessionMinter(w http.ResponseWriter, r *http.Request, vaultID string) (*Actor, error) {
	sess := sessionFromContext(r.Context())
	if sess != nil && sess.VaultID == "" && sess.AgentID != "" {
		if role, err := s.store.GetVaultRole(r.Context(), sess.AgentID, vaultID); err == nil && role == "proxy" {
			actor, err := s.actorFromSession(r.Context(), sess)
			if err != nil {
				jsonError(w, http.StatusForbidden, "Invalid session")
				return nil, err
			}
			return actor, nil
		}
	}
	_, err := s.requireVaultMember(w, r, vaultID)
	return nil, err
}

// handleRevokeScopedSession deletes one vault-scoped token by its
// public_id. The caller must be at least a vault `member` of the row's
// vault, or the agent that minted it — other proxy-only callers cannot
// revoke. Cross-vault revocation is blocked at the store level via the
// vault_id filter.
func (s *Server) handleRevokeScopedSession(w http.ResponseWriter, r *http.Request) {
	publicID := r.PathValue("id")
	if publicID == "" {
		jsonError(w, http.StatusBadRequest, "Session id is required")
		return
	}

	vaultName := r.URL.Query().Get("vault")
	if vaultName == "" {
		jsonError(w, http.StatusBadRequest, "vault is required")
		return
	}

	ctx := r.Context()
	ns, err := s.store.GetVault(ctx, vaultName)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", vaultName))
		return
	}

	proxyAgent, err := s.requireSessionMinter(w, r, ns.ID)
	if err != nil {
		return
	}

	if proxyAgent != nil {
		err = s.store.RevokeScopedSessionMintedBy(ctx, ns.ID, publicID, proxyAgent.ID)
	} else {
		err = s.store.RevokeScopedSession(ctx, ns.ID, publicID)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "Session not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, "Failed to revoke scoped session")
		return
	}
	jsonOK(w, map[string]string{"status": "revoked"})
}


