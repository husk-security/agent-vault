package broker

import (
	"fmt"
	"net/url"
	"path"
	"strings"
	"unicode"
)

// RequestRule is one line of a service's request policy: what an allowlist
// entry may be used for, once its host has matched. It exists because a host
// isn't an operation. `github.com` on the allowlist allows a clone and a push
// alike, and the two differ only in a path and a query parameter, since both
// POST.
//
// A service with no rules allows every request, as it always did. A service
// with rules is read top to bottom: the first rule that matches decides, and a
// request nothing matches is refused.
type RequestRule struct {
	Action string `yaml:"action" json:"action"` // "allow" or "deny"
	// Methods matches any of these, upper case. Empty matches every method.
	// RuleMethodWebSocket stands for a WebSocket upgrade, which is a GET on the
	// wire but carries traffic in both directions, so `GET` doesn't cover it.
	Methods []string `yaml:"methods,omitempty" json:"methods,omitempty"`
	// Path is a glob in the same language as Service.Path. Empty matches every path.
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
	// Query names parameters and values, all of which must match. Empty matches every query.
	Query map[string]string `yaml:"query,omitempty" json:"query,omitempty"`
}

const (
	RuleAllow           = "allow"
	RuleDeny            = "deny"
	RuleMethodWebSocket = "WEBSOCKET"

	maxRulesPerService = 64
)

// RuleDecision is the outcome of CheckRules. Rule is the index of the rule that
// decided, -1 when no rule did.
type RuleDecision struct {
	Allowed bool
	Rule    int
}

// CheckRules applies rules to one request. escapedPath is the path as the client
// sent it, rawQuery the query as the client sent it.
//
// The upstream decides what a path means, and it may read it differently from
// us, so the two actions treat an ambiguous request in opposite ways. A deny
// rule matches generously: on the path with dot segments, doubled slashes,
// encodings and `;` parameters taken out, ignoring case, and on a query it can't
// parse. An allow rule naming a path or a query matches only a request with
// nothing ambiguous in it, and with every value of a named parameter equal to
// the one it names.
func CheckRules(rules []RequestRule, method, escapedPath, rawQuery string) RuleDecision {
	if len(rules) == 0 {
		return RuleDecision{Allowed: true, Rule: -1}
	}
	method = strings.ToUpper(method)
	clean, canonical := canonicalPath(escapedPath)
	query, queryErr := url.ParseQuery(rawQuery)
	for i := range rules {
		r := &rules[i]
		if !methodMatches(r.Methods, method) {
			continue
		}
		deny := r.Action != RuleAllow
		if r.Path != "" {
			if deny {
				if _, ok := matchPathGlob(strings.ToLower(r.Path), strings.ToLower(clean)); !ok {
					continue
				}
			} else if _, ok := matchPathGlob(r.Path, clean); !ok || !canonical {
				continue
			}
		}
		if len(r.Query) > 0 && !queryMatches(r.Query, query, queryErr, deny) {
			continue
		}
		return RuleDecision{Allowed: !deny, Rule: i}
	}
	return RuleDecision{Allowed: false, Rule: -1}
}

func methodMatches(methods []string, method string) bool {
	if len(methods) == 0 {
		return true
	}
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}

func queryMatches(want map[string]string, query url.Values, parseErr error, deny bool) bool {
	if parseErr != nil {
		return deny
	}
	for k, v := range want {
		if deny {
			// Any value, under any spelling of the name.
			found := false
			for name, values := range query {
				if !strings.EqualFold(name, k) {
					continue
				}
				for _, got := range values {
					found = found || strings.EqualFold(got, v)
				}
			}
			if !found {
				return false
			}
			continue
		}
		values := query[k]
		if len(values) == 0 {
			return false
		}
		for _, got := range values {
			if got != v {
				return false
			}
		}
	}
	return true
}

// canonicalPath returns what a path comes to once everything a server might
// normalize is gone, and whether the path was already in that form.
func canonicalPath(escaped string) (clean string, canonical bool) {
	decoded := escaped
	canonical = true
	for i := 0; i < 4; i++ {
		next, err := url.PathUnescape(decoded)
		if err != nil {
			canonical = false
			break
		}
		if next == decoded {
			break
		}
		if i > 0 {
			canonical = false // encoded twice
		}
		decoded = next
	}
	lower := strings.ToLower(escaped)
	for _, encoded := range []string{"%2f", "%5c", "%2e", "%3b"} {
		if strings.Contains(lower, encoded) {
			canonical = false
		}
	}
	if strings.ContainsRune(decoded, '\\') || strings.ContainsRune(decoded, ';') || strings.ContainsFunc(decoded, unicode.IsControl) {
		canonical = false
	}
	unified := strings.ReplaceAll(decoded, `\`, "/")
	segments := strings.Split(unified, "/")
	for i, s := range segments {
		if j := strings.IndexByte(s, ';'); j >= 0 {
			segments[i] = s[:j]
		}
	}
	clean = path.Clean("/" + strings.Join(segments, "/"))
	if clean != decoded {
		canonical = false
	}
	return clean, canonical
}

// ValidateRules checks a service's request rules.
func (s *Service) ValidateRules() error {
	if len(s.Rules) > maxRulesPerService {
		return fmt.Errorf("rules: at most %d allowed", maxRulesPerService)
	}
	for i, r := range s.Rules {
		if r.Action != RuleAllow && r.Action != RuleDeny {
			return fmt.Errorf("rule %d: action must be %q or %q", i, RuleAllow, RuleDeny)
		}
		for _, m := range r.Methods {
			if m == "" || strings.ToUpper(m) != m || strings.ContainsFunc(m, func(c rune) bool { return c < 'A' || c > 'Z' }) {
				return fmt.Errorf("rule %d: method %q must be upper-case letters", i, m)
			}
		}
		if err := ValidatePath(r.Path); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
		for k := range r.Query {
			if k == "" {
				return fmt.Errorf("rule %d: query parameter name is empty", i)
			}
		}
	}
	return nil
}
