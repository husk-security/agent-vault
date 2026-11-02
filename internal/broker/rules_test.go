package broker

import "testing"

// What deploy/agent-vault-services.json in Fleet says about github.com.
var gitReadOnly = []RequestRule{
	{Action: RuleDeny, Query: map[string]string{"service": "git-receive-pack"}},
	{Action: RuleAllow, Methods: []string{"GET", "HEAD"}},
	{Action: RuleAllow, Methods: []string{"POST"}, Path: "/*/git-upload-pack"},
}

func TestRulesCloneButNotPush(t *testing.T) {
	cases := []struct {
		name          string
		method, p, q  string
		allowed       bool
	}{
		{"clone, refs", "GET", "/o/r.git/info/refs", "service=git-upload-pack", true},
		{"clone, pack", "POST", "/o/r.git/git-upload-pack", "", true},
		{"a page", "GET", "/o/r", "", true},
		{"head", "HEAD", "/o/r", "", true},

		{"push, refs", "GET", "/o/r.git/info/refs", "service=git-receive-pack", false},
		{"push, pack", "POST", "/o/r.git/git-receive-pack", "", false},

		{"refs, name upper case", "GET", "/o/r.git/info/refs", "SERVICE=git-receive-pack", false},
		{"refs, value upper case", "GET", "/o/r.git/info/refs", "service=GIT-RECEIVE-PACK", false},
		{"refs, value encoded", "GET", "/o/r.git/info/refs", "service=git%2Dreceive%2Dpack", false},
		{"refs, second value", "GET", "/o/r.git/info/refs", "service=git-upload-pack&service=git-receive-pack", false},
		{"refs, a query that doesn't parse", "GET", "/o/r.git/info/refs", "service=git-receive-pack;x=1", false},
		{"refs, another bad query", "GET", "/o/r.git/info/refs", "service=%zz", false},

		{"pack, method lower case", "post", "/o/r.git/git-receive-pack", "", false},
		{"pack, path upper case", "POST", "/o/r.git/GIT-UPLOAD-PACK", "", false},
		{"pack, trailing slash", "POST", "/o/r.git/git-upload-pack/", "", false},
		{"pack, dot segments", "POST", "/o/r.git/git-receive-pack/../git-upload-pack", "", false},
		{"pack, dot segments the other way", "POST", "/o/r.git/git-upload-pack/../git-receive-pack", "", false},
		{"pack, encoded dots", "POST", "/o/r.git/git-receive-pack/%2e%2e/git-upload-pack", "", false},
		{"pack, encoded slash", "POST", "/o/r.git/git-receive-pack%2fgit-upload-pack", "", false},
		{"pack, encoded twice", "POST", "/o/r.git/git-receive-pack%252fgit-upload-pack", "", false},
		{"pack, double slash", "POST", "/o/r.git/git-receive-pack//git-upload-pack", "", false},
		{"pack, backslash", "POST", `/o/r.git/git-receive-pack\git-upload-pack`, "", false},
		{"pack, parameters", "POST", "/o/r.git/git-receive-pack;/git-upload-pack", "", false},
		{"pack, in the query", "POST", "/o/r.git/git-receive-pack", "x=/git-upload-pack", false},

		{"other methods", "PUT", "/o/r", "", false},
		{"delete", "DELETE", "/o/r", "", false},
		{"a websocket isn't a GET", RuleMethodWebSocket, "/o/r", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CheckRules(gitReadOnly, c.method, c.p, c.q).Allowed; got != c.allowed {
				t.Fatalf("%s %s?%s: allowed %v, want %v", c.method, c.p, c.q, got, c.allowed)
			}
		})
	}
}

func TestRulesNoneMeansOpen(t *testing.T) {
	if d := CheckRules(nil, "DELETE", "/anything", ""); !d.Allowed || d.Rule != -1 {
		t.Fatalf("got %+v", d)
	}
}

func TestRulesNothingMatchingIsRefused(t *testing.T) {
	rules := []RequestRule{{Action: RuleAllow, Methods: []string{"GET"}}}
	if d := CheckRules(rules, "POST", "/", ""); d.Allowed || d.Rule != -1 {
		t.Fatalf("got %+v", d)
	}
}

func TestRulesFirstMatchDecides(t *testing.T) {
	rules := []RequestRule{
		{Action: RuleDeny, Methods: []string{"GET"}, Path: "/secret/*"},
		{Action: RuleAllow, Methods: []string{"GET"}},
	}
	if d := CheckRules(rules, "GET", "/secret/x", ""); d.Allowed || d.Rule != 0 {
		t.Fatalf("got %+v", d)
	}
	if d := CheckRules(rules, "GET", "/open", ""); !d.Allowed || d.Rule != 1 {
		t.Fatalf("got %+v", d)
	}
}

// A deny rule on a path sees through what a server might normalize.
func TestRulesDenyPathSeesThroughSpelling(t *testing.T) {
	rules := []RequestRule{
		{Action: RuleDeny, Path: "/admin/*"},
		{Action: RuleAllow},
	}
	for _, p := range []string{"/admin/x", "/ADMIN/x", "/%61dmin/x", "/%2561dmin/x", "/a/../admin/x", "//admin//x", `/admin\x`, "/admin;v=1/x", "/./admin/x", "/admin%2fx"} {
		if CheckRules(rules, "GET", p, "").Allowed {
			t.Errorf("%s should be refused", p)
		}
	}
	if !CheckRules(rules, "GET", "/public/x", "").Allowed {
		t.Error("/public/x should be allowed")
	}
}

// npm's scoped packages arrive with an encoded slash, and a rule with no path has no need to care.
func TestRulesAllowWithNoPathTakesAnySpelling(t *testing.T) {
	rules := []RequestRule{{Action: RuleAllow, Methods: []string{"GET"}}}
	if !CheckRules(rules, "GET", "/@scope%2fname", "").Allowed {
		t.Fatal("refused")
	}
}

func TestRulesAllowOnQueryNeedsEveryValue(t *testing.T) {
	rules := []RequestRule{{Action: RuleAllow, Query: map[string]string{"service": "git-upload-pack"}}}
	if !CheckRules(rules, "GET", "/", "service=git-upload-pack").Allowed {
		t.Fatal("refused the plain case")
	}
	for _, q := range []string{"", "service=git-receive-pack", "service=git-upload-pack&service=git-receive-pack", "service=%zz"} {
		if CheckRules(rules, "GET", "/", q).Allowed {
			t.Errorf("%q should be refused", q)
		}
	}
}

func TestValidateRules(t *testing.T) {
	bad := [][]RequestRule{
		{{Action: "maybe"}},
		{{Action: ""}},
		{{Action: RuleAllow, Methods: []string{"get"}}},
		{{Action: RuleAllow, Methods: []string{""}}},
		{{Action: RuleAllow, Path: "no-slash"}},
		{{Action: RuleAllow, Path: "/a?b"}},
		{{Action: RuleAllow, Query: map[string]string{"": "x"}}},
		make([]RequestRule, maxRulesPerService+1),
	}
	for i, rules := range bad {
		s := Service{Rules: rules}
		if s.ValidateRules() == nil {
			t.Errorf("case %d should not validate", i)
		}
	}
	s := Service{Rules: gitReadOnly}
	if err := s.ValidateRules(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateChecksRules(t *testing.T) {
	cfg := Config{Vault: "v", Services: []Service{{Name: "svc", Host: "a.example.com", Auth: Auth{Type: "passthrough"}, Rules: []RequestRule{{Action: "nope"}}}}}
	if Validate(&cfg) == nil {
		t.Fatal("bad rule passed Validate")
	}
}
