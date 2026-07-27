package normalize

import "testing"

// --- LogAnalytics (relay_security decision -> mallcop Type) ----------------
//
// mallcoppro-f1a re-scope: this connector now maps ONLY the
// authorization-boundary decisions (unauthorized_writer / nip42_auth_failure
// -> login_failure; nip86_admin_call's allowpubkey/banpubkey methods ->
// iam_policy_attach + role_assignment fan-out). rate_limited,
// nip09_tombstone, and balance_gate_rejected are usage/billing and now
// produce ZERO Results. The tests below assert both directions: the KEPT
// decisions map correctly, and the DROPPED decisions produce nothing.

// TestLogAnalyticsAuthFailureDecisions covers every decision that represents
// an authorization-boundary rejected write/auth attempt: the Type MUST be
// byte-equal to mallcop/core/detect/auth_failure_burst.go's
// authFailureEventTypes gate literal "login_failure" (verified by reading
// that file directly, 2026-07-21) so a burst of same-pubkey rejections
// fires auth-failure-burst.
func TestLogAnalyticsAuthFailureDecisions(t *testing.T) {
	cases := []string{
		"nip42_auth_failure",
		"unauthorized_writer",
	}
	for _, decision := range cases {
		t.Run(decision, func(t *testing.T) {
			got := LogAnalytics(decision, "deadbeefpubkey", "203.0.113.5", "relay.moot.pub", "restricted: pubkey is not admitted to this relay's tenant write-allowlist")
			if len(got) != 1 {
				t.Fatalf("want 1 result, got %d: %+v", len(got), got)
			}
			r := got[0]
			if r.Type != "login_failure" {
				t.Errorf("Type = %q, want %q", r.Type, "login_failure")
			}
			if r.Type != LogAnalyticsAuthFailureEventType {
				t.Errorf("Type %q does not match exported LogAnalyticsAuthFailureEventType %q", r.Type, LogAnalyticsAuthFailureEventType)
			}
			p := decode(t, r, map[string]any{"decision": decision})
			if p["ip"] != "203.0.113.5" {
				t.Errorf("ip = %v, want 203.0.113.5", p["ip"])
			}
			if p["reason"] != "restricted: pubkey is not admitted to this relay's tenant write-allowlist" {
				t.Errorf("reason = %v", p["reason"])
			}
			if p["domain"] != "relay.moot.pub" {
				t.Errorf("domain = %v", p["domain"])
			}
		})
	}
}

// TestLogAnalyticsUsageBillingDecisionsProduceNoFinding proves the three
// usage/billing decisions produce ZERO Results — not a finding, not even
// the inert CatchAll — regardless of what pubkey/detail they carry.
func TestLogAnalyticsUsageBillingDecisionsProduceNoFinding(t *testing.T) {
	cases := []struct {
		name     string
		decision string
		detail   string
	}{
		{"rate_limited", "rate_limited", "rate-limited: too many anonymous requests from this IP, try again later"},
		{"nip09_tombstone", "nip09_tombstone", "tombstoned event id=abc123def456"},
		{"balance_gate_rejected", "balance_gate_rejected", "restricted: insufficient donut balance"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := LogAnalytics(c.decision, "somepubkey", "198.51.100.7", "relay.moot.pub", c.detail)
			if len(got) != 0 {
				t.Fatalf("want 0 results (usage/billing must produce no finding), got %d: %+v", len(got), got)
			}
		})
	}
}

// TestLogAnalyticsNIP86AllowlistGrantFanOut asserts the allowpubkey GRANT
// method fans out to config-drift's "iam_policy_attach" gate and
// priv-escalation's "role_assignment" gate, carrying the target pubkey +
// method + outcome.
func TestLogAnalyticsNIP86AllowlistGrantFanOut(t *testing.T) {
	got := LogAnalytics("nip86_admin_call", "adminpubkeyhex", "", "", "method=allowpubkey outcome=allow")
	if len(got) != 2 {
		t.Fatalf("want 2 fan-out results, got %d: %+v", len(got), got)
	}

	cd := wantType(t, got, "iam_policy_attach")
	cdp := decode(t, cd, map[string]any{})
	if cdp["policy_name"] != "allowpubkey" {
		t.Errorf("iam_policy_attach policy_name = %v, want allowpubkey", cdp["policy_name"])
	}
	if cdp["resource_name"] != "nostr-relay" {
		t.Errorf("iam_policy_attach resource_name = %v", cdp["resource_name"])
	}
	if cdp["change_description"] != "NIP-86 admin call: method=allowpubkey outcome=allow" {
		t.Errorf("iam_policy_attach change_description = %v", cdp["change_description"])
	}

	pe := wantType(t, got, "role_assignment")
	pep := decode(t, pe, map[string]any{})
	// allowpubkey is a GRANT: role carries the "write" token priv-escalation
	// recognizes (so it casts its committee vote), action stays "role_assignment"
	// (not a narrowing), and the raw method survives in role_name for fidelity
	// (mallcoppro-956).
	if pep["role"] != "relay-write-allowlist" {
		t.Errorf("role_assignment role = %v, want relay-write-allowlist", pep["role"])
	}
	if pep["role_name"] != "allowpubkey" {
		t.Errorf("role_assignment role_name = %v, want allowpubkey", pep["role_name"])
	}
	if pep["action"] != "role_assignment" {
		t.Errorf("role_assignment action = %v, want role_assignment (a grant is an elevation)", pep["action"])
	}
	if pep["target_user"] != "adminpubkeyhex" {
		t.Errorf("role_assignment target_user = %v, want adminpubkeyhex", pep["target_user"])
	}
	if pep["principal_id"] != "adminpubkeyhex" {
		t.Errorf("role_assignment principal_id = %v, want adminpubkeyhex", pep["principal_id"])
	}
}

// TestLogAnalyticsNIP86AllowlistRevokeDenyStillFansOut proves the revoke
// (banpubkey) method also fans out, and that a DENIED admin-call attempt
// (a non-admin caller probing the admin surface) still fans out — the
// fan-out does not condition on outcome=allow vs outcome=deny, mirroring
// the Cosmos SQL role assignment precedent's unconditional fan-out.
func TestLogAnalyticsNIP86AllowlistRevokeDenyStillFansOut(t *testing.T) {
	got := LogAnalytics("nip86_admin_call", "", "", "", "method=banpubkey outcome=deny")
	if len(got) != 2 {
		t.Fatalf("want 2 fan-out results even for a denied grant/revoke call, got %d: %+v", len(got), got)
	}
	types := map[string]bool{got[0].Type: true, got[1].Type: true}
	if !types["iam_policy_attach"] || !types["role_assignment"] {
		t.Errorf("want iam_policy_attach + role_assignment, got %v", types)
	}
	// banpubkey is a REVOKE, not an elevation: the role_assignment leg carries
	// action "remove_role_assignment" so priv-escalation's remove/revoke guard
	// drops it (no priv-escalation vote), while config_drift still surfaces the
	// ban via the iam_policy_attach leg (mallcoppro-956).
	pe := wantType(t, got, "role_assignment")
	pep := decode(t, pe, map[string]any{})
	if pep["action"] != "remove_role_assignment" {
		t.Errorf("banpubkey role_assignment action = %v, want remove_role_assignment (a revoke narrows, not elevates)", pep["action"])
	}
}

// TestLogAnalyticsNIP86NonAllowlistMethodsProduceNoFinding proves that
// nip86_admin_call methods OTHER than allowpubkey/banpubkey — the read-only
// capability surface (supportedmethods, listallowedpubkeys) and any
// unrecognized method a caller invents — are NOT a security-config change
// and produce zero Results, regardless of outcome.
func TestLogAnalyticsNIP86NonAllowlistMethodsProduceNoFinding(t *testing.T) {
	cases := []string{
		"method=supportedmethods outcome=allow",
		"method=listallowedpubkeys outcome=allow",
		"method=listallowedpubkeys outcome=deny",
		"method=someunknownmethod outcome=deny",
	}
	for _, detail := range cases {
		t.Run(detail, func(t *testing.T) {
			got := LogAnalytics("nip86_admin_call", "callerpubkey", "", "", detail)
			if len(got) != 0 {
				t.Fatalf("want 0 results for non-allowlist admin method (%q), got %d: %+v", detail, len(got), got)
			}
		})
	}
}

// TestLogAnalyticsUnknownDecisionFallsBackToCatchAll proves a decision this
// connector doesn't recognize (e.g. a future seclog.Decision* added to the
// relay before this connector is updated) still reaches the type-less
// detectors instead of being dropped or crashing — distinct from the
// KNOWN usage/billing decisions above, which are deliberately dropped.
func TestLogAnalyticsUnknownDecisionFallsBackToCatchAll(t *testing.T) {
	got := LogAnalytics("some_future_decision", "pk", "1.2.3.4", "d", "detail text")
	if len(got) != 1 {
		t.Fatalf("want 1 result, got %d", len(got))
	}
	if got[0].Type != CatchAll {
		t.Errorf("Type = %q, want CatchAll (%q)", got[0].Type, CatchAll)
	}
}

// TestNIP86AdminIsAllowlistChange exercises the method-name gate directly.
func TestNIP86AdminIsAllowlistChange(t *testing.T) {
	cases := []struct {
		method string
		want   bool
	}{
		{"allowpubkey", true},
		{"banpubkey", true},
		{"listallowedpubkeys", false},
		{"supportedmethods", false},
		{"", false},
		{"AllowPubKey", false}, // khatru's MethodName() is always lowercase; no case-fold
	}
	for _, c := range cases {
		if got := nip86AdminIsAllowlistChange(c.method); got != c.want {
			t.Errorf("nip86AdminIsAllowlistChange(%q) = %v, want %v", c.method, got, c.want)
		}
	}
}

// TestParseNIP86Method exercises the detail-string parser directly against
// the EXACT format the relay's own source emits (nip86admin.go's
// `"method="+mp.MethodName()+" outcome="+outcome` — verified by reading that
// file, 2026-07-21) plus defensive malformed-input cases.
func TestParseNIP86Method(t *testing.T) {
	cases := []struct{ detail, want string }{
		{"method=allowpubkey outcome=allow", "allowpubkey"},
		{"method=listallowedpubkeys outcome=deny", "listallowedpubkeys"},
		{"no method here", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := parseNIP86Method(c.detail); got != c.want {
			t.Errorf("parseNIP86Method(%q) = %q, want %q", c.detail, got, c.want)
		}
	}
}
