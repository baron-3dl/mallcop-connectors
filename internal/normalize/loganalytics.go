package normalize

import "strings"

// LogAnalytics maps a decoded relay_security structured log line (emitted by
// the nostr-relay's internal/seclog package, mallcoppro-813, and surfaced via
// Azure Log Analytics ContainerAppConsoleLogs_CL — cmd/loganalytics) to
// canonical mallcop events.
//
// decision/pubkey/remote/domain/detail are the five relay_security fields
// (see nostr-relay's internal/seclog/seclog.go doc comment: "{"msg":
// "relay_security","decision":<decision>,"pubkey":<pubkey>,"remote":<remote>,
// "domain":<domain>,"detail":<detail>}"). The decision literals below are
// byte-identical copies of nostr-relay's seclog.Decision* constants (verified
// against internal/seclog/seclog.go 2026-07-21) — this package cannot import
// that module (separate repo/module), so the strings are duplicated here
// rather than shared.
//
// mallcoppro-f1a RE-SCOPE: this connector previously ingested EVERY
// relay_security decision, including rate_limited / nip09_tombstone /
// balance_gate_rejected — those are USAGE/billing signals (a paying client
// hit its rate cap, a paid tombstone was accepted, a request was rejected
// for insufficient balance), not infrastructure subversion, and produced
// noisy findings a security operator has no action to take on. This
// connector now maps ONLY the two AUTHORIZATION-BOUNDARY signal families:
// (1) nip86_admin_call, narrowed further to just the write-allowlist
// GRANT/REVOKE methods (allowpubkey/banpubkey) — someone changing WHO may
// write to the relay; (2) unauthorized_writer (and, defensively,
// nip42_auth_failure — see below) — a non-admitted pubkey trying to write
// or authenticate and being rejected, framed as allowlist-breach probing.
// rate_limited, nip09_tombstone, and balance_gate_rejected now produce NO
// Result at all (see the decision switch below) rather than a CatchAll
// pass-through, so this connector's output is exclusively
// authorization-boundary events.
//
// decisionNIP42AuthFailure is defined in seclog.go but NOT currently wired to
// any call site in the relay (mallcoppro-813's live-proof escalation: no
// non-vendor khatru hook point exists for the raw NIP-42 AUTH envelope
// failure without hand-patching vendored khatru, which that item's scope
// forbade — accepted descope mallcoppro-a26). It is still mapped here
// (defensively, alongside unauthorized_writer, which DOES fire in prod) in
// case a future relay change wires it in — it is squarely an
// authorization-boundary failure (a failed proof-of-identity), not a
// usage/billing signal, so it stays in scope even though the KEEP list this
// item was scoped against only calls out unauthorized_writer by name; today
// it will simply never appear in a live query result.
const (
	decisionNIP42AuthFailure    = "nip42_auth_failure"
	decisionUnauthorizedWriter  = "unauthorized_writer"
	decisionBalanceGateRejected = "balance_gate_rejected" // usage/billing — DROP
	decisionRateLimited         = "rate_limited"          // usage/billing — DROP
	decisionNIP86AdminCall      = "nip86_admin_call"
	decisionNIP09Tombstone      = "nip09_tombstone" // usage/billing — DROP
)

// LogAnalyticsAuthFailureEventType is the canonical Type for every relay
// decision that represents a failed authorization-boundary attempt to write
// or connect (nip42_auth_failure, unauthorized_writer) — it MUST exactly
// equal mallcop/core/detect/auth_failure_burst.go's authFailureEventTypes
// gate literal ("login_failure") so a repeated-rejection burst from the same
// pubkey (allowlist-breach probing: a non-admitted key repeatedly trying to
// write or authenticate) fires auth-failure-burst exactly like a repeated
// failed console login would for any other connector.
const LogAnalyticsAuthFailureEventType = "login_failure"

// LogAnalytics maps a single relay_security line to zero or more Results.
//
// Only two decision families produce a Result: the auth-failure-burst family
// (nip42_auth_failure / unauthorized_writer, both authorization-boundary
// rejections) and the nip86_admin_call GRANT/REVOKE family (a write-allowlist
// membership change — see nip86AdminIsAllowlistChange below). Every other
// relay_security decision produces NO Result:
//
//   - rate_limited / nip09_tombstone / balance_gate_rejected are USAGE/billing
//     signals (a paying client hit its rate cap, a paid tombstone was
//     accepted, a request was rejected for insufficient balance) — not
//     infrastructure subversion — and are dropped ENTIRELY (mallcoppro-f1a
//     re-scope): no Result, not even the inert CatchAll, so this connector's
//     output is exclusively authorization-boundary events.
//   - a nip86_admin_call whose method is not a write-allowlist grant/revoke
//     (e.g. "supportedmethods", "listallowedpubkeys", or any method name a
//     caller invents) is not a security-config change either and is also
//     dropped.
//   - a genuinely UNRECOGNIZED decision string (a future seclog.Decision* the
//     relay adds before this connector is updated) still falls through to
//     CatchAll rather than being silently dropped — that is the one case
//     where "we don't know what this is yet" should still reach the
//     type-less detectors, as distinct from "we know exactly what this is
//     and it's usage, not security."
func LogAnalytics(decision, pubkey, remote, domain, detail string) []Result {
	switch decision {

	// --- auth-failure-burst: nip42_auth_failure / unauthorized_writer are
	// both "this pubkey tried to write or authenticate without standing on
	// this relay's write-allowlist and was rejected" — allowlist-breach
	// PROBING, the same brute-force/probing shape auth-failure-burst already
	// detects for login_failure, not a per-event new-actor signal. actor
	// (the caller's pubkey) is set by cmd/loganalytics from the same
	// `pubkey` field, so repeated rejections from one pubkey accrue exactly
	// like repeated login_failure events from one username.
	case decisionNIP42AuthFailure, decisionUnauthorizedWriter:
		p := map[string]any{"action": "allowlist_breach_probe", "decision": decision}
		set(p, "reason", detail)
		set(p, "ip", remote)
		set(p, "source_ip", remote)
		set(p, "domain", domain)
		return []Result{{Type: LogAnalyticsAuthFailureEventType, Payload: p}}

	// --- usage/billing — DROP entirely, no Result (mallcoppro-f1a). A
	// rejected-for-rate-limit request carries no authorization-boundary
	// signal: the caller may be perfectly admitted and simply over its
	// quota. Not routed to CatchAll — this is a KNOWN, deliberately-excluded
	// decision, not an unrecognized one.
	case decisionRateLimited:
		return nil

	// --- usage/billing — DROP entirely, no Result (mallcoppro-f1a). A
	// balance-gate rejection is a billing outcome (insufficient donut
	// balance), not a subversion of the relay's security boundary.
	case decisionBalanceGateRejected:
		return nil

	// --- priv-escalation + config-drift fan-out, NARROWED to the
	// write-allowlist GRANT/REVOKE methods only (mallcoppro-f1a re-scope).
	// nip86admin.go's RejectNonAdminAPICall logs this decision for EVERY
	// NIP-86 method call (allow/ban/list/supportedmethods alike), but only
	// AllowPubKey/BanPubKey actually change WHO may write to the relay —
	// list/supportedmethods are read-only capability surface, not a
	// security-config change, so they are dropped (see
	// nip86AdminIsAllowlistChange). Fan-out still fires on both allow AND
	// deny outcomes for a grant/revoke method call: a DENIED attempt to call
	// AllowPubKey/BanPubKey by a non-admin caller is itself an
	// authorization-boundary probe against the relay's admin surface,
	// mirroring azure.go's Microsoft.DocumentDB/databaseAccounts/
	// sqlRoleAssignments/write mapping (a Cosmos DB SQL RBAC grant, which
	// also fans out to iam_policy_attach + role_assignment unconditionally
	// because that gate has no "unprivileged tier" to condition on) — this
	// relay's write-allowlist model has no such tier either.
	//
	// detail is "method=<name> outcome=<allow|deny>" (nip86admin.go); method
	// is parsed out both to gate on (grant/revoke family only) and for
	// payload richness (role/policy_name).
	case decisionNIP86AdminCall:
		method := parseNIP86Method(detail)
		if !nip86AdminIsAllowlistChange(method) {
			return nil
		}
		cd := map[string]any{"action": "admin_call"}
		set(cd, "resource_name", "nostr-relay")
		set(cd, "policy_name", method)
		cd["change_description"] = "NIP-86 admin call: " + detail
		// priv-escalation fan-out: mirror azure.go's sqlRoleAssignments
		// write-vs-delete split so the GENERIC priv-escalation gate reads a
		// GRANT as an elevation and a REVOKE as a narrowing — no new detector
		// rule, and no NIP-86 method vocabulary leaks into priv-escalation's
		// cross-cloud elevated-keyword set (mallcoppro-956). allowpubkey grants
		// a pubkey relay-write-allowlist membership (an elevation): action
		// "role_assignment" with a role carrying the "write" token
		// priv-escalation already recognizes. banpubkey REVOKES it (a
		// narrowing): action "remove_role_assignment", which trips isElevated's
		// remove/revoke guard so priv-escalation stays quiet — config_drift
		// still surfaces the ban via the iam_policy_attach leg. Previously role
		// carried the raw method name ("allowpubkey"), which matched no elevated
		// keyword, so priv-escalation never cast its committee vote for a genuine
		// write grant. The raw method stays in policy_name (config-drift leg) and
		// role_name (priv-escalation leg) for evidence fidelity.
		peAction := "role_assignment"
		if method == "banpubkey" {
			peAction = "remove_role_assignment"
		}
		pe := map[string]any{"action": peAction}
		set(pe, "role", "relay-write-allowlist")
		set(pe, "role_name", method)
		set(pe, "target_user", pubkey)
		set(pe, "principal_id", pubkey)
		set(pe, "resource_name", "nostr-relay")
		return []Result{
			{Type: "iam_policy_attach", Payload: cd},
			{Type: "role_assignment", Payload: pe},
		}

	// --- usage/billing — DROP entirely, no Result (mallcoppro-f1a). An
	// accepted NIP-09 tombstone is the relay processing a paid delete
	// request, not a config-drift-shaped audit-trail tamper — the customer
	// exercised a right their own key already had, no boundary was crossed.
	case decisionNIP09Tombstone:
		return nil
	}

	return []Result{{Type: CatchAll, Payload: map[string]any{"action": "relay_security:" + decision}}}
}

// nip86AdminIsAllowlistChange reports whether method is one of the two
// NIP-86 methods that actually GRANT or REVOKE write-allowlist membership
// (khatru's method-name constants — see
// vendor/github.com/nbd-wtf/go-nostr/nip86/methods.go's AllowPubKey/BanPubKey
// MethodName() implementations, both lowercase with no separator). Every
// other method this relay wires (listallowedpubkeys, supportedmethods) or
// that a caller might invent is read-only capability surface or unsupported,
// not a security-config change.
func nip86AdminIsAllowlistChange(method string) bool {
	switch method {
	case "allowpubkey", "banpubkey":
		return true
	}
	return false
}

// parseNIP86Method extracts the method name from a nip86admin.go detail
// string of the form "method=<name> outcome=<allow|deny>". Returns "" if the
// expected "method=" prefix isn't found (defensive: never panics on an
// unexpected detail shape).
func parseNIP86Method(detail string) string {
	const prefix = "method="
	idx := strings.Index(detail, prefix)
	if idx < 0 {
		return ""
	}
	rest := detail[idx+len(prefix):]
	if sp := strings.IndexByte(rest, ' '); sp >= 0 {
		return rest[:sp]
	}
	return rest
}
