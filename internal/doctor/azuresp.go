package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Azure OAuth2 scopes the Azure-SP family mints tokens for. The DATA plane
// scope differs per connector (Log Analytics has its own resource); the
// CONTROL plane scope is always ARM. Diagnose's alternate-scope branch turns
// on the fact that these are two different tokens for the SAME principal.
const (
	ScopeARM          = "https://management.azure.com/.default"
	ScopeLogAnalytics = "https://api.loganalytics.io/.default"
)

// stalenessThreshold is how old LastVerifiedLive may be before every emitted
// remediation is downgraded from "run this" to "proposed but unverified"
// (design §6, safety property 4). 90 days is one Azure API-version cycle: long
// enough not to cry wolf, short enough that a role rename or an API-version
// retirement shows up as doubt before the operator pastes the command.
const stalenessThreshold = 90 * 24 * time.Hour

// bodyExcerptMax caps how much of a provider response body is quoted into a
// Diagnosis summary. A GRANT-MISS is only useful if it carries the body that
// was not understood, but an unbounded body would let a provider push
// arbitrary bytes into a report the operator reads.
const bodyExcerptMax = 400

// CallOutcome records ONE HTTP call the doctor made, as evidence. Body is the
// provider's own response body — it never contains our credentials (we send a
// bearer token, we do not receive one).
type CallOutcome struct {
	Status int
	Body   string
	// Err is set when the call could not be made at all (DNS, TLS, timeout).
	// A transport failure is NOT a permission failure and must not be
	// diagnosed as one.
	Err string
}

func (o CallOutcome) failedToRun() bool { return o.Err != "" }

// Target names the concrete resource this doctor is diagnosing access to. Its
// fields are what the emitted az commands are scoped to — so a wrong Target
// means a wrongly-scoped grant, which is why they are read from the same flags
// and env the connector itself runs with, never guessed.
type Target struct {
	ConnectorID    string
	SubscriptionID string
	ResourceGroup  string
	// WorkspaceName is the Log Analytics workspace ARM name (loganalytics only).
	WorkspaceName string
	// WorkspaceResourceID is the full ARM id; when empty it is composed from
	// SubscriptionID/ResourceGroup/WorkspaceName.
	WorkspaceResourceID string
}

func (t Target) workspaceScope() string {
	if t.WorkspaceResourceID != "" {
		return t.WorkspaceResourceID
	}
	if t.SubscriptionID == "" || t.ResourceGroup == "" || t.WorkspaceName == "" {
		return ""
	}
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.OperationalInsights/workspaces/%s",
		t.SubscriptionID, t.ResourceGroup, t.WorkspaceName)
}

func (t Target) resourceGroupScope() string {
	if t.SubscriptionID == "" || t.ResourceGroup == "" {
		return ""
	}
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", t.SubscriptionID, t.ResourceGroup)
}

func (t Target) subscriptionScope() string {
	if t.SubscriptionID == "" {
		return ""
	}
	return "/subscriptions/" + t.SubscriptionID
}

// Expected is the identity the operator DECLARED this connector should be
// running as. It is what closes the wrong-service-principal case: on
// 2026-07-27 a scan authenticated as service principal "mallcop-pro-aci"
// (oid 00000000-0000-4000-8000-000000000008) while every grant had been made
// to "mallcop-monitor" (oid 00000000-0000-4000-8000-000000000007), and the
// only way that was ever discovered was by injecting a diagnostic step into a
// CI workflow to print the identity behind an opaque secret. Declaring the
// expectation makes the doctor answer it offline, in one local JWT decode.
//
// Empty fields are not checked — an operator who has not declared an
// expectation gets no wrong-principal verdict, never a fabricated one.
type Expected struct {
	ObjectID    string
	AppID       string
	DisplayName string
}

func (e Expected) declared() bool { return e.ObjectID != "" || e.AppID != "" }

func (e Expected) label() string {
	switch {
	case e.DisplayName != "" && e.AppID != "":
		return fmt.Sprintf("%s (appId %s)", e.DisplayName, e.AppID)
	case e.DisplayName != "":
		return e.DisplayName
	case e.AppID != "":
		return "appId " + e.AppID
	default:
		return "objectId " + e.ObjectID
	}
}

// workspaceProps is the subset of an ARM Log Analytics workspace GET response
// the doctor reads. enableLogAccessUsingOnlyResourcePermissions is THE field
// that tells the resource-context deficiency apart from a missing grant — the
// two are byte-identical at the data plane (both are
// 403 InsufficientAccessError with no remediation hint).
type workspaceProps struct {
	Location   string `json:"location"`
	ID         string `json:"id"`
	Properties struct {
		CustomerID string `json:"customerId"`
		Features   struct {
			// Pointer: ABSENT and false are different. Absent means the ARM
			// response did not tell us the access mode, which must stay
			// ambiguous rather than defaulting to "workspace-context".
			ResourceContextOnly *bool `json:"enableLogAccessUsingOnlyResourcePermissions"`
		} `json:"features"`
	} `json:"properties"`
}

// Evidence is what one Probe run gathered. It is the connector-family-specific
// ProbeResult of the kernel (core/connect.ProbeResult): Diagnose consumes it,
// nothing else interprets it.
type Evidence struct {
	// Identity is the LOCALLY decoded acting identity (design §7 Azure fast
	// path: zero network calls to answer "who am I authenticating as").
	Identity IdentityClaims
	// IdentityErr is why Identity could not be read, if it could not.
	IdentityErr string
	// CredentialsMissing is set when the SP env vars are not configured at all,
	// so there is no token to decode and no call to make.
	CredentialsMissing string

	// DataPlane is the outcome of the SAME call the connector itself makes.
	DataPlane CallOutcome
	// DataPlaneScope is the OAuth2 scope the data-plane token was minted for.
	DataPlaneScope string

	// ControlPlane is the ALTERNATE-SCOPE probe: the same principal, a token
	// minted for ARM instead, reading the target resource's control-plane
	// record. Nil when the family has no separate control plane (cmd/azure's
	// data plane IS ARM) or when the data-plane call succeeded.
	ControlPlane *CallOutcome
	// Workspace is parsed from ControlPlane when it returned 200.
	Workspace *workspaceProps

	CheckedAt time.Time
}

// azureErrorBody is the error envelope BOTH Azure planes use. Captured live:
// Log Analytics data plane (<operator deploy repo, private> CI run,
// 2026-07-27) and ARM control plane (<operator infra repo, private> run 30289332141,
// 2026-07-27); see testdata/.
type azureErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		// correlationId is present on the Log Analytics plane only.
		CorrelationID string `json:"correlationId"`
	} `json:"error"`
}

func parseAzureError(body string) (code, message string, ok bool) {
	var b azureErrorBody
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		return "", "", false
	}
	if b.Error.Code == "" {
		return "", "", false
	}
	return b.Error.Code, b.Error.Message, true
}

// authorizationFailedRE pulls the denied ACTION and SCOPE out of a real ARM
// AuthorizationFailed message. Recorded verbatim (<operator infra repo, private> run
// 30289332141): "The client '<id>' with object id '<oid>' does not have
// authorization to perform action '<action>' over scope '<scope>' or the scope
// is invalid. ..." Parsing it is what lets Remediate scope the emitted grant
// to EXACTLY the denied scope instead of a broad subscription-wide guess.
var authorizationFailedRE = regexp.MustCompile(
	`perform action '([^']+)' over scope '([^']+)'`)

// deficiency is the named failure this doctor concluded. It is an internal
// enum, not a wire type: the wire carries the kernel's Diagnosis (Known /
// Summary / Confidence). It exists so Remediate can build a correctly-scoped
// command from the SAME conclusion Diagnose reached, instead of re-parsing a
// human sentence.
type deficiency int

const (
	defHealthy deficiency = iota
	defUnknown            // GRANT-MISS
	defNoCredentials
	defIdentityUnreadable
	defWrongPrincipal
	defUserTokenInHeadlessConnector
	defTokenExpired
	defTokenAudienceMismatch
	defResourceContextMode
	defMissingWorkspaceGrant
	defMissingResourceRead
	defAmbiguousDenial
	defARMAuthorizationFailed
)

// assessment is Diagnose's full conclusion: the wire Diagnosis plus the
// structured facts Remediate needs.
type assessment struct {
	def        deficiency
	diagnosis  Diagnosis
	evidence   Evidence
	deniedAct  string // ARM AuthorizationFailed only
	deniedScpe string // ARM AuthorizationFailed only
}

// AzureSP is the GrantClaim for the Azure service-principal identity family
// (design §11: "Ships in slice 1: mallcop doctor for the Azure service-
// principal family"). One value serves both cmd/azure (ARM Activity Log) and
// cmd/loganalytics (Log Analytics query API) because they authenticate with
// the same client-credentials SP against the same tenant — the identity family
// is the unit, not the connector.
//
// The sibling binary supplies MintToken / DataPlane / ControlPlane so the
// doctor exercises the connector's OWN call, not a parallel reimplementation
// of it that could pass while the real call fails.
type AzureSP struct {
	Target   Target
	Expected Expected

	// LastVerifiedLive is when mallcop's own CI eval last proved these
	// remediations against a live Azure account. Zero means never.
	LastVerifiedLive time.Time

	// DataPlaneScope is the OAuth2 scope the connector's real call needs.
	DataPlaneScope string

	// MintToken returns an access token for scope. It must never log the token.
	MintToken func(ctx context.Context, scope string) (string, error)
	// DataPlaneCall performs the connector's own read using token.
	DataPlaneCall func(ctx context.Context, token string) CallOutcome
	// ControlPlaneCall performs the ARM GET on the target resource using an
	// ARM-scoped token. Nil for families whose data plane already IS ARM.
	ControlPlaneCall func(ctx context.Context, token string) CallOutcome

	// Now is injectable for deterministic tests; nil means time.Now.
	Now func() time.Time

	// last holds the most recent assessment so Remediate(Diagnosis) — the
	// kernel's signature — can build correctly-scoped commands.
	last *assessment
}

func (a *AzureSP) now() time.Time {
	if a.Now != nil {
		return a.Now().UTC()
	}
	return time.Now().UTC()
}

// Probe gathers evidence. Order matters: the identity is decoded OFFLINE from
// the minted token before any diagnosis is attempted, so the wrong-principal
// case is answerable even when every network call after it fails.
func (a *AzureSP) Probe(ctx context.Context) (Evidence, error) {
	ev := Evidence{CheckedAt: a.now(), DataPlaneScope: a.DataPlaneScope}

	token, err := a.MintToken(ctx, a.DataPlaneScope)
	if err != nil {
		// The token endpoint is the operator's credential configuration, not a
		// grant problem. Record it and keep going far enough to report it.
		ev.CredentialsMissing = err.Error()
		return ev, nil
	}

	claims, err := DecodeIdentity(token)
	if err != nil {
		ev.IdentityErr = err.Error()
	}
	ev.Identity = claims

	ev.DataPlane = a.DataPlaneCall(ctx, token)
	if ev.DataPlane.Status == 200 || ev.DataPlane.failedToRun() {
		// A healthy data plane needs no alternate-scope probe, and a transport
		// failure would make one meaningless.
		return ev, nil
	}

	// ALTERNATE-SCOPE PROBE. The data plane denied us; ask the SAME principal,
	// with a token for a DIFFERENT scope (ARM), whether it can see the target
	// resource at all. This is the branch that separates "workspace is in
	// resource-context access mode" from "principal has no grant" — the two
	// deficiencies that are byte-identical at the data plane.
	if a.ControlPlaneCall != nil {
		armToken, armErr := a.MintToken(ctx, ScopeARM)
		if armErr != nil {
			ev.ControlPlane = &CallOutcome{Err: armErr.Error()}
			return ev, nil
		}
		out := a.ControlPlaneCall(ctx, armToken)
		ev.ControlPlane = &out
		if out.Status == 200 {
			var wp workspaceProps
			if err := json.Unmarshal([]byte(out.Body), &wp); err == nil {
				ev.Workspace = &wp
			}
		}
	}
	return ev, nil
}

// Diagnose turns Evidence into a Diagnosis. Every branch below is a real
// decision over real evidence — a locally decoded JWT, the provider's own
// error code, and the alternate-scope result — not a signature lookup.
func (a *AzureSP) Diagnose(ev Evidence) (Diagnosis, error) {
	as := a.assess(ev)
	a.last = &as
	return as.diagnosis, nil
}

func (a *AzureSP) assess(ev Evidence) assessment {
	mk := func(def deficiency, known bool, conf float64, format string, args ...any) assessment {
		return assessment{
			def:      def,
			evidence: ev,
			diagnosis: Diagnosis{
				Known:      known,
				Summary:    fmt.Sprintf(format, args...),
				Confidence: conf,
			},
		}
	}

	// 1. No credentials at all. Nothing to diagnose about grants yet.
	if ev.CredentialsMissing != "" {
		return mk(defNoCredentials, true, 1.0,
			"the connector has no usable Azure service-principal credential: %s", ev.CredentialsMissing)
	}

	// 2. Identity unreadable. The doctor refuses to assert an identity it
	//    could not read — that would be worse than saying nothing, because the
	//    whole wrong-principal case turns on this claim.
	if ev.IdentityErr != "" {
		return mk(defIdentityUnreadable, false, 0.0,
			"could not read the acting identity from the access token (%s); "+
				"cannot attribute this connector's calls to a principal", ev.IdentityErr)
	}

	// 3. WRONG SERVICE PRINCIPAL — decided OFFLINE, before any network verdict,
	//    because a wrong principal makes every downstream 403 a red herring.
	if a.Expected.declared() {
		if wrong, detail := a.principalMismatch(ev.Identity); wrong {
			return mk(defWrongPrincipal, true, 0.99, "%s", detail)
		}
	}

	// 4. A delegated USER token in a headless connector: the credential will
	//    expire or MFA-break, and every grant made to the service principal is
	//    being ignored because the connector is not that principal.
	if !ev.Identity.IsAppToken() {
		return mk(defUserTokenInHeadlessConnector, true, 0.9,
			"the connector is authenticating as a delegated USER identity (oid %s), not a service principal; "+
				"role assignments made to a service principal do not apply to it", ev.Identity.OID)
	}

	// 5. Token-level failures the JWT itself explains, checked before the
	//    permission ladder so an expired or wrong-audience token is never
	//    misdiagnosed as a missing grant.
	if !ev.Identity.Expiry.IsZero() && ev.Identity.Expiry.Before(ev.CheckedAt) {
		return mk(defTokenExpired, true, 0.95,
			"the access token expired at %s (clock skew or a cached token)",
			ev.Identity.Expiry.Format(time.RFC3339))
	}
	if aud := ev.Identity.Audience; aud != "" && ev.DataPlane.Status == 401 &&
		!audienceMatchesScope(aud, ev.DataPlaneScope) {
		return mk(defTokenAudienceMismatch, true, 0.95,
			"the access token was minted for audience %q but the connector calls an endpoint that requires scope %q",
			aud, ev.DataPlaneScope)
	}

	// 6. Transport failure is not a permission failure.
	if ev.DataPlane.failedToRun() {
		return mk(defUnknown, false, 0.0,
			"the connector's own read could not be attempted: %s", ev.DataPlane.Err)
	}

	// 7. Healthy.
	if ev.DataPlane.Status == 200 {
		return mk(defHealthy, true, 1.0,
			"connector %s can read its source as %s; no deficiency found",
			a.Target.ConnectorID, identityLabel(ev.Identity))
	}

	// 8. A denial. Read the provider's OWN error code.
	code, message, ok := parseAzureError(ev.DataPlane.Body)
	if !ok {
		return mk(defUnknown, false, 0.0,
			"HTTP %d from the connector's source with a body this doctor does not recognize: %s",
			ev.DataPlane.Status, excerpt(ev.DataPlane.Body))
	}

	switch code {
	case "InsufficientAccessError":
		return a.assessInsufficientAccess(ev)

	case "AuthorizationFailed":
		as := mk(defARMAuthorizationFailed, true, 0.95, "")
		if m := authorizationFailedRE.FindStringSubmatch(message); m != nil {
			as.deniedAct, as.deniedScpe = m[1], m[2]
			as.diagnosis.Summary = fmt.Sprintf(
				"service principal %s is not authorized to perform %q at scope %q",
				identityLabel(ev.Identity), as.deniedAct, as.deniedScpe)
			return as
		}
		// AuthorizationFailed whose message we could not parse: we know the
		// class but not the scope, so we cannot emit a correctly-scoped grant.
		// Say so rather than guessing a scope.
		as.diagnosis.Confidence = 0.5
		as.diagnosis.Summary = fmt.Sprintf(
			"ARM denied service principal %s with AuthorizationFailed, but the message did not name an action and scope: %s",
			identityLabel(ev.Identity), excerpt(message))
		return as
	}

	// A 403 carrying a code the corpus has not mapped: a GRANT-MISS (design
	// §4). Known:false, never a confident guess.
	return mk(defUnknown, false, 0.0,
		"HTTP %d %s from the connector's source, which this doctor has no mapped remediation for: %s",
		ev.DataPlane.Status, code, excerpt(message))
}

// assessInsufficientAccess resolves the ambiguity the 2026-07-27 incident was
// built on: Log Analytics returns the SAME `403 InsufficientAccessError` body
// whether the workspace is in resource-context access mode (workspace-scoped
// RBAC silently ignored) or the principal simply holds no role. The data plane
// cannot tell them apart. The ALTERNATE-SCOPE control-plane read can.
func (a *AzureSP) assessInsufficientAccess(ev Evidence) assessment {
	mk := func(def deficiency, conf float64, format string, args ...any) assessment {
		return assessment{def: def, evidence: ev, diagnosis: Diagnosis{
			Known: true, Summary: fmt.Sprintf(format, args...), Confidence: conf,
		}}
	}
	who := identityLabel(ev.Identity)

	if ev.ControlPlane == nil || ev.ControlPlane.failedToRun() {
		return mk(defAmbiguousDenial, 0.5,
			"Log Analytics denied %s with InsufficientAccessError; without a control-plane read of the workspace "+
				"this doctor cannot tell resource-context access mode from a missing role assignment", who)
	}

	if ev.ControlPlane.Status == 403 || ev.ControlPlane.Status == 401 {
		// The principal cannot even READ the workspace resource. No workspace
		// grant can be effective; it is missing read at the resource itself.
		return mk(defMissingResourceRead, 0.9,
			"%s cannot read the workspace resource on the ARM control plane either (HTTP %d), "+
				"so it holds no effective role on this workspace at all",
			who, ev.ControlPlane.Status)
	}

	if ev.Workspace == nil || ev.Workspace.Properties.Features.ResourceContextOnly == nil {
		return mk(defAmbiguousDenial, 0.5,
			"Log Analytics denied %s with InsufficientAccessError; the workspace's ARM record did not report "+
				"enableLogAccessUsingOnlyResourcePermissions, so resource-context access mode cannot be ruled out", who)
	}

	if *ev.Workspace.Properties.Features.ResourceContextOnly {
		// THE headline case. Observed live 2026-07-27 on example-project prod: the
		// workspace-scoped Log Analytics Reader assignment existed and was
		// silently ignored, because in resource-context ("require resource
		// permissions") mode the workspace query endpoint does not honor
		// workspace-scoped RBAC.
		return mk(defResourceContextMode, 0.95,
			"the Log Analytics workspace is in resource-context access mode "+
				"(enableLogAccessUsingOnlyResourcePermissions=true), under which the workspace query endpoint "+
				"IGNORES workspace-scoped RBAC — so any Log Analytics Reader grant made to %s on this workspace "+
				"has no effect", who)
	}

	// Workspace-context mode is on, so a workspace-scoped role assignment WOULD
	// be honored — the principal just does not have one.
	return mk(defMissingWorkspaceGrant, 0.9,
		"the workspace is in workspace-context access mode, so a workspace-scoped role assignment is honored; "+
			"%s does not hold one and its query is denied", who)
}

// principalMismatch compares the locally decoded identity against what the
// operator declared. Returns the human sentence so Diagnose does not have to
// rebuild it.
func (a *AzureSP) principalMismatch(got IdentityClaims) (bool, string) {
	if a.Expected.ObjectID != "" && !strings.EqualFold(a.Expected.ObjectID, got.OID) {
		return true, fmt.Sprintf(
			"WRONG SERVICE PRINCIPAL: this connector's credential authenticates as objectId %s, "+
				"but the grants for it were made to %s (objectId %s). Every permission check will fail, "+
				"and every 403 downstream is a symptom of this, not of a missing grant",
			got.OID, a.Expected.label(), a.Expected.ObjectID)
	}
	if a.Expected.AppID != "" && got.AppID != "" && !strings.EqualFold(a.Expected.AppID, got.AppID) {
		return true, fmt.Sprintf(
			"WRONG SERVICE PRINCIPAL: this connector's credential authenticates as appId %s (objectId %s), "+
				"but the expected identity is %s",
			got.AppID, got.OID, a.Expected.label())
	}
	return false, ""
}

// audienceMatchesScope compares a token's aud claim to the OAuth2 scope the
// endpoint requires. AAD strips the "/.default" suffix and may or may not keep
// a trailing slash on the audience, so this normalizes both before comparing.
func audienceMatchesScope(aud, scope string) bool {
	norm := func(s string) string {
		s = strings.TrimSuffix(s, "/.default")
		s = strings.TrimSuffix(s, "/")
		return strings.ToLower(s)
	}
	return norm(aud) == norm(scope)
}

func identityLabel(c IdentityClaims) string {
	if c.AppID != "" {
		return fmt.Sprintf("service principal appId %s (objectId %s)", c.AppID, c.OID)
	}
	return "objectId " + c.OID
}

func excerpt(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= bodyExcerptMax {
		return s
	}
	return s[:bodyExcerptMax] + "… (truncated)"
}
