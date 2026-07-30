package doctor

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// FIXTURE PROVENANCE — every response body under testdata/ is a REAL Azure
// response, not a hand-written approximation:
//
//   - law_403_insufficient_access.json
//     Captured verbatim from the GROUND-TRUTH incident: GitHub Actions run
//     30295738283…/30295666850 in <operator deploy repo, private>, step "Run mallcop
//     scan", 2026-07-27T18:52:49Z. The scan's loganalytics sibling printed it
//     on stderr as `Log Analytics API error 403: <body>` while a
//     workspace-scoped Log Analytics Reader role assignment WAS in place and
//     was being silently ignored (see <operator infra template, private>:140-153).
//     This is the exact body the design brief calls "the same 403
//     InsufficientAccessError with zero remediation hint".
//
//   - arm_403_authorization_failed.json
//     Captured from <operator infra repo, private> run 30289332141 ("Deploy example-project
//     production", 2026-07-27), where the CI service principal lacked
//     Contributor on the resource group. TWO substitutions were required
//     because GitHub Actions MASKS registered secrets in its logs: the
//     `client` id and the subscription id appear as `***` in the raw log, and
//     are restored here from their non-secret published values
//     (<operator infra template, private>:111-112 and the deploy workflow header).
//     The object id, action and scope are verbatim.
//
//   - law_error_unmapped_code.json
//     A REAL Azure error envelope captured live from api.loganalytics.io on
//     2026-07-30 (code WorkspaceNotFoundError). It stands in for "a denial
//     carrying an error code this doctor has no mapped remediation for": no
//     unmapped-403 body has ever been recorded in this estate, and inventing
//     one would be exactly the fabrication the item forbids, so a real
//     envelope with a real, unmapped code is served with a 403 status by the
//     test. What is under test is the doctor's behaviour on an unrecognized
//     CODE, which this exercises faithfully.
//
//   - arm_workspace_workspace_context.json
//     LIVE CAPTURE, REDACTED. The body was recorded 2026-07-30T13:02:10Z from a
//     real ARM workspace GET (api-version=2022-10-01): HTTP/2 200, content-type
//     application/json; charset=utf-8, 1007 body bytes on the wire.
//     Authenticated with a live operator session via an ARM-scoped token; the
//     token was piped into curl and never written, logged or committed. This
//     was a READ — no grant was requested or applied, so the item's emit-only
//     constraint holds.
//
//     ACCOUNT-SCOPED IDENTIFIERS HAVE BEEN REPLACED WITH PLACEHOLDERS, because
//     this repository is PUBLIC. Substituted: subscription id, tenant id,
//     application/object ids, Log Analytics customerId, correlation id, etag,
//     resource-group / workspace / deployment names and the resource tags. Each
//     placeholder is an obviously-synthetic 00000000-0000-4000-8000-0000000000NN
//     GUID or an `example-*` name. Byte count therefore no longer matches the
//     wire; the recorded provenance above is what the capture WAS, not what this
//     file is byte-for-byte.
//
//     WHAT REMAINS REAL is everything the tests actually discriminate on: the
//     full field set and nesting, ARM's real `resourceGroups` /
//     `Microsoft.OperationalInsights` id casing, sku/provisioningState/
//     retentionInDays/publicNetworkAccess*/workspaceCapping/dataIngestionStatus
//     shapes, and — load-bearing — location is eastus2 (NOT eastus:
//     remediate.go embeds Location into the emitted ARM --what-if template, so
//     an invented region would make that assertion vacuous, and "eastus" would
//     additionally pass as a prefix of "eastus2").
//     enableLogAccessUsingOnlyResourcePermissions is false here — the
//     workspace-context case as it genuinely exists in production.
//
//   - arm_workspace_resource_context.json
//     The same live capture with EXACTLY ONE FIELD FLIPPED:
//     features.enableLogAccessUsingOnlyResourcePermissions false -> true.
//     That single boolean is precisely the change the real incident made and
//     that <operator infra template, private>:150-152 reverted to fix it; Azure has
//     no other observable difference between the two access modes on this body.
//     The one-field-only claim is not a comment to trust — it is enforced by
//     TestWorkspaceFixturesAreTheLiveCaptureFlippedOnce below, which fails if
//     any other byte of the two files diverges.
//
// NO BEARER TOKEN IS RECORDED ANYWHERE. Committing a real AAD access token
// would be a live credential leak, so token fixtures are MINTED by
// makeToken below with the real AAD claim key set (captured from a live
// api.loganalytics.io token on 2026-07-30 — key names only, never the token)
// and the real, non-secret identity values from the incident.
func loadFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(b)
}

// TestWorkspaceFixturesAreTheLiveCaptureFlippedOnce enforces the provenance
// claim above instead of asking a reader to take it on trust. The two bodies
// must differ in EXACTLY ONE leaf:
// features.enableLogAccessUsingOnlyResourcePermissions. If someone hand-edits
// either file — changes the region, drops a field, invents a shape — this fails.
//
// It also enforces the REDACTION invariant. This repository is public, so the
// capture's account-scoped identifiers were replaced with obviously-synthetic
// placeholders. A byte-count check against the wire would be meaningless now,
// so instead every GUID in both fixtures must BE a placeholder — which is what
// actually protects us: re-introducing a real subscription id, tenant id,
// object id or customerId turns this test red.
func TestWorkspaceFixturesAreTheLiveCaptureFlippedOnce(t *testing.T) {
	ws := loadFixture(t, "arm_workspace_workspace_context.json")
	rc := loadFixture(t, "arm_workspace_resource_context.json")

	guid := regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	for _, f := range []struct{ name, body string }{
		{"arm_workspace_workspace_context.json", ws},
		{"arm_workspace_resource_context.json", rc},
	} {
		for _, g := range guid.FindAllString(f.body, -1) {
			if !strings.HasPrefix(g, "00000000-") {
				t.Errorf("%s carries what looks like a REAL identifier %q; this repo is public, "+
					"so every GUID in a fixture must be a 00000000-… placeholder", f.name, g)
			}
		}
	}

	// The flip must be reproducible from the capture by that one substitution
	// and nothing else — a raw text check, so reordering or re-indenting the
	// file (which would make it no longer the recorded bytes) also fails.
	if want := strings.Replace(ws,
		`"enableLogAccessUsingOnlyResourcePermissions":false`,
		`"enableLogAccessUsingOnlyResourcePermissions":true`, 1); want != rc {
		t.Errorf("resource-context fixture is not the live capture with the single access-mode "+
			"boolean flipped.\n  derived: %s\n  on disk: %s", want, rc)
	}

	// And the semantic consequence: same everything, opposite access mode.
	var wsm, rcm map[string]any
	if err := json.Unmarshal([]byte(ws), &wsm); err != nil {
		t.Fatalf("workspace-context fixture is not valid JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(rc), &rcm); err != nil {
		t.Fatalf("resource-context fixture is not valid JSON: %v", err)
	}
	feat := func(m map[string]any) map[string]any {
		return m["properties"].(map[string]any)["features"].(map[string]any)
	}
	if feat(wsm)["enableLogAccessUsingOnlyResourcePermissions"] != false ||
		feat(rcm)["enableLogAccessUsingOnlyResourcePermissions"] != true {
		t.Fatalf("access-mode flag is not false/true across the pair: %v vs %v", feat(wsm), feat(rcm))
	}
	delete(feat(wsm), "enableLogAccessUsingOnlyResourcePermissions")
	delete(feat(rcm), "enableLogAccessUsingOnlyResourcePermissions")
	if !reflect.DeepEqual(wsm, rcm) {
		t.Errorf("the two fixtures differ somewhere other than the access mode:\n %#v\n %#v", wsm, rcm)
	}

	// Guard the values remediate.go actually consumes. `eastus` is a PREFIX of
	// `eastus2`, so a substring assertion elsewhere cannot catch the region
	// having been invented — pin it exactly here.
	if loc := wsm["location"]; loc != "eastus2" {
		t.Errorf("location must be the real workspace region eastus2, got %v", loc)
	}
	if id, _ := wsm["id"].(string); !strings.Contains(id, "/resourceGroups/") ||
		!strings.Contains(id, "/providers/Microsoft.OperationalInsights/") {
		t.Errorf("id must carry ARM's real casing, got %v", id)
	}
	if cid := wsm["properties"].(map[string]any)["customerId"]; cid != "00000000-0000-4000-8000-000000000005" {
		t.Errorf("customerId must be the redaction placeholder, got %v", cid)
	}
}

// Real, non-secret identifiers from the 2026-07-27 incident.
const (
	// expectedOID / expectedAppID: "mallcop-monitor", the SP every grant was
	// made to (<operator infra template, private>:111-112).
	expectedOID   = "00000000-0000-4000-8000-000000000007"
	expectedAppID = "00000000-0000-4000-8000-000000000003"
	expectedName  = "mallcop-monitor"

	// actualOID: "mallcop-pro-aci", the SP the scan was ACTUALLY running as —
	// discovered only by the "DIAG scan SP identity" step injected into
	// <operator deploy repo, private> CI run at 2026-07-27T19:36:49Z.
	actualOID  = "00000000-0000-4000-8000-000000000008"
	actualName = "mallcop-pro-aci"

	tenantID = "00000000-0000-4000-8000-000000000002"
)

// makeToken builds a JWT with the REAL AAD client-credentials claim key set.
// The signature segment is not a real signature and is never verified — the
// doctor decodes claims offline and makes no authorization decision from them
// (see DecodeIdentity). Minting rather than recording is deliberate: a
// recorded token would be a live bearer credential committed to git.
func makeToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	seg := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal token segment: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := map[string]any{"typ": "JWT", "alg": "RS256", "kid": "test", "x5t": "test"}
	return seg(header) + "." + seg(claims) + ".not-a-real-signature"
}

// appTokenClaims is the claim set an AAD CLIENT-CREDENTIALS token carries.
func appTokenClaims(oid, appid, aud string) map[string]any {
	return map[string]any{
		"aud":      aud,
		"iss":      "https://sts.windows.net/" + tenantID + "/",
		"iat":      float64(time.Now().Add(-time.Minute).Unix()),
		"nbf":      float64(time.Now().Add(-time.Minute).Unix()),
		"exp":      float64(time.Now().Add(time.Hour).Unix()),
		"aio":      "opaque",
		"appid":    appid,
		"appidacr": "1",
		"idp":      "https://sts.windows.net/" + tenantID + "/",
		"idtyp":    "app",
		"oid":      oid,
		"rh":       "opaque",
		"sub":      oid,
		"tid":      tenantID,
		"uti":      "opaque",
		"ver":      "1.0",
	}
}
