package normalize

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// decode runs a Result through PayloadJSON and returns the decoded flat payload.
func decode(t *testing.T, r Result, raw any) map[string]any {
	t.Helper()
	b, err := r.PayloadJSON(raw)
	if err != nil {
		t.Fatalf("PayloadJSON: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	return m
}

func wantType(t *testing.T, got []Result, typ string) Result {
	t.Helper()
	for _, r := range got {
		if r.Type == typ {
			return r
		}
	}
	t.Fatalf("no result with Type %q; got %+v", typ, got)
	return Result{}
}

// --- AWS -------------------------------------------------------------------

func TestAWSConsoleLoginFailure(t *testing.T) {
	raw := map[string]any{
		"CloudTrailEvent": `{"sourceIPAddress":"1.2.3.4","awsRegion":"us-east-1",
			"responseElements":{"ConsoleLogin":"Failure"},"errorMessage":"bad password"}`,
	}
	got := AWS("ConsoleLogin", raw)
	r := wantType(t, got, "login_failure")
	p := decode(t, r, raw)
	if p["ip"] != "1.2.3.4" {
		t.Errorf("ip = %v", p["ip"])
	}
	if p["reason"] != "bad password" {
		t.Errorf("reason = %v", p["reason"])
	}
}

func TestAWSAddUserToGroupRoleAssignment(t *testing.T) {
	raw := map[string]any{
		"CloudTrailEvent": `{"requestParameters":{"groupName":"admins","userName":"bob"}}`,
	}
	r := wantType(t, AWS("AddUserToGroup", raw), "role_assignment")
	p := decode(t, r, raw)
	if p["role"] != "admins" || p["target_user"] != "bob" || p["action"] != "AddUserToGroup" {
		t.Errorf("payload = %+v", p)
	}
}

func TestAWSStopLoggingCloudTrailStop(t *testing.T) {
	raw := map[string]any{"CloudTrailEvent": `{"requestParameters":{"name":"my-trail"}}`}
	r := wantType(t, AWS("StopLogging", raw), "cloudtrail_stop")
	p := decode(t, r, raw)
	if p["resource_name"] != "my-trail" {
		t.Errorf("resource_name = %v", p["resource_name"])
	}
}

func TestAWSGetObjectExfilFields(t *testing.T) {
	raw := map[string]any{
		"CloudTrailEvent": `{"sourceIPAddress":"9.9.9.9","requestParameters":{"bucketName":"secrets","key":"db.dump"},
			"responseElements":{"contentLength":1048576}}`,
	}
	r := wantType(t, AWS("GetObject", raw), "object_get")
	p := decode(t, r, raw)
	if bt, ok := p["bytes_transferred"].(float64); !ok || int64(bt) != 1048576 {
		t.Errorf("bytes_transferred = %v", p["bytes_transferred"])
	}
	if p["destination"] != "9.9.9.9" {
		t.Errorf("destination = %v", p["destination"])
	}
}

func TestAWSAssumeRoleCrossAccountTrust(t *testing.T) {
	raw := map[string]any{
		"CloudTrailEvent": `{"recipientAccountId":"111111111111",
			"sourceIPAddress":"203.0.113.5",
			"userIdentity":{"type":"IAMUser","principalId":"AIDACKCEVSQ6C2EXAMPLE",
				"arn":"arn:aws:iam::111111111111:user/alice","accountId":"111111111111",
				"accessKeyId":"AKIAIOSFODNN7EXAMPLE","userName":"alice"},
			"requestParameters":{"roleArn":"arn:aws:iam::222222222222:role/cross",
				"roleSessionName":"alice-session"},
			"responseElements":{"credentials":{"accessKeyId":"ASIAEXAMPLE",
				"sessionToken":"FQoGZXIvYXdzEXAMPLETOKEN","expiration":"Jul 17, 2026 1:00:00 PM"}}}`,
	}
	r := wantType(t, AWS("AssumeRole", raw), "trust_added")
	p := decode(t, r, raw)
	if p["domain"] != "222222222222" {
		t.Errorf("domain = %v", p["domain"])
	}
	if p["external_user"] != "111111111111" {
		t.Errorf("external_user = %v", p["external_user"])
	}
	if p["member"] != "arn:aws:iam::222222222222:role/cross" {
		t.Errorf("member = %v", p["member"])
	}
	if p["caller"] != "arn:aws:iam::111111111111:user/alice" {
		t.Errorf("caller = %v", p["caller"])
	}
	if p["session_name"] != "alice-session" {
		t.Errorf("session_name = %v", p["session_name"])
	}
	if p["source_ip"] != "203.0.113.5" {
		t.Errorf("source_ip = %v", p["source_ip"])
	}
	if p["target"] != "arn:aws:iam::222222222222:role/cross" {
		t.Errorf("target = %v", p["target"])
	}
}

// Same-account assume: caller identity must still be promoted onto
// role_assignment, and the caller fallback (userIdentity.principalId, used
// when arn is absent — e.g. a federated/anonymous principal) must kick in.
func TestAWSAssumeRoleSameAccountRoleAssignment(t *testing.T) {
	raw := map[string]any{
		"CloudTrailEvent": `{"recipientAccountId":"111111111111",
			"sourceIPAddress":"10.0.0.9",
			"userIdentity":{"type":"AWSAccount","principalId":"111111111111:federated-session"},
			"requestParameters":{"roleArn":"arn:aws:iam::111111111111:role/internal",
				"roleSessionName":"internal-session"}}`,
	}
	r := wantType(t, AWS("AssumeRole", raw), "role_assignment")
	p := decode(t, r, raw)
	if p["member"] != "arn:aws:iam::111111111111:role/internal" {
		t.Errorf("member = %v", p["member"])
	}
	if p["caller"] != "111111111111:federated-session" {
		t.Errorf("caller (principalId fallback) = %v", p["caller"])
	}
	if p["session_name"] != "internal-session" {
		t.Errorf("session_name = %v", p["session_name"])
	}
	if p["source_ip"] != "10.0.0.9" {
		t.Errorf("source_ip = %v", p["source_ip"])
	}
	if p["target"] != "arn:aws:iam::111111111111:role/internal" {
		t.Errorf("target = %v", p["target"])
	}
}

func TestAWSUnmappedCatchAll(t *testing.T) {
	r := wantType(t, AWS("DescribeInstances", map[string]any{}), CatchAll)
	if r.Type != CatchAll {
		t.Errorf("want catch-all, got %q", r.Type)
	}
}

// --- Azure -----------------------------------------------------------------

func TestAzureRoleAssignment(t *testing.T) {
	entry := map[string]any{
		"caller":     "admin@corp.com",
		"resourceId": "/subscriptions/s/resourceGroups/rg",
		"properties": map[string]any{
			"roleDefinitionName": "Owner",
			"principalId":        "victim",
		},
	}
	r := wantType(t, Azure("Microsoft.Authorization/roleAssignments/write", entry), "role_assignment")
	p := decode(t, r, entry)
	if p["role"] != "Owner" || p["target_user"] != "victim" || p["action"] != "role_assignment" {
		t.Errorf("payload = %+v", p)
	}
}

func TestAzureDiagnosticDeleteAuditTrail(t *testing.T) {
	entry := map[string]any{"resourceId": "/diag/setting1"}
	r := wantType(t, Azure("microsoft.insights/diagnosticSettings/delete", entry), "audit_trail_delete")
	p := decode(t, r, entry)
	if p["resource_name"] != "/diag/setting1" {
		t.Errorf("resource_name = %v", p["resource_name"])
	}
}

func TestAzureKeyVaultSecretAccess(t *testing.T) {
	entry := map[string]any{"resourceId": "/vault/secrets/db"}
	r := wantType(t, Azure("Microsoft.KeyVault/vaults/secrets/read", entry), "secret_access")
	p := decode(t, r, entry)
	if p["target"] != "/vault/secrets/db" {
		t.Errorf("target = %v", p["target"])
	}
}

func TestAzureUserAddNewActor(t *testing.T) {
	entry := map[string]any{"properties": map[string]any{"displayName": "svc-acct", "objectId": "obj-1"}}
	r := wantType(t, Azure("Microsoft.Directory/users/add", entry), "user_created")
	p := decode(t, r, entry)
	if p["display_name"] != "svc-acct" || p["principal_id"] != "obj-1" {
		t.Errorf("payload = %+v", p)
	}
}

// --- Azure relay-infra (Microsoft.App / Microsoft.DocumentDB /
// Microsoft.ContainerRegistry / Microsoft.Network dnszones) -----------------
//
// The Type strings asserted below are byte-equal to real gate literals read
// directly out of ~/projects/mallcop/core/detect (NOT reinvented here):
//   - "config_change"    -- config_drift.go configRules (evType: "config_change")
//   - "secret_access"    -- unusual_resource_access.go resourceAccessEventTypes,
//                           AND scanned regardless-of-type by secrets_exposure.go
//                           (the "scan-all" detector vocab.go documents)
//   - "iam_policy_attach" -- config_drift.go configRules (evType: "iam_policy_attach")
//   - "role_assignment"   -- priv_escalation.go builtinElevationEventTypes
//   - "dependency_add"    -- dependency_tamper.go depTamperEventTypes
// A mistyped Type here would compile and pass Go's type system fine but the
// detector would silently never fire in production -- that's the whole bug
// class this table exists to prevent, hence exact literal assertions.

func TestAzureContainerAppWriteConfigDrift(t *testing.T) {
	// Real op name + shape captured live via az rest against the Activity Log
	// API for nostr-relay-prod (2026-07-20): a containerApps/write PATCH that
	// attempted (and in that instance failed) a custom-hostname bind. Azure
	// represents hostname binds as an ordinary containerApps/write -- there is
	// no separate "hostname op"; the write body carries the customDomains
	// change. So a single containerApps/write mapping covers both plain config
	// changes AND hostname bind attempts.
	entry := map[string]any{
		"caller":     "opscb@3dl.dev",
		"resourceId": "/subscriptions/s/resourceGroups/nostr-relay-prod/providers/Microsoft.App/containerApps/nostr-relay-prod",
		"properties": map[string]any{
			"statusCode":    "BadRequest",
			"statusMessage": `{"error":{"code":"InvalidCustomHostNameValidation","message":"TXT record not found"}}`,
		},
	}
	r := wantType(t, Azure("Microsoft.App/containerApps/write", entry), "config_change")
	p := decode(t, r, entry)
	if p["resource_name"] != entry["resourceId"] {
		t.Errorf("resource_name = %v", p["resource_name"])
	}
}

func TestAzureManagedEnvironmentWriteConfigDrift(t *testing.T) {
	entry := map[string]any{"resourceId": "/subscriptions/s/resourceGroups/nostr-relay-prod/providers/Microsoft.App/managedEnvironments/cae-nostr-relay-prod"}
	r := wantType(t, Azure("Microsoft.App/managedEnvironments/write", entry), "config_change")
	p := decode(t, r, entry)
	if p["resource_name"] != entry["resourceId"] {
		t.Errorf("resource_name = %v", p["resource_name"])
	}
}

func TestAzureContainerAppListSecretsSecretAccess(t *testing.T) {
	entry := map[string]any{"resourceId": "/subscriptions/s/resourceGroups/nostr-relay-prod/providers/Microsoft.App/containerApps/nostr-relay-prod"}
	r := wantType(t, Azure("Microsoft.App/containerApps/listSecrets/action", entry), "secret_access")
	p := decode(t, r, entry)
	if p["target"] != entry["resourceId"] {
		t.Errorf("target = %v", p["target"])
	}
}

func TestAzureCosmosDatabaseAccountWriteConfigDrift(t *testing.T) {
	entry := map[string]any{"resourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-nostr-relay-prod"}
	r := wantType(t, Azure("Microsoft.DocumentDB/databaseAccounts/write", entry), "config_change")
	p := decode(t, r, entry)
	if p["resource_name"] != entry["resourceId"] {
		t.Errorf("resource_name = %v", p["resource_name"])
	}
}

func TestAzureCosmosSqlRoleAssignmentFanOut(t *testing.T) {
	entry := map[string]any{
		"caller":     "attacker@corp.com",
		"resourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-nostr-relay-prod/sqlRoleAssignments/ra1",
		"properties": map[string]any{
			"roleDefinitionId": "00000000-0000-0000-0000-000000000002", // Cosmos DB built-in Data Contributor
			"principalId":      "victim-principal",
		},
	}
	got := Azure("Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/write", entry)
	cd := wantType(t, got, "iam_policy_attach")
	cdp := decode(t, cd, entry)
	if cdp["resource_name"] != entry["resourceId"] {
		t.Errorf("iam_policy_attach resource_name = %v", cdp["resource_name"])
	}
	pe := wantType(t, got, "role_assignment")
	pep := decode(t, pe, entry)
	if pep["target_user"] != "victim-principal" || pep["principal_id"] != "victim-principal" {
		t.Errorf("role_assignment payload = %+v", pep)
	}
}

// TestAzureCosmosSqlRoleAssignmentWriteResolverFillsEmptyFields is the
// mallcoppro-32e regression: a real Cosmos sqlRoleAssignments/write
// BeginRequest event carries NO requestbody at all, so both flat properties
// and the requestbody fallback leave role/principal empty. With a configured
// CosmosRoleResolver, Azure() must call it and use its result to populate the
// role_assignment Result's role/role_name and target_user/principal_id.
func TestAzureCosmosSqlRoleAssignmentWriteResolverFillsEmptyFields(t *testing.T) {
	entry := map[string]any{
		"caller":     "attacker@corp.com",
		"resourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-nostr-relay-prod/sqlRoleAssignments/ra1",
		// No "properties" at all -- mirrors the live-observed bodyless event.
	}
	resolver := func(resourceID string) (string, string, bool) {
		if resourceID != entry["resourceId"] {
			t.Errorf("resolver called with resourceID = %q, want %q", resourceID, entry["resourceId"])
		}
		return "Cosmos DB Built-in Data Contributor", "resolved-principal-guid", true
	}
	got := Azure("Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/write", entry, WithCosmosRoleResolver(resolver))
	pe := wantType(t, got, "role_assignment")
	pep := decode(t, pe, entry)
	if pep["role"] != "Cosmos DB Built-in Data Contributor" || pep["role_name"] != "Cosmos DB Built-in Data Contributor" {
		t.Errorf("role/role_name = %v/%v, want Cosmos DB Built-in Data Contributor", pep["role"], pep["role_name"])
	}
	if pep["target_user"] != "resolved-principal-guid" || pep["principal_id"] != "resolved-principal-guid" {
		t.Errorf("target_user/principal_id = %v/%v, want resolved-principal-guid", pep["target_user"], pep["principal_id"])
	}
}

// TestAzureCosmosSqlRoleAssignmentWriteNoResolverStaysEmpty pins the
// no-regression / graceful-degradation half of mallcoppro-32e: with no
// resolver configured (the default, e.g. every existing caller before this
// change), a bodyless Cosmos sqlRoleAssignments/write entry keeps today's
// best-effort empty role/principal rather than erroring or panicking.
func TestAzureCosmosSqlRoleAssignmentWriteNoResolverStaysEmpty(t *testing.T) {
	entry := map[string]any{
		"caller":     "attacker@corp.com",
		"resourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-nostr-relay-prod/sqlRoleAssignments/ra1",
	}
	got := Azure("Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/write", entry)
	pe := wantType(t, got, "role_assignment")
	pep := decode(t, pe, entry)
	if pep["role"] != nil || pep["target_user"] != nil {
		t.Errorf("expected empty role/target_user with no resolver, got role=%v target_user=%v", pep["role"], pep["target_user"])
	}
}

func TestAzureCosmosListKeysSecretAccess(t *testing.T) {
	entry := map[string]any{"resourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-nostr-relay-prod"}
	r := wantType(t, Azure("Microsoft.DocumentDB/databaseAccounts/listKeys/action", entry), "secret_access")
	p := decode(t, r, entry)
	if p["target"] != entry["resourceId"] {
		t.Errorf("target = %v", p["target"])
	}
}

func TestAzureCosmosReadonlyKeysSecretAccess(t *testing.T) {
	entry := map[string]any{"resourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-nostr-relay-prod"}
	r := wantType(t, Azure("Microsoft.DocumentDB/databaseAccounts/readonlykeys/action", entry), "secret_access")
	p := decode(t, r, entry)
	if p["target"] != entry["resourceId"] {
		t.Errorf("target = %v", p["target"])
	}
}

func TestAzureContainerRegistryPushDependencyTamper(t *testing.T) {
	entry := map[string]any{
		"caller":     "ci@corp.com",
		"resourceId": "/subscriptions/s/resourceGroups/nostr-relay-prod/providers/Microsoft.ContainerRegistry/registries/acrnostrrelayprod",
		"properties": map[string]any{
			"repository": "nostr-relay",
			"tag":        "v0.19.0",
		},
	}
	r := wantType(t, Azure("Microsoft.ContainerRegistry/registries/push/write", entry), "dependency_add")
	p := decode(t, r, entry)
	if p["package"] != "nostr-relay" || p["ecosystem"] != "docker" || p["direct"] != true {
		t.Errorf("payload = %+v", p)
	}
}

func TestAzureDNSRecordWriteConfigDrift(t *testing.T) {
	entry := map[string]any{"resourceId": "/subscriptions/s/resourceGroups/moot-rg/providers/Microsoft.Network/dnszones/moot.pub/A/asuid.relay"}
	r := wantType(t, Azure("Microsoft.Network/dnsZones/A/write", entry), "config_change")
	p := decode(t, r, entry)
	if p["resource_name"] != entry["resourceId"] {
		t.Errorf("resource_name = %v", p["resource_name"])
	}
}

func TestAzureDNSRecordDeleteConfigDrift(t *testing.T) {
	entry := map[string]any{"resourceId": "/subscriptions/s/resourceGroups/rg-dns/providers/Microsoft.Network/dnszones/3dl.network/CNAME/relay"}
	r := wantType(t, Azure("Microsoft.Network/dnsZones/CNAME/delete", entry), "config_change")
	p := decode(t, r, entry)
	if p["resource_name"] != entry["resourceId"] {
		t.Errorf("resource_name = %v", p["resource_name"])
	}
}

// TestAzureDNSRecordCaseInsensitive pins a real production finding: the SAME
// logical Azure operation was observed in the live subscription's Activity Log
// with TWO different casings of the resource-provider segment --
// "Microsoft.Network/dnsZones/..." and "Microsoft.Network/dnszones/..." --
// across different events (az monitor activity-log list against moot-rg /
// rg-dns, 2026-07-20). A case-sensitive switch would silently drop half the
// real-world record-write events into CatchAll, so the match must be
// case-insensitive.
func TestAzureDNSRecordCaseInsensitive(t *testing.T) {
	entry := map[string]any{"resourceId": "/subscriptions/s/resourceGroups/moot-rg/providers/Microsoft.Network/dnszones/moot.pub/TXT/asuid.relay"}
	r := wantType(t, Azure("microsoft.network/dnszones/txt/write", entry), "config_change")
	p := decode(t, r, entry)
	if p["resource_name"] != entry["resourceId"] {
		t.Errorf("resource_name = %v", p["resource_name"])
	}
}

// TestAzureDNSZoneLevelWriteUnmapped is a negative test: zone-LEVEL writes
// (creating/deleting the whole dnszone resource, no record-type segment) are
// out of scope per the item spec ("record write/delete") -- only per-record
// operations map to config-drift. This also guards against a loose
// prefix/suffix matcher accidentally slurping in
// dnssecConfigs/write or diagnosticSettings/write, which also end in
// "/write" under the same Microsoft.Network/dnszones/ prefix.
func TestAzureDNSZoneLevelWriteUnmapped(t *testing.T) {
	entry := map[string]any{"resourceId": "/subscriptions/s/resourceGroups/moot-rg/providers/Microsoft.Network/dnszones/moot.pub"}
	r := wantType(t, Azure("Microsoft.Network/dnsZones/write", entry), CatchAll)
	if r.Type != CatchAll {
		t.Errorf("zone-level write should stay CatchAll, got %q", r.Type)
	}
}

// --- Azure authorization + perimeter subversion (mallcoppro-c789) -----------
//
// Type strings below are byte-equal to real gate literals (grep'd, not
// reinvented) out of ~/projects/mallcop/core/detect:
//   - "role_assignment"    -- priv_escalation.go builtinElevationEventTypes
//   - "iam_policy_attach"  -- config_drift.go configRules
//   - "config_change"      -- config_drift.go configRules
//   - "secret_access"      -- unusual_resource_access.go resourceAccessEventTypes
//   - "audit_log_disabled" -- config_drift.go configRules
//
// LIVE-VERIFIED FIELD SHAPE (az rest against nostr-relay-prod's Activity Log,
// 2026-07-21): the Administrative-category "EndRequest" event (the terminal
// Succeeded one) carries NO request detail -- properties is just {entity,
// eventCategory, hierarchy, message}. Only the paired "BeginRequest" event
// carries the actual write body, and only as a JSON-ENCODED STRING under
// properties.requestbody, keyed by roleDefinitionId (a GUID -- roleDefinitionName
// never appears). Fixtures below exercise BOTH shapes: the requestbody-bearing
// one (real BeginRequest shape) AND the flat-properties one (matches this
// package's existing test convention / a hypothetical richer API response) to
// prove azureRequestBodyProps' fallback doesn't regress the flat path.

func TestAzureRoleAssignmentDeleteRoleAssignment(t *testing.T) {
	// Real BeginRequest shape: requestbody is a JSON string, roleDefinitionId
	// (GUID) not roleDefinitionName.
	entry := map[string]any{
		"caller":     "attacker@corp.com",
		"resourceId": "/subscriptions/s/resourceGroups/nostr-relay-prod/providers/Microsoft.ContainerRegistry/registries/acrnostrrelayprod/providers/Microsoft.Authorization/roleAssignments/c867cdf3",
		"properties": map[string]any{
			"requestbody": `{"properties":{"roleDefinitionId":"/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/owner-guid","principalId":"victim-principal"}}`,
		},
	}
	r := wantType(t, Azure("Microsoft.Authorization/roleAssignments/delete", entry), "role_assignment")
	p := decode(t, r, entry)
	if p["target_user"] != "victim-principal" || p["principal_id"] != "victim-principal" {
		t.Errorf("payload = %+v", p)
	}
	if p["action"] != "remove_role_assignment" {
		t.Errorf("action = %v, want remove_role_assignment (so priv-escalation's narrowing guard doesn't misfire)", p["action"])
	}
}

func TestAzureSqlRoleAssignmentDeleteFanOut(t *testing.T) {
	entry := map[string]any{
		"caller":     "attacker@corp.com",
		"resourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-nostr-relay-prod/sqlRoleAssignments/ra1",
		"properties": map[string]any{
			"roleDefinitionId": "00000000-0000-0000-0000-000000000002",
			"principalId":      "victim-principal",
		},
	}
	got := Azure("Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/delete", entry)
	cd := wantType(t, got, "iam_policy_attach")
	if decode(t, cd, entry)["resource_name"] != entry["resourceId"] {
		t.Errorf("iam_policy_attach resource_name mismatch")
	}
	pe := wantType(t, got, "role_assignment")
	pep := decode(t, pe, entry)
	if pep["target_user"] != "victim-principal" || pep["principal_id"] != "victim-principal" {
		t.Errorf("role_assignment payload = %+v", pep)
	}
}

// TestAzureCosmosSqlRoleAssignmentDeleteResolverFillsEmptyFields is the
// mallcoppro-32e regression for the /delete side: same bodyless-event gap,
// action stays "remove_role_assignment" (not "role_assignment") since this is
// the delete-narrows-access case.
func TestAzureCosmosSqlRoleAssignmentDeleteResolverFillsEmptyFields(t *testing.T) {
	entry := map[string]any{
		"caller":     "attacker@corp.com",
		"resourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-nostr-relay-prod/sqlRoleAssignments/ra1",
	}
	resolver := func(resourceID string) (string, string, bool) {
		return "Cosmos DB Built-in Data Reader", "resolved-principal-guid-2", true
	}
	got := Azure("Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/delete", entry, WithCosmosRoleResolver(resolver))
	pe := wantType(t, got, "role_assignment")
	pep := decode(t, pe, entry)
	if pep["role"] != "Cosmos DB Built-in Data Reader" || pep["role_name"] != "Cosmos DB Built-in Data Reader" {
		t.Errorf("role/role_name = %v/%v, want Cosmos DB Built-in Data Reader", pep["role"], pep["role_name"])
	}
	if pep["target_user"] != "resolved-principal-guid-2" || pep["principal_id"] != "resolved-principal-guid-2" {
		t.Errorf("target_user/principal_id = %v/%v, want resolved-principal-guid-2", pep["target_user"], pep["principal_id"])
	}
	if pep["action"] != "remove_role_assignment" {
		t.Errorf("action = %v, want remove_role_assignment", pep["action"])
	}
}

// TestAzureCosmosSqlRoleAssignmentDeleteNoResolverStaysEmpty is the
// no-regression half for the /delete side.
func TestAzureCosmosSqlRoleAssignmentDeleteNoResolverStaysEmpty(t *testing.T) {
	entry := map[string]any{
		"caller":     "attacker@corp.com",
		"resourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-nostr-relay-prod/sqlRoleAssignments/ra1",
	}
	got := Azure("Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/delete", entry)
	pe := wantType(t, got, "role_assignment")
	pep := decode(t, pe, entry)
	if pep["role"] != nil || pep["target_user"] != nil {
		t.Errorf("expected empty role/target_user with no resolver, got role=%v target_user=%v", pep["role"], pep["target_user"])
	}
}

func TestAzureFederatedIdentityCredentialWriteConfigChange(t *testing.T) {
	// Federating a userAssignedIdentity to an external OIDC issuer/subject is
	// the workload-identity-federation abuse pattern: an external principal
	// (e.g. a GitHub Actions repo) becomes able to assume this identity with
	// no secret exchange. Real op name confirmed via `az provider operation
	// show --namespace Microsoft.ManagedIdentity`.
	entry := map[string]any{
		"caller":     "attacker@corp.com",
		"resourceId": "/subscriptions/s/resourceGroups/nostr-relay-prod/providers/Microsoft.ManagedIdentity/userAssignedIdentities/relay-identity/federatedIdentityCredentials/evil-cred",
	}
	r := wantType(t, Azure("Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write", entry), "config_change")
	p := decode(t, r, entry)
	if p["resource_name"] != entry["resourceId"] {
		t.Errorf("resource_name = %v", p["resource_name"])
	}
}

func TestAzureCosmosDisableLocalAuthOffConfigChange(t *testing.T) {
	entry := map[string]any{
		"resourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-nostr-relay-prod",
		"properties": map[string]any{
			"requestbody": `{"properties":{"disableLocalAuth":false}}`,
		},
	}
	r := wantType(t, Azure("Microsoft.DocumentDB/databaseAccounts/write", entry), "config_change")
	p := decode(t, r, entry)
	desc := fmt.Sprint(p["change_description"])
	if !strings.Contains(desc, "AAD-only") && !strings.Contains(desc, "weakened") {
		t.Errorf("change_description should call out the AAD-only weakening, got %+v", p)
	}
}

func TestAzureCosmosWriteUnreadableToggleConfigChangeFallback(t *testing.T) {
	// Real EndRequest shape: no requestbody at all -- the toggle isn't
	// reliably readable. Per the item spec's own escape hatch: still
	// config_change, just with the limitation noted in the description.
	entry := map[string]any{"resourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-nostr-relay-prod"}
	r := wantType(t, Azure("Microsoft.DocumentDB/databaseAccounts/write", entry), "config_change")
	p := decode(t, r, entry)
	if p["resource_name"] != entry["resourceId"] {
		t.Errorf("resource_name = %v", p["resource_name"])
	}
}

func TestAzureKeyVaultSecretWriteWildcardSecretAccess(t *testing.T) {
	entry := map[string]any{"resourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/relay-vault/secrets/db-conn"}
	r := wantType(t, Azure("Microsoft.KeyVault/vaults/secrets/write", entry), "secret_access")
	p := decode(t, r, entry)
	if p["target"] != entry["resourceId"] {
		t.Errorf("target = %v", p["target"])
	}
}

func TestAzureKeyVaultSecretDeleteWildcardSecretAccess(t *testing.T) {
	entry := map[string]any{"resourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/relay-vault/secrets/db-conn"}
	r := wantType(t, Azure("Microsoft.KeyVault/vaults/secrets/delete", entry), "secret_access")
	p := decode(t, r, entry)
	if p["target"] != entry["resourceId"] {
		t.Errorf("target = %v", p["target"])
	}
}

// TestAzureKeyVaultCasingInsensitive guards the same casing-hazard class as the
// diagnosticSettings bug: the KeyVault secrets prefix and vaults/write must match
// real Azure operationName casing, not just one hand-authored form.
func TestAzureKeyVaultCasingInsensitive(t *testing.T) {
	entry := map[string]any{"resourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/relay-vault/secrets/db-conn"}
	// mixed/alternate casing Azure may emit
	wantType(t, Azure("microsoft.keyvault/vaults/secrets/read", entry), "secret_access")
	wantType(t, Azure("Microsoft.KeyVault/Vaults/Secrets/Read", entry), "secret_access")
	wantType(t, Azure("MICROSOFT.KEYVAULT/VAULTS/WRITE", entry), "config_change")
}

func TestAzureCosmosRegenerateKeySecretAccess(t *testing.T) {
	// Real op name confirmed via `az provider operation show --namespace
	// Microsoft.DocumentDB`: Microsoft.DocumentDB/databaseAccounts/regenerateKey/action.
	entry := map[string]any{"resourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-nostr-relay-prod"}
	r := wantType(t, Azure("Microsoft.DocumentDB/databaseAccounts/regenerateKey/action", entry), "secret_access")
	p := decode(t, r, entry)
	if p["target"] != entry["resourceId"] {
		t.Errorf("target = %v", p["target"])
	}
}

func TestAzureContainerRegistryWriteConfigChange(t *testing.T) {
	// Absorbs mallcoppro-386. Live-verified: `az monitor activity-log list
	// -g nostr-relay-prod --offset 7d` shows real
	// Microsoft.ContainerRegistry/registries/write events (ACR SKU/network
	// rule/admin-user changes), distinct from the already-mapped
	// registries/push/write (image push -> dependency_add).
	entry := map[string]any{"resourceId": "/subscriptions/s/resourceGroups/nostr-relay-prod/providers/Microsoft.ContainerRegistry/registries/acrnostrrelayprod"}
	r := wantType(t, Azure("Microsoft.ContainerRegistry/registries/write", entry), "config_change")
	p := decode(t, r, entry)
	if p["resource_name"] != entry["resourceId"] {
		t.Errorf("resource_name = %v", p["resource_name"])
	}
}

func TestAzureManagedCertificateWriteConfigChange(t *testing.T) {
	entry := map[string]any{"resourceId": "/subscriptions/s/resourceGroups/nostr-relay-prod/providers/Microsoft.App/managedEnvironments/cae-nostr-relay-prod/managedCertificates/relay-cert"}
	r := wantType(t, Azure("Microsoft.App/managedEnvironments/managedCertificates/write", entry), "config_change")
	p := decode(t, r, entry)
	if p["resource_name"] != entry["resourceId"] {
		t.Errorf("resource_name = %v", p["resource_name"])
	}
}

// TestAzureManagedCertificateDeleteCaseInsensitive pins the SAME casing
// hazard already proven for Microsoft.Network/dnszones (mallcoppro-d63):
// `az provider operation show` returns this op family lowercased
// (microsoft.app/managedenvironments/managedcertificates/delete); a
// case-sensitive match against the documented PascalCase form would silently
// drop it.
func TestAzureManagedCertificateDeleteCaseInsensitive(t *testing.T) {
	entry := map[string]any{"resourceId": "/subscriptions/s/resourceGroups/nostr-relay-prod/providers/microsoft.app/managedenvironments/cae-nostr-relay-prod/managedcertificates/relay-cert"}
	r := wantType(t, Azure("microsoft.app/managedenvironments/managedcertificates/delete", entry), "config_change")
	p := decode(t, r, entry)
	if p["resource_name"] != entry["resourceId"] {
		t.Errorf("resource_name = %v", p["resource_name"])
	}
}

func TestAzureDiagnosticSettingWriteRemovesLAWAuditDisabled(t *testing.T) {
	entry := map[string]any{
		"resourceId": "/diag/setting1",
		"properties": map[string]any{
			"requestbody": `{"properties":{"logs":[{"category":"ContainerAppConsoleLogs","enabled":false}]}}`,
		},
	}
	r := wantType(t, Azure("microsoft.insights/diagnosticSettings/write", entry), "audit_log_disabled")
	p := decode(t, r, entry)
	if p["resource_name"] != "/diag/setting1" {
		t.Errorf("resource_name = %v", p["resource_name"])
	}
}

func TestAzureDiagnosticSettingWriteKeepsLAWConfigChange(t *testing.T) {
	entry := map[string]any{
		"resourceId": "/diag/setting1",
		"properties": map[string]any{
			"requestbody": `{"properties":{"workspaceId":"/subscriptions/s/resourceGroups/nostr-relay-prod/providers/Microsoft.OperationalInsights/workspaces/law-nostr-relay-prod","logs":[{"category":"ContainerAppConsoleLogs","enabled":true}]}}`,
		},
	}
	r := wantType(t, Azure("microsoft.insights/diagnosticSettings/write", entry), "config_change")
	p := decode(t, r, entry)
	if p["resource_name"] != "/diag/setting1" {
		t.Errorf("resource_name = %v", p["resource_name"])
	}
}

// TestAzureDiagnosticSettingWriteUnreadableDefaultsConfigChange matches the REAL
// EndRequest shape (no requestbody at all). mallcoppro-2627: when the LAW-removal
// toggle can't be verified, fall back to config_change (config-drift MEDIUM), NOT
// the audit-blinding CRITICAL. Live proof showed the old default fired CRITICAL on
// every benign diagnostic write (a real acr-diag-to-law ADDITION), which is alarm
// fatigue. Real removals are still caught via the requestbody-bearing BeginRequest
// event and the unambiguous diagnosticSettings/delete case.
func TestAzureDiagnosticSettingWriteUnreadableDefaultsConfigChange(t *testing.T) {
	entry := map[string]any{"resourceId": "/diag/setting1"}
	r := wantType(t, Azure("microsoft.insights/diagnosticSettings/write", entry), "config_change")
	p := decode(t, r, entry)
	if p["resource_name"] != "/diag/setting1" {
		t.Errorf("resource_name = %v", p["resource_name"])
	}
}

// TestAzureDiagnosticSettingWriteAllCategoriesDisabledAuditDisabled covers the
// mallcoppro-2627 hardening: a write that names a workspace but disables every
// log category routes nothing to the LAW — an audit-blinding evasion the old
// workspaceId-only check missed. Must escalate to audit_log_disabled.
func TestAzureDiagnosticSettingWriteAllCategoriesDisabledAuditDisabled(t *testing.T) {
	entry := map[string]any{
		"resourceId": "/diag/setting1",
		"properties": map[string]any{
			"requestbody": `{"properties":{"workspaceId":"/subscriptions/s/resourceGroups/nostr-relay-prod/providers/Microsoft.OperationalInsights/workspaces/law-nostr-relay-prod","logs":[{"category":"ContainerAppConsoleLogs","enabled":false},{"category":"ContainerAppSystemLogs","enabled":false}]}}`,
		},
	}
	wantType(t, Azure("Microsoft.Insights/diagnosticSettings/write", entry), "audit_log_disabled")
}

// TestAzureDiagnosticSettingRealCasingWriteCaughtLive pins a live-proof-caught
// bug: a real captured event from nostr-relay-prod's Activity Log (az monitor
// activity-log list -g nostr-relay-prod --offset 7d, 2026-07-21) has
// operationName.value "Microsoft.Insights/diagnosticSettings/write" (capital
// M, capital I) -- the pre-existing exact-lowercase match
// ("microsoft.insights/diagnosticSettings/write") never matched this and
// silently fell through to CatchAll in production. This test proves the CASING
// match works — the event is mapped, not dropped to CatchAll. Post-mallcoppro-2627
// a no-requestbody write maps to config_change (config-drift MEDIUM), not the
// CRITICAL audit-blinding alert; the point here is that the real PascalCase
// operationName is CAUGHT at all.
// Same casing-inconsistency class already proven for Microsoft.Network/
// dnszones (mallcoppro-d63).
func TestAzureDiagnosticSettingRealCasingWriteCaughtLive(t *testing.T) {
	entry := map[string]any{"resourceId": "/subscriptions/s/resourceGroups/nostr-relay-prod/providers/Microsoft.App/containerApps/nostr-relay-prod/providers/Microsoft.Insights/diagnosticSettings/relay-diag"}
	r := wantType(t, Azure("Microsoft.Insights/diagnosticSettings/write", entry), "config_change")
	p := decode(t, r, entry)
	if p["resource_name"] != entry["resourceId"] {
		t.Errorf("resource_name = %v", p["resource_name"])
	}
}

func TestAzureDiagnosticSettingRealCasingDeleteCaughtLive(t *testing.T) {
	entry := map[string]any{"resourceId": "/subscriptions/s/resourceGroups/nostr-relay-prod/providers/Microsoft.App/containerApps/nostr-relay-prod/providers/Microsoft.Insights/diagnosticSettings/relay-diag"}
	r := wantType(t, Azure("Microsoft.Insights/diagnosticSettings/delete", entry), "audit_trail_delete")
	p := decode(t, r, entry)
	if p["resource_name"] != entry["resourceId"] {
		t.Errorf("resource_name = %v", p["resource_name"])
	}
}

// --- GCP -------------------------------------------------------------------

func TestGCPSetIamPolicyFanOut(t *testing.T) {
	proto := map[string]any{
		"resourceName": "projects/p",
		"request": map[string]any{
			"policy": map[string]any{
				"bindings": []any{
					map[string]any{"role": "roles/owner", "members": []any{"user:evil@x.com"}},
				},
			},
		},
	}
	got := GCP("google.iam.admin.v1.SetIamPolicy", proto)
	// Must produce BOTH config-drift (iam_policy_attach) AND priv-escalation (role_assignment).
	cd := wantType(t, got, "iam_policy_attach")
	if decode(t, cd, proto)["resource_name"] != "projects/p" {
		t.Errorf("iam_policy_attach missing resource_name")
	}
	pe := wantType(t, got, "role_assignment")
	pep := decode(t, pe, proto)
	if pep["role"] != "roles/owner" || pep["target_user"] != "evil@x.com" {
		t.Errorf("role_assignment payload = %+v", pep)
	}
}

func TestGCPCreateServiceAccountUserCreated(t *testing.T) {
	proto := map[string]any{
		"request":  map[string]any{"accountId": "svc"},
		"response": map[string]any{"email": "svc@p.iam.gserviceaccount.com"},
	}
	r := wantType(t, GCP("google.iam.admin.v1.CreateServiceAccount", proto), "user_created")
	p := decode(t, r, proto)
	if p["principal_id"] != "svc@p.iam.gserviceaccount.com" {
		t.Errorf("principal_id = %v", p["principal_id"])
	}
}

func TestGCPStorageGetObjectExfil(t *testing.T) {
	proto := map[string]any{
		"resourceName":    "projects/_/buckets/b/objects/o",
		"requestMetadata": map[string]any{"requestSize": float64(2048)},
	}
	r := wantType(t, GCP("storage.objects.get", proto), "object_get")
	p := decode(t, r, proto)
	if bt, ok := p["bytes_transferred"].(float64); !ok || int64(bt) != 2048 {
		t.Errorf("bytes_transferred = %v", p["bytes_transferred"])
	}
}

func TestGCPDeleteSinkAuditTrailDelete(t *testing.T) {
	proto := map[string]any{"resourceName": "projects/p/sinks/audit"}
	r := wantType(t, GCP("google.logging.v2.ConfigServiceV2.DeleteSink", proto), "audit_trail_delete")
	if decode(t, r, proto)["resource_name"] != "projects/p/sinks/audit" {
		t.Errorf("resource_name wrong")
	}
}

// --- M365 ------------------------------------------------------------------

func TestM365LoginFailure(t *testing.T) {
	rec := map[string]any{"ClientIP": "5.5.5.5", "LogonError": "InvalidPassword"}
	r := wantType(t, M365("AzureActiveDirectory", "UserLoginFailed", rec), "login_failure")
	p := decode(t, r, rec)
	if p["ip"] != "5.5.5.5" || p["reason"] != "InvalidPassword" {
		t.Errorf("payload = %+v", p)
	}
}

func TestM365AddMemberToRole(t *testing.T) {
	rec := map[string]any{
		"ObjectId": "alice@corp.com",
		"ModifiedProperties": []any{
			map[string]any{"Name": "Role.DisplayName", "NewValue": "Global Administrator"},
		},
	}
	r := wantType(t, M365("AzureActiveDirectory", "Add member to role.", rec), "role_assignment")
	p := decode(t, r, rec)
	if p["role"] != "Global Administrator" {
		t.Errorf("role = %v", p["role"])
	}
}

func TestM365FileDownloadedExfil(t *testing.T) {
	rec := map[string]any{"FileSizeBytes": float64(500000), "ClientIP": "7.7.7.7", "ObjectId": "/sites/x/doc.xlsx"}
	r := wantType(t, M365("SharePoint", "FileDownloaded", rec), "file_download")
	p := decode(t, r, rec)
	if bt, ok := p["bytes_transferred"].(float64); !ok || int64(bt) != 500000 {
		t.Errorf("bytes_transferred = %v", p["bytes_transferred"])
	}
}

func TestM365ConsentExternalAccess(t *testing.T) {
	rec := map[string]any{
		"ObjectId": "app-123",
		"ModifiedProperties": []any{
			map[string]any{"Name": "ConsentContext.DisplayName", "NewValue": "Sketchy App"},
		},
	}
	r := wantType(t, M365("AzureActiveDirectory", "Consent to application.", rec), "org.add_outside_collaborator")
	p := decode(t, r, rec)
	if p["collaborator"] != "Sketchy App" {
		t.Errorf("collaborator = %v", p["collaborator"])
	}
}

// --- Okta ------------------------------------------------------------------

func TestOktaPrivilegeGrant(t *testing.T) {
	raw := map[string]any{
		"target": []any{
			map[string]any{"type": "AppRole", "displayName": "Super Admin"},
			map[string]any{"type": "User", "alternateId": "victim@corp.com"},
		},
	}
	r := wantType(t, Okta("user.account.privilege.grant", raw), "role_assignment")
	p := decode(t, r, raw)
	if p["role"] != "Super Admin" || p["target_user"] != "victim@corp.com" {
		t.Errorf("payload = %+v", p)
	}
}

func TestOktaMFADeactivate(t *testing.T) {
	raw := map[string]any{
		"target": []any{map[string]any{"type": "User", "alternateId": "bob@corp.com"}},
	}
	r := wantType(t, Okta("user.mfa.factor.deactivate", raw), "mfa_disabled")
	p := decode(t, r, raw)
	if p["target_user"] != "bob@corp.com" {
		t.Errorf("target_user = %v", p["target_user"])
	}
}

func TestOktaLoginWithGeo(t *testing.T) {
	raw := map[string]any{
		"client": map[string]any{
			"ipAddress":           "203.0.113.1",
			"geographicalContext": map[string]any{"country": "RU", "state": "Moscow"},
		},
	}
	r := wantType(t, Okta("user.session.start", raw), "login")
	p := decode(t, r, raw)
	if p["ip"] != "203.0.113.1" || p["geo"] != "RU/Moscow" {
		t.Errorf("payload = %+v", p)
	}
}

func TestOktaUnmappedCatchAll(t *testing.T) {
	r := wantType(t, Okta("user.account.unlock", map[string]any{}), CatchAll)
	if r.Type != CatchAll {
		t.Errorf("want catch-all")
	}
}

// PayloadJSON always carries the raw event under "raw" for recursive scanning by
// injection-probe / secrets-exposure.
func TestPayloadCarriesRaw(t *testing.T) {
	raw := map[string]any{"weird": "AKIAIOSFODNN7EXAMPLE"}
	r := Result{Type: "login", Payload: map[string]any{"action": "login"}}
	p := decode(t, r, raw)
	if _, ok := p["raw"]; !ok {
		t.Fatalf("payload missing raw key: %+v", p)
	}
}

// --- credential redaction (mallcoppro-132) ----------------------------------

// PayloadJSON must scrub STS session tokens out of stored raw payloads: this
// is the shape cmd/aws/s3trail.go passes as "raw" — the already-decoded inner
// CloudTrail record (not wrapped in a CloudTrailEvent string), so
// responseElements.credentials sits directly in the object tree.
func TestPayloadRedactsAssumeRoleCredentials(t *testing.T) {
	rec := map[string]any{
		"eventName": "AssumeRole",
		"responseElements": map[string]any{
			"credentials": map[string]any{
				"accessKeyId":  "ASIAEXAMPLE",
				"sessionToken": "FQoGZXIvYXdzEXAMPLETOKEN",
				"expiration":   "Jul 17, 2026 1:00:00 PM",
			},
		},
	}
	r := Result{Type: "role_assignment", Payload: map[string]any{"action": "AssumeRole"}}
	p := decode(t, r, rec)

	rawOut, ok := p["raw"].(map[string]any)
	if !ok {
		t.Fatalf("raw not a map: %T", p["raw"])
	}
	creds := dig(rawOut, "responseElements", "credentials")
	if creds == nil {
		t.Fatalf("responseElements.credentials missing from redacted raw: %+v", rawOut)
	}
	if creds["sessionToken"] != redactedValue {
		t.Errorf("sessionToken = %v, want %q", creds["sessionToken"], redactedValue)
	}
	if creds["accessKeyId"] != "ASIAEXAMPLE" {
		t.Errorf("accessKeyId = %v, want preserved", creds["accessKeyId"])
	}
	if creds["expiration"] != "Jul 17, 2026 1:00:00 PM" {
		t.Errorf("expiration = %v, want preserved", creds["expiration"])
	}
}

// Depth coverage + case-insensitivity + a different key (secretAccessKey), in
// a shape resembling a non-AWS connector record (array of nested events, as
// e.g. M365/Okta batches decode to) — proves the redaction walk is generic,
// not AWS-specific, and isn't fooled by key casing.
func TestPayloadRedactsCredentialsAtAnyDepth(t *testing.T) {
	raw := map[string]any{
		"batch": []any{
			map[string]any{
				"id": "evt-1",
				"nested": map[string]any{
					"deeper": map[string]any{
						"SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
						"SessionToken":    "AQoEXAMPLEH4aoAH0gNCAPy...",
						"accessKeyId":     "AKIAIOSFODNN7EXAMPLE",
					},
				},
			},
		},
	}
	r := Result{Type: "cloud_other", Payload: map[string]any{"action": "x"}}
	p := decode(t, r, raw)

	rawOut, ok := p["raw"].(map[string]any)
	if !ok {
		t.Fatalf("raw not a map: %T", p["raw"])
	}
	batch, ok := rawOut["batch"].([]any)
	if !ok || len(batch) != 1 {
		t.Fatalf("batch = %+v", rawOut["batch"])
	}
	deeper := dig(batch[0].(map[string]any), "nested", "deeper")
	if deeper == nil {
		t.Fatalf("nested.deeper missing: %+v", batch[0])
	}
	if deeper["SecretAccessKey"] != redactedValue {
		t.Errorf("SecretAccessKey = %v, want %q", deeper["SecretAccessKey"], redactedValue)
	}
	if deeper["SessionToken"] != redactedValue {
		t.Errorf("SessionToken = %v, want %q", deeper["SessionToken"], redactedValue)
	}
	if deeper["accessKeyId"] != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("accessKeyId = %v, want preserved", deeper["accessKeyId"])
	}
}

// The DEFAULT aws connector path (cmd/aws/main.go LookupEvents mode) builds
// rawMap with "CloudTrailEvent" as a STRING holding the full inner CloudTrail
// JSON document — not an already-decoded map, unlike the S3 org-trail path
// covered by TestPayloadRedactsAssumeRoleCredentials above. Prove the string
// is decoded, redacted, and re-encoded rather than passed through verbatim.
func TestPayloadRedactsCredentialsInsideCloudTrailEventString(t *testing.T) {
	inner := `{"eventName":"AssumeRole","responseElements":{"credentials":{` +
		`"accessKeyId":"ASIAEXAMPLE","sessionToken":"FQoGZXIvYXdzEXAMPLETOKEN",` +
		`"expiration":"Jul 17, 2026 1:00:00 PM"}}}`
	rawMap := map[string]any{"CloudTrailEvent": inner}

	r := Result{Type: "role_assignment", Payload: map[string]any{"action": "AssumeRole"}}
	b, err := r.PayloadJSON(rawMap)
	if err != nil {
		t.Fatalf("PayloadJSON: %v", err)
	}

	if strings.Contains(string(b), "FQoGZXIvYXdzEXAMPLETOKEN") {
		t.Fatalf("stored payload leaks live session token: %s", b)
	}
	if !strings.Contains(string(b), redactedValue) {
		t.Fatalf("stored payload missing %q: %s", redactedValue, b)
	}

	var p map[string]any
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	rawOut, ok := p["raw"].(map[string]any)
	if !ok {
		t.Fatalf("raw not a map: %T", p["raw"])
	}
	cteStr, ok := rawOut["CloudTrailEvent"].(string)
	if !ok {
		t.Fatalf("CloudTrailEvent not a string: %T", rawOut["CloudTrailEvent"])
	}

	var innerDoc map[string]any
	if err := json.Unmarshal([]byte(cteStr), &innerDoc); err != nil {
		t.Fatalf("re-encoded CloudTrailEvent not valid JSON: %v (%s)", err, cteStr)
	}
	creds := dig(innerDoc, "responseElements", "credentials")
	if creds == nil {
		t.Fatalf("responseElements.credentials missing from redacted inner doc: %+v", innerDoc)
	}
	if creds["sessionToken"] != redactedValue {
		t.Errorf("sessionToken = %v, want %q", creds["sessionToken"], redactedValue)
	}
	if creds["accessKeyId"] != "ASIAEXAMPLE" {
		t.Errorf("accessKeyId = %v, want preserved", creds["accessKeyId"])
	}
	if creds["expiration"] != "Jul 17, 2026 1:00:00 PM" {
		t.Errorf("expiration = %v, want preserved", creds["expiration"])
	}
}

// A CloudTrailEvent string that isn't valid JSON must pass through unchanged
// rather than being dropped or mangled.
func TestPayloadCloudTrailEventNonJSONPassesThrough(t *testing.T) {
	rawMap := map[string]any{"CloudTrailEvent": "not json at all"}
	r := Result{Type: "cloud_other", Payload: map[string]any{"action": "x"}}
	p := decode(t, r, rawMap)

	rawOut, ok := p["raw"].(map[string]any)
	if !ok {
		t.Fatalf("raw not a map: %T", p["raw"])
	}
	if rawOut["CloudTrailEvent"] != "not json at all" {
		t.Errorf("CloudTrailEvent = %v, want unchanged", rawOut["CloudTrailEvent"])
	}
}
