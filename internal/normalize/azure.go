package normalize

import (
	"encoding/json"
	"strings"
)

// CosmosRoleResolver resolves a Cosmos DB SQL role assignment's role name and
// principal ID via a supplementary ARM control-plane GET, for the case where
// the Activity Log's BeginRequest event carries no requestbody at ALL (see
// the sqlRoleAssignments cases below) -- unlike Microsoft.Authorization/
// roleAssignments/write and ContainerRegistry/registries/write, which DO
// carry a requestbody and never need this (mallcoppro-32e, live-verified
// 2026-07-21/27: a real Cosmos SQL RBAC grant's captured event has no
// requestbody under any observed field). resourceID is the sqlRoleAssignments
// resource ID from the Activity Log entry
// (".../databaseAccounts/<acct>/sqlRoleAssignments/<guid>"). ok is true only
// when at least the principal was resolved; a resolver that can't reach ARM
// or gets a non-200 must return ("", "", false) rather than erroring --
// enrichment is best-effort and must never fail the scan.
type CosmosRoleResolver func(resourceID string) (roleName, principalID string, ok bool)

// azureConfig holds Azure()'s optional supplementary-lookup configuration.
type azureConfig struct {
	cosmosRoleResolver CosmosRoleResolver
}

// AzureOption configures optional supplementary behavior for Azure(). Kept
// out of Azure()'s required signature (via variadic opts) so normalize.Azure
// stays pure/testable by default and every existing 2-arg caller keeps
// compiling unchanged.
type AzureOption func(*azureConfig)

// WithCosmosRoleResolver configures Azure() to fall back to a supplementary
// ARM GET (cmd/azure's resolveCosmosRole) when role/principal can't be
// extracted from the Activity Log entry itself. This is the one deliberate
// exception to "normalize-only": Baron authorized it (mallcoppro-32e) because
// without it, every real Cosmos SQL RBAC grant ships with an empty
// role/principal and priv-escalation can't attribute WHO got WHICH Cosmos
// data-plane role.
func WithCosmosRoleResolver(r CosmosRoleResolver) AzureOption {
	return func(c *azureConfig) { c.cosmosRoleResolver = r }
}

// Azure maps a raw Azure Activity Log entry to canonical mallcop events.
//
// opName is operationName.value (e.g. "Microsoft.Authorization/roleAssignments/write").
// entry is the JSON-decoded raw Activity Log entry. Azure puts the actor in
// "caller", the resource in "resourceId", and detail under "properties".
//
// opts is optional supplementary configuration (currently just
// WithCosmosRoleResolver); callers that don't need it pass none, and the
// function behaves exactly as before.
func Azure(opName string, entry map[string]any, opts ...AzureOption) []Result {
	cfg := &azureConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	props := subMap(entry, "properties")
	resourceID := mapStr(entry, "resourceId")
	caller := mapStr(entry, "caller")

	switch {
	case opName == "Microsoft.Authorization/roleAssignments/write":
		role := firstNonEmpty(mapStr(props, "roleDefinitionName"), mapStr(props, "roleDefinitionId"))
		principal := mapStr(props, "principalId")
		if rb := azureRequestBodyProps(props); rb != nil {
			role = firstNonEmpty(role, mapStr(rb, "roleDefinitionName"), mapStr(rb, "roleDefinitionId"))
			principal = firstNonEmpty(principal, mapStr(rb, "principalId"))
		}
		p := map[string]any{"action": "role_assignment"}
		set(p, "role", role)
		set(p, "role_name", role)
		set(p, "target_user", principal)
		set(p, "principal_id", principal)
		set(p, "resource_name", resourceID)
		return []Result{{Type: "role_assignment", Payload: p}}

	// roleAssignments/delete is the authorization-subversion mirror of write:
	// removing another principal's role assignment is just as much a control-
	// plane authorization change as granting one (denial-of-service against a
	// legitimate admin, or an attacker covering tracks by deleting a
	// competing grant). Mapped to the SAME "role_assignment" gate as write
	// (mallcoppro-c789 spec) rather than the pre-existing "iam_change", which
	// was a stale generic catch-all predating this item's authorization-
	// subversion scope. action is "remove_role_assignment" (not the raw
	// Azure "delete") so priv-escalation's isElevated() narrowing guard
	// (action-prefix "remove"/"revoke"/"delete_role" = benign narrowing, not
	// escalation) applies correctly instead of silently bypassing it.
	case opName == "Microsoft.Authorization/roleAssignments/delete":
		role := firstNonEmpty(mapStr(props, "roleDefinitionName"), mapStr(props, "roleDefinitionId"))
		principal := mapStr(props, "principalId")
		if rb := azureRequestBodyProps(props); rb != nil {
			role = firstNonEmpty(role, mapStr(rb, "roleDefinitionName"), mapStr(rb, "roleDefinitionId"))
			principal = firstNonEmpty(principal, mapStr(rb, "principalId"))
		}
		p := map[string]any{"action": "remove_role_assignment"}
		set(p, "role", role)
		set(p, "role_name", role)
		set(p, "target_user", principal)
		set(p, "principal_id", principal)
		set(p, "resource_name", resourceID)
		return []Result{{Type: "role_assignment", Payload: p}}

	case opName == "Microsoft.Authorization/roleDefinitions/write":
		p := map[string]any{}
		set(p, "resource_name", resourceID)
		set(p, "policy_name", mapStr(props, "roleName"))
		set(p, "change_description", "custom role definition written")
		return []Result{{Type: "iam_policy_create", Payload: p}}

	case opName == "Microsoft.Authorization/policyAssignments/write":
		p := map[string]any{}
		set(p, "resource_name", resourceID)
		set(p, "policy_name", firstNonEmpty(mapStr(props, "displayName"), mapStr(props, "policyDefinitionId")))
		set(p, "change_description", "policy assignment created")
		return []Result{{Type: "iam_policy_attach", Payload: p}}

	case opName == "Microsoft.ManagedIdentity/userAssignedIdentities/assign":
		principal := mapStr(props, "principalId")
		p := map[string]any{"action": "iam_change", "role": "ManagedIdentity"}
		set(p, "target_user", principal)
		set(p, "principal_id", principal)
		set(p, "resource_name", resourceID)
		return []Result{{Type: "iam_change", Payload: p}}

	case opName == "Microsoft.ManagedIdentity/userAssignedIdentities/write":
		p := map[string]any{"action": "service_principal_created"}
		set(p, "display_name", firstNonEmpty(mapStr(props, "displayName"), lastSegment(resourceID)))
		set(p, "principal_id", mapStr(props, "principalId"))
		return []Result{{Type: "service_principal_created", Payload: p}}

	// federatedIdentityCredentials/write attaches an external OIDC
	// issuer+subject trust to a managed identity -- the workload-identity-
	// federation abuse pattern (an external principal, e.g. a GitHub Actions
	// repo, becomes able to assume the identity with no secret exchange).
	// Paired with userAssignedIdentities/write above per the mallcoppro-c789
	// spec ("role_assignment or config_change"); config_change chosen since
	// this is a trust-boundary/perimeter configuration change, consistent
	// with how this file treats other boundary changes (DNS, ACR, Container
	// Apps ingress). Case-insensitive match: this is the same
	// Microsoft.ManagedIdentity provider family where `az provider operation
	// show` returns operation names lowercased, and Microsoft.App/
	// Microsoft.Network have both proven to emit inconsistent live casing
	// for their newer resource types (mallcoppro-d63) -- not independently
	// live-verified for this op (no federatedIdentityCredentials exist in
	// this subscription), so matched defensively.
	case strings.EqualFold(opName, "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write"):
		p := map[string]any{}
		set(p, "resource_name", resourceID)
		set(p, "change_description", "federated identity credential written: external OIDC trust attached to a managed identity")
		return []Result{{Type: "config_change", Payload: p}}

	case opName == "Microsoft.Directory/users/add" || opName == "Microsoft.AAD/users/write":
		p := map[string]any{"action": "user_created"}
		set(p, "display_name", firstNonEmpty(mapStr(props, "displayName"), mapStr(props, "objectId")))
		set(p, "principal_id", mapStr(props, "objectId"))
		return []Result{{Type: "user_created", Payload: p}}

	case opName == "Microsoft.Directory/groupMembers/add" || opName == "Microsoft.AAD/groups/members/write":
		member := mapStr(props, "userPrincipalName")
		p := map[string]any{"action": "org.add_member"}
		set(p, "member", member)
		set(p, "role", "Member")
		return []Result{{Type: "org.add_member", Payload: p}}

	case strings.Contains(opName, "domains/federation") || opName == "Microsoft.AAD/federationSettings/write":
		domain := firstNonEmpty(mapStr(props, "domainName"), lastSegment(resourceID))
		p := map[string]any{"action": "federation_settings_update"}
		set(p, "domain", domain)
		set(p, "domain_name", domain)
		return []Result{{Type: "federation_settings_update", Payload: p}}

	case opName == "Microsoft.Network/networkSecurityGroups/securityRules/write":
		p := map[string]any{}
		set(p, "resource_name", resourceID)
		set(p, "change_description", "NSG security rule modified")
		p["new_value"] = "rule changed"
		return []Result{{Type: "security_group_modify", Payload: p}}

	case opName == "Microsoft.Network/azureFirewalls/write" ||
		strings.Contains(opName, "firewallPolicies/ruleCollectionGroups/write"):
		p := map[string]any{}
		set(p, "resource_name", resourceID)
		set(p, "change_description", "firewall rule added")
		p["new_value"] = "rule added"
		return []Result{{Type: "firewall_rule_add", Payload: p}}

	// AUDIT-BLINDING: a diagnosticSettings write can either ADD/strengthen a
	// LAW-routed audit pipeline (benign) or REMOVE it (someone turning off the
	// monitor itself, mallcoppro-c789). Distinguished by whether the write's
	// resulting state still names a Log Analytics Workspace destination
	// (properties.workspaceId, per the documented diagnostic-setting resource
	// schema). When the toggle can't be read at all (no requestbody), default
	// to the audit-blinding alert: a missed audit-disable is worse than a
	// false-positive review of a benign logging addition.
	//
	// CASE-INSENSITIVE — LIVE-PROOF-CAUGHT BUG (mallcoppro-c789, 2026-07-21):
	// the pre-existing match here was the exact-lowercase string
	// "microsoft.insights/diagnosticSettings/write". A real captured event
	// from nostr-relay-prod's Activity Log (az monitor activity-log list -g
	// nostr-relay-prod --offset 7d) has operationName.value
	// "Microsoft.Insights/diagnosticSettings/write" -- capital M, capital I --
	// which NEVER matched, silently falling through to CatchAll in
	// production. This is the SAME casing-inconsistency class already proven
	// for Microsoft.Network/dnszones (mallcoppro-d63); fixed the same way.
	case strings.EqualFold(opName, "Microsoft.Insights/diagnosticSettings/write"):
		p := map[string]any{"config_key": "diagnosticSettings"}
		set(p, "resource_name", resourceID)
		// Only escalate to the audit-blinding alert (audit_log_disabled ->
		// config-drift CRITICAL) when the write's requestbody CONFIRMS the LAW
		// pipeline was removed or fully disabled. When the pipeline is intact,
		// or the state can't be read (the common Succeeded/EndRequest event
		// carries no requestbody), fall back to config_change (config-drift
		// MEDIUM) rather than crying wolf. mallcoppro-2627: the old default
		// fired CRITICAL on EVERY diagnosticSettings write -- including benign
		// monitoring ADDITIONS -- which is alarm fatigue that trains operators
		// to ignore the signal. Real removals are still caught two ways: the
		// paired BeginRequest event carries the requestbody, and an outright
		// deletion is the unambiguous diagnosticSettings/delete case below.
		typ := "config_change"
		desc := "diagnostic setting written; LAW pipeline intact or unverifiable from this Activity Log entry"
		if rb := azureRequestBodyProps(props); rb != nil && removesLAWPipeline(rb) {
			typ = "audit_log_disabled"
			desc = "audit log diagnostic setting modified: LAW pipeline removed or all categories disabled"
		}
		set(p, "change_description", desc)
		return []Result{{Type: typ, Payload: p}}

	// Case-insensitive for the same live-proven reason as the write case above.
	case strings.EqualFold(opName, "Microsoft.Insights/diagnosticSettings/delete"):
		p := map[string]any{}
		set(p, "resource_name", resourceID)
		set(p, "change_description", "diagnostic setting deleted")
		return []Result{{Type: "audit_trail_delete", Payload: p}}

	case opName == "Microsoft.Security/securityContacts/write" || opName == "Microsoft.Security/pricings/write":
		p := map[string]any{"config_key": lastSegment(resourceID)}
		set(p, "resource_name", resourceID)
		set(p, "change_description", "Defender config changed")
		return []Result{{Type: "config_change", Payload: p}}

	// Wildcarded across every Microsoft.KeyVault/vaults/secrets/* operation
	// (read, write, delete, backup/purge/recover/restore/setSecret/
	// getSecret/readMetadata/update actions — confirmed exhaustively via `az
	// provider operation show --namespace Microsoft.KeyVault`), not just
	// read/getSecret: a WRITE planting a new secret, or a DELETE/purge
	// destroying one, is exactly as much "someone touched a secret" as a read
	// for this authorization-subversion surface (mallcoppro-c789 spec).
	case strings.HasPrefix(strings.ToLower(opName), "microsoft.keyvault/vaults/secrets/"):
		p := map[string]any{"action": "secret_access"}
		set(p, "target", resourceID)
		set(p, "resource", resourceID)
		set(p, "resource_id", resourceID)
		return []Result{{Type: "secret_access", Payload: p}}

	case strings.EqualFold(opName, "Microsoft.KeyVault/vaults/write"):
		p := map[string]any{"config_key": "keyVaultAccessPolicies"}
		set(p, "resource_name", resourceID)
		set(p, "change_description", "Key Vault policy modified")
		return []Result{{Type: "config_change", Payload: p}}

	case opName == "Microsoft.Storage/storageAccounts/listKeys/action":
		p := map[string]any{"action": "secret_access"}
		set(p, "target", resourceID)
		set(p, "resource_id", resourceID)
		return []Result{{Type: "secret_access", Payload: p}}

	case strings.HasPrefix(opName, "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"):
		p := map[string]any{"action": "bulk_read"}
		set(p, "target", resourceID)
		set(p, "resource", resourceID)
		opCount, _ := azFloat(props, "operationCount")
		p["files_accessed"] = int(opCount)
		p["resource_count"] = int(opCount)
		p["bytes_transferred"] = int64(0)
		set(p, "destination", firstNonEmpty(caller, mapStr(props, "clientIP")))
		return []Result{{Type: "bulk_read", Payload: p}}

	case opName == "Microsoft.Compute/virtualMachines/read":
		p := map[string]any{"action": "vm_access"}
		set(p, "target", resourceID)
		set(p, "resource_id", resourceID)
		return []Result{{Type: "vm_access", Payload: p}}

	case opName == "Microsoft.ContainerRegistry/registries/pull" ||
		opName == "Microsoft.ContainerRegistry/registries/repositories/content/read":
		p := map[string]any{"action": "registry_access"}
		set(p, "target", resourceID)
		set(p, "resource_id", resourceID)
		return []Result{{Type: "registry_access", Payload: p}}

	case opName == "Microsoft.Sql/servers/databases/export/action":
		p := map[string]any{"resource_count": 1}
		set(p, "destination", firstNonEmpty(mapStr(props, "storageUri"), resourceID))
		p["bytes_transferred"] = int64(0)
		return []Result{{Type: "data_export", Payload: p}}

	case opName == "Microsoft.Sql/servers/databases/read":
		p := map[string]any{"action": "database_access"}
		set(p, "target", resourceID)
		set(p, "resource_id", resourceID)
		return []Result{{Type: "database_access", Payload: p}}

	case strings.HasPrefix(opName, "Microsoft.AAD/conditionalAccessPolicies/"):
		p := map[string]any{"config_key": "conditionalAccessPolicy"}
		set(p, "resource_name", resourceID)
		set(p, "change_description", "Conditional Access / MFA policy modified or deleted")
		return []Result{{Type: "mfa_requirement_removed", Payload: p}}

	case opName == "Microsoft.Subscription/subscriptions/write" ||
		opName == "Microsoft.Management/managementGroups/subscriptions/write":
		p := map[string]any{"action": "admin_action", "role": "SubscriptionOwner"}
		set(p, "target_user", caller)
		return []Result{{Type: "admin_action", Payload: p}}

	// --- relay-infra control plane (Microsoft.App / Container Apps) --------
	//
	// Confirmed live (az rest against the Activity Log API for
	// nostr-relay-prod, 2026-07-20): Azure represents a custom-hostname bind
	// as an ORDINARY containerApps/write PATCH (the customDomains change
	// rides in the write body) — there is no separate "hostname op" to match.
	// A captured real event showed exactly this: a containerApps/write whose
	// properties.statusCode was "BadRequest" with statusMessage.error.code
	// "InvalidCustomHostNameValidation" (missing TXT record for
	// asuid.relay.dontguess.ai). So one case covers both plain config changes
	// and hostname-bind attempts/failures.
	case opName == "Microsoft.App/containerApps/write" || opName == "Microsoft.App/managedEnvironments/write":
		p := map[string]any{}
		set(p, "resource_name", resourceID)
		set(p, "change_description", "Container Apps resource written: "+opName)
		return []Result{{Type: "config_change", Payload: p}}

	case opName == "Microsoft.App/containerApps/listSecrets/action":
		p := map[string]any{"action": "secret_access"}
		set(p, "target", resourceID)
		set(p, "resource_id", resourceID)
		return []Result{{Type: "secret_access", Payload: p}}

	// managedCertificates write/delete is the custom-domain TLS cert surface:
	// an attacker who can mint/replace the managed cert for the relay's
	// custom domain can intercept or re-point TLS traffic even without a DNS
	// change. Case-insensitive (see isAzureManagedCertChange doc) — same
	// casing hazard class already proven live for Microsoft.Network/dnszones
	// (mallcoppro-d63), not independently live-verified for this op (no
	// managedCertificates resources exist in this subscription).
	case isAzureManagedCertChange(opName):
		p := map[string]any{}
		set(p, "resource_name", resourceID)
		set(p, "change_description", "Container Apps managed certificate change: "+opName)
		return []Result{{Type: "config_change", Payload: p}}

	// --- relay-infra data plane (Microsoft.DocumentDB / Cosmos DB) ----------
	//
	// disableLocalAuth toggled OFF re-enables Cosmos master-key auth on an
	// account meant to be AAD-only -- a classic authorization-perimeter
	// downgrade. LIVE-VERIFIED (az rest against nostr-relay-prod's Activity
	// Log, 2026-07-21): the Administrative "EndRequest" event Azure actually
	// retains for this op carries NO request body at all (properties is just
	// {entity, eventCategory, hierarchy, message}); only a paired
	// "BeginRequest" event (not always captured/paginated the same way) would
	// carry it, as a JSON-ENCODED STRING under properties.requestbody. Per
	// the item spec's own escape hatch: when the toggle isn't reliably
	// readable, stay on config_change and note the limitation rather than
	// inventing a distinct gate for a field that's usually absent.
	case opName == "Microsoft.DocumentDB/databaseAccounts/write":
		p := map[string]any{}
		set(p, "resource_name", resourceID)
		desc := "Cosmos DB account configuration changed (disableLocalAuth toggle not reliably readable from this Activity Log entry)"
		if rb := azureRequestBodyProps(props); rb != nil {
			if dla, ok := rb["disableLocalAuth"].(bool); ok && !dla {
				desc = "Cosmos DB disableLocalAuth turned OFF -- AAD-only authorization weakened to allow key-based auth"
			} else {
				desc = "Cosmos DB account configuration changed"
			}
		}
		set(p, "change_description", desc)
		return []Result{{Type: "config_change", Payload: p}}

	// sqlRoleAssignments/write grants a Cosmos DB SQL RBAC role to a
	// principal — the Cosmos-native analog of Microsoft.Authorization/
	// roleAssignments/write. It fans out exactly like the GCP SetIamPolicy
	// mapping: an iam_policy_attach for config-drift (a policy object was
	// attached) AND a role_assignment for priv-escalation (a principal's
	// effective access widened) — unconditionally, since Cosmos SQL role
	// assignments have no "unprivileged" tier the way GCP bindings do.
	case opName == "Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/write":
		principal := mapStr(props, "principalId")
		role := firstNonEmpty(mapStr(props, "roleDefinitionName"), mapStr(props, "roleDefinitionId"))
		if rb := azureRequestBodyProps(props); rb != nil {
			role = firstNonEmpty(role, mapStr(rb, "roleDefinitionName"), mapStr(rb, "roleDefinitionId"))
			principal = firstNonEmpty(principal, mapStr(rb, "principalId"))
		}
		// mallcoppro-32e: the Cosmos sqlRoleAssignments BeginRequest event
		// carries NO requestbody at all (unlike roleAssignments/write and
		// ContainerRegistry/registries/write, which do) -- role/principal
		// ship empty for every real grant with only the reads above. When a
		// resolver is configured and either field is still unresolved, make a
		// supplementary ARM GET on the assignment resource. Nil resolver or
		// ok=false keeps today's best-effort empty behavior (no regression).
		if (role == "" || principal == "") && cfg.cosmosRoleResolver != nil {
			if rn, pid, ok := cfg.cosmosRoleResolver(resourceID); ok {
				role = firstNonEmpty(role, rn)
				principal = firstNonEmpty(principal, pid)
			}
		}
		cd := map[string]any{"action": "role_assignment"}
		set(cd, "resource_name", resourceID)
		set(cd, "policy_name", role)
		set(cd, "change_description", "Cosmos DB SQL role assignment written")
		pe := map[string]any{"action": "role_assignment"}
		set(pe, "role", role)
		set(pe, "role_name", role)
		set(pe, "target_user", principal)
		set(pe, "principal_id", principal)
		set(pe, "resource_name", resourceID)
		return []Result{
			{Type: "iam_policy_attach", Payload: cd},
			{Type: "role_assignment", Payload: pe},
		}

	// sqlRoleAssignments/delete: same fan-out as write per the mallcoppro-c789
	// spec. Unlike Authorization/roleAssignments/delete (which narrows
	// access, hence action "remove_role_assignment" there), a Cosmos SQL role
	// assignment delete still fans out to iam_policy_attach + role_assignment
	// literally as specified -- deleting authorization state on the relay's
	// data-plane database is itself worth a config-drift/priv-escalation
	// signal (e.g. an attacker removing a legitimate operator's access, or
	// erasing evidence of a role grant).
	case opName == "Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/delete":
		principal := mapStr(props, "principalId")
		role := firstNonEmpty(mapStr(props, "roleDefinitionName"), mapStr(props, "roleDefinitionId"))
		if rb := azureRequestBodyProps(props); rb != nil {
			role = firstNonEmpty(role, mapStr(rb, "roleDefinitionName"), mapStr(rb, "roleDefinitionId"))
			principal = firstNonEmpty(principal, mapStr(rb, "principalId"))
		}
		// See the /write case above (mallcoppro-32e): same supplementary-GET
		// fallback, since the delete's BeginRequest event is equally bodyless.
		if (role == "" || principal == "") && cfg.cosmosRoleResolver != nil {
			if rn, pid, ok := cfg.cosmosRoleResolver(resourceID); ok {
				role = firstNonEmpty(role, rn)
				principal = firstNonEmpty(principal, pid)
			}
		}
		cd := map[string]any{"action": "role_assignment"}
		set(cd, "resource_name", resourceID)
		set(cd, "policy_name", role)
		set(cd, "change_description", "Cosmos DB SQL role assignment deleted")
		pe := map[string]any{"action": "remove_role_assignment"}
		set(pe, "role", role)
		set(pe, "role_name", role)
		set(pe, "target_user", principal)
		set(pe, "principal_id", principal)
		set(pe, "resource_name", resourceID)
		return []Result{
			{Type: "iam_policy_attach", Payload: cd},
			{Type: "role_assignment", Payload: pe},
		}

	// listKeys/readonlykeys/regenerateKey are all Cosmos master-key retrieval
	// or rotation actions -- the same secret_access surface. regenerateKey op
	// name confirmed via `az provider operation show --namespace
	// Microsoft.DocumentDB` (Microsoft.DocumentDB/databaseAccounts/regenerateKey/action).
	case opName == "Microsoft.DocumentDB/databaseAccounts/listKeys/action" ||
		opName == "Microsoft.DocumentDB/databaseAccounts/readonlykeys/action" ||
		opName == "Microsoft.DocumentDB/databaseAccounts/regenerateKey/action":
		p := map[string]any{"action": "secret_access"}
		set(p, "target", resourceID)
		set(p, "resource_id", resourceID)
		return []Result{{Type: "secret_access", Payload: p}}

	// --- relay-infra supply chain (Microsoft.ContainerRegistry) -------------

	// registries/write is the ACR resource's own config surface (admin user
	// toggle, network rules, SKU, replication) — distinct from
	// registries/push/write (an image push) below. Absorbs mallcoppro-386.
	// Live-verified: `az monitor activity-log list -g nostr-relay-prod
	// --offset 7d` shows real registries/write events on acrnostrrelayprod.
	case opName == "Microsoft.ContainerRegistry/registries/write":
		p := map[string]any{}
		set(p, "resource_name", resourceID)
		set(p, "change_description", "Container Registry configuration changed (admin user, network rules, SKU, or replication)")
		return []Result{{Type: "config_change", Payload: p}}
	//
	// A registry push is a directly-authored artifact landing in the supply
	// chain — the closest fit in dependency-tamper's fixed vocabulary is
	// "dependency_add" with Direct: true (not a transitive lock-file change),
	// which also lets dependency-tamper's Rule 4 (direct-add check) evaluate.
	case opName == "Microsoft.ContainerRegistry/registries/push/write":
		repo := firstNonEmpty(mapStr(props, "repository"), lastSegment(resourceID))
		p := map[string]any{"action": "registry_push"}
		set(p, "package", repo)
		set(p, "ecosystem", "docker")
		set(p, "new_version", mapStr(props, "tag"))
		set(p, "registry", lastSegment(resourceID))
		p["direct"] = true
		return []Result{{Type: "dependency_add", Payload: p}}

	// --- relay-infra domain surface (Microsoft.Network/dnszones) ------------
	//
	// Record-set write/delete on a DNS zone is the domain-takeover surface for
	// relay.moot.pub (moot-rg) / relay.3dl.network (rg-dns): an attacker who
	// can rewrite an A/CNAME/TXT record can redirect or hijack the relay
	// hostname. Matched case-insensitively: a live capture (az monitor
	// activity-log list against moot-rg / rg-dns, 2026-07-20) showed the SAME
	// logical operation emitted with inconsistent casing across events
	// ("Microsoft.Network/dnsZones/A/write" vs "Microsoft.Network/dnszones/write"
	// for a zone-level op in the same subscription) — a case-sensitive switch
	// would silently drop half of these in production. Deliberately scoped to
	// RECORD-set ops only (not zone-level create/delete, dnssecConfigs, or
	// diagnosticSettings, which also end in "/write" under the same prefix).
	case isAzureDNSRecordChange(opName):
		p := map[string]any{"config_key": "dnsRecordSet"}
		set(p, "resource_name", resourceID)
		set(p, "change_description", "DNS record set change: "+opName)
		return []Result{{Type: "config_change", Payload: p}}
	}

	return []Result{{Type: CatchAll, Payload: map[string]any{"action": opName}}}
}

// azureDNSRecordTypes are the DNS record-set resource-type segments Azure
// emits under Microsoft.Network/dnszones/<TYPE>/write|delete (verified against
// the live provider operation list: az provider operation show --namespace
// Microsoft.Network, plus a live Activity Log capture on moot-rg / rg-dns).
var azureDNSRecordTypes = []string{"a", "aaaa", "cname", "mx", "txt", "ns", "ptr", "srv", "caa", "ds", "soa", "tlsa"}

// isAzureDNSRecordChange reports whether opName is a per-record write or
// delete under Microsoft.Network/dnszones/<TYPE>/ — deliberately excluding the
// zone-level write/delete (creating/deleting the zone resource itself, which
// has no record-type segment) and any other dnszones sub-path
// (dnssecConfigs/*, providers/Microsoft.Insights/diagnosticSettings/*) that
// also happens to end in "/write" or "/delete". Case-insensitive: Azure's own
// Activity Log casing for this provider is not consistent (see the case
// comment above).
func isAzureDNSRecordChange(opName string) bool {
	lower := strings.ToLower(opName)
	for _, rt := range azureDNSRecordTypes {
		if lower == "microsoft.network/dnszones/"+rt+"/write" || lower == "microsoft.network/dnszones/"+rt+"/delete" {
			return true
		}
	}
	return false
}

// azureManagedCertOps are the managedCertificates operation-name suffixes
// (lowercase, per `az provider operation show --namespace Microsoft.App`
// which returns this newer resource-type family lowercased) this connector
// treats as a perimeter change.
var azureManagedCertOps = []string{
	"microsoft.app/managedenvironments/managedcertificates/write",
	"microsoft.app/managedenvironments/managedcertificates/delete",
}

// isAzureManagedCertChange reports whether opName is a managed-certificate
// write or delete under Microsoft.App/managedEnvironments/managedCertificates,
// matched case-insensitively. Azure's Microsoft.App provider has already
// proven (via Microsoft.Network/dnszones, mallcoppro-d63) to emit
// inconsistent live casing for its resource-type segments; this op family
// hasn't been independently live-verified (no managedCertificates resources
// exist in this subscription yet), so it is matched defensively rather than
// assuming the documented PascalCase form holds.
func isAzureManagedCertChange(opName string) bool {
	lower := strings.ToLower(opName)
	for _, op := range azureManagedCertOps {
		if lower == op {
			return true
		}
	}
	return false
}

// azureRequestBodyProps decodes properties.requestbody -- the JSON-ENCODED
// STRING Azure Activity Log's "BeginRequest" events carry the write payload
// under -- into its nested "properties" object, when present.
//
// LIVE-VERIFIED (az rest against nostr-relay-prod's real Activity Log,
// 2026-07-21, covering roleAssignments/write, sqlRoleAssignments/write,
// databaseAccounts/write, and ContainerRegistry registries/write): the
// Administrative-category "EndRequest" event -- the one carrying the
// terminal "Succeeded" status, i.e. the event most naturally associated with
// "this action completed" -- exposes NO request detail whatsoever;
// properties is just {entity, eventCategory, hierarchy, message,
// statusCode}. Only the PAIRED "BeginRequest" event (same operationId,
// earlier eventTimestamp, status "Started") carries the actual write body,
// and only as this JSON-encoded string -- keyed by roleDefinitionId (a raw
// GUID; roleDefinitionName never appears in ANY live-captured event) for
// authorization writes. This mirrors awsInner()'s handling of AWS's
// CloudTrailEvent string field (aws.go) -- same idiom, different provider.
//
// Both events flow through this connector independently (cmd/azure/main.go's
// normalizeEntry has no eventName filter), so a caller that reads ONLY flat
// properties fields will get an empty role/principal on BOTH resulting
// mallcop events for a real production roleAssignments/write. Every case in
// this file that needs role/principal detail tries flat properties FIRST,
// then falls back to this function -- additive, so synthetic
// flat-properties test fixtures (this package's existing convention) are
// unaffected.
//
// Returns nil when requestbody is absent or unparseable, so callers can
// treat that as "not reliably readable" -- the same class of gap the
// mallcoppro-c789 spec explicitly calls out for Cosmos disableLocalAuth (see
// the databaseAccounts/write case above) and extends to diagnosticSettings'
// LAW-pipeline check.
func azureRequestBodyProps(props map[string]any) map[string]any {
	raw := mapStr(props, "requestbody")
	if raw == "" {
		return nil
	}
	var body struct {
		Properties map[string]any `json:"properties"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		return nil
	}
	return body.Properties
}

// removesLAWPipeline reports whether a diagnostic-setting write body's
// resulting state names NO Log Analytics Workspace destination
// (properties.workspaceId empty/absent) -- i.e. the write leaves the audit
// pipeline blind. Based on the documented Azure diagnostic-setting resource
// schema; NOT independently live-verified (no diagnosticSettings resources
// are provisioned in this subscription -- confirmed via `az monitor
// diagnostic-settings list`, empty result). See the c789 progress note for
// the follow-up to verify once a real diagnosticSettings resource exists.
// removesLAWPipeline reports whether a diagnostic-setting write leaves the audit
// pipeline blinded — i.e. it no longer routes to a Log Analytics Workspace, OR
// it names a workspace but every log category is disabled (routing nowhere
// useful). mallcoppro-2627: the old check only tested workspaceId=="" and so
// treated any non-empty workspaceId as "intact", missing the all-categories-
// disabled evasion and forcing the write case to over-default to CRITICAL.
func removesLAWPipeline(rb map[string]any) bool {
	if mapStr(rb, "workspaceId") == "" {
		return true
	}
	logs, ok := rb["logs"].([]any)
	if !ok || len(logs) == 0 {
		// Workspace present, no readable log-category config — assume intact.
		return false
	}
	for _, l := range logs {
		lm, ok := l.(map[string]any)
		if !ok {
			continue
		}
		if enabled, ok := lm["enabled"].(bool); ok && enabled {
			return false // at least one category still flowing to the LAW
		}
	}
	return true // workspace named but every category disabled — blinded
}

// lastSegment returns the final path segment of a slash-delimited string.
func lastSegment(s string) string {
	if s == "" {
		return ""
	}
	parts := strings.Split(s, "/")
	return parts[len(parts)-1]
}

func azFloat(m map[string]any, k string) (float64, bool) {
	if m == nil {
		return 0, false
	}
	if v, ok := m[k].(float64); ok {
		return v, true
	}
	return 0, false
}
