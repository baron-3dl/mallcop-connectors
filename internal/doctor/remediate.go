package doctor

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Remediate returns the RANKED, narrowest-first fix list for the diagnosis
// Diagnose most recently produced (design §6 safety property 2: never a single
// broad "just in case" grant).
//
// TRUST BOUNDARY: every option is TEXT. This process never runs any of it and
// never asks for the rights that would let it (design §6, hard). The operator
// reads BlastRadius, optionally runs DryRun, and decides.
//
// The signature matches the kernel's `Remediate func(Diagnosis) []RemediationOption`
// exactly; the structured scope facts come from the assessment Diagnose stored,
// so a command is never scoped by re-parsing an English sentence.
func (a *AzureSP) Remediate(d Diagnosis) []RemediationOption {
	if a.last == nil || a.last.diagnosis != d {
		// Remediate called without (or out of step with) a Diagnose. Emit
		// nothing rather than a command scoped from stale evidence.
		return nil
	}
	opts := a.remediateFor(*a.last)
	return a.applyStaleness(opts)
}

func (a *AzureSP) remediateFor(as assessment) []RemediationOption {
	switch as.def {
	case defHealthy, defUnknown, defIdentityUnreadable:
		// Nothing to rank: healthy needs no remediation, and a GRANT-MISS by
		// definition has no mapped fix (design §4 — the miss IS the output).
		return nil
	case defNoCredentials:
		return a.remediateNoCredentials()
	case defWrongPrincipal:
		return a.remediateWrongPrincipal(as)
	case defUserTokenInHeadlessConnector:
		return a.remediateUserToken(as)
	case defTokenExpired, defTokenAudienceMismatch:
		return nil
	case defResourceContextMode:
		return a.remediateResourceContext(as)
	case defMissingWorkspaceGrant:
		return a.remediateMissingWorkspaceGrant(as)
	case defMissingResourceRead:
		return a.remediateMissingResourceRead(as)
	case defAmbiguousDenial:
		// Ambiguous: the alternate-scope probe could not tell the two
		// deficiencies apart, so emit BOTH ladders — interleaved so the result
		// is still globally narrowest-first, not two ladders stapled together.
		// The lowered Diagnosis confidence tells the operator it is a choice.
		return interleaveNarrowestFirst(a.remediateResourceContext(as), a.remediateMissingWorkspaceGrant(as))
	case defARMAuthorizationFailed:
		return a.remediateARMAuthorizationFailed(as)
	}
	return nil
}

func (a *AzureSP) remediateNoCredentials() []RemediationOption {
	return []RemediationOption{{
		Command: ShellCommand(
			"export AZURE_TENANT_ID=<tenant-guid> AZURE_CLIENT_ID=<app-id> AZURE_CLIENT_SECRET=<secret>  " +
				"# or set them as repository secrets on the workflow that runs this connector"),
		BlastRadius: "Grants nothing. This only tells the connector which existing service principal to " +
			"authenticate as; it creates no identity and no permission.",
		KnownIssues: []string{
			"Set these where the connector runs (CI secret store), not in a file that gets committed.",
		},
	}}
}

func (a *AzureSP) remediateWrongPrincipal(as assessment) []RemediationOption {
	got := as.evidence.Identity
	opts := []RemediationOption{{
		// NARROWEST: grants nothing at all. Re-point the credential.
		Command: ShellCommand(fmt.Sprintf(
			"az ad sp show --id %s --query \"{displayName:displayName,appId:appId,objectId:id}\" -o json  "+
				"# confirm which principal your AZURE_CLIENT_ID/AZURE_CLIENT_SECRET resolve to, then replace them "+
				"with the credentials of %s", quoteArg(got.OID), a.Expected.label())),
		BlastRadius: "Read-only. This reads one directory entry and grants no permission to anyone. " +
			"The fix itself is swapping which credential the connector runs with — no new access is created.",
		KnownIssues: []string{
			"An opaque client-id/secret pair gives no hint which principal it belongs to; this is exactly why the " +
				"doctor decodes the token's oid claim locally instead of making you inject a diagnostic step into CI.",
		},
		DryRun: dryRun(fmt.Sprintf("az ad sp show --id %s -o table", quoteArg(got.OID))),
	}}

	// BROADER alternative: keep the credential you have and grant IT the role.
	// Ranked second because it widens the blast radius of a principal the
	// operator did not intend to use here.
	if scope := a.Target.workspaceScope(); scope != "" && got.OID != "" {
		opts = append(opts, a.logAnalyticsReaderOption(got.OID, scope,
			fmt.Sprintf("Lets the principal you are CURRENTLY authenticating as (objectId %s) query every table in "+
				"workspace %s. Broader than option 1, which grants nothing — only choose this if this principal, "+
				"not %s, is the one you meant to run as.",
				got.OID, a.Target.WorkspaceName, a.Expected.label())))
	}
	return opts
}

func (a *AzureSP) remediateUserToken(as assessment) []RemediationOption {
	return []RemediationOption{{
		Command: ShellCommand(
			"export AZURE_TENANT_ID=<tenant-guid> AZURE_CLIENT_ID=<service-principal-app-id> " +
				"AZURE_CLIENT_SECRET=<service-principal-secret>  " +
				"# replace the interactive/user credential this connector is currently using"),
		BlastRadius: "Grants nothing. It switches the connector from a human user identity to the service " +
			"principal the grants were actually made to.",
		KnownIssues: []string{
			fmt.Sprintf("The connector is currently running as objectId %s, which is a user, not an app.",
				as.evidence.Identity.OID),
			"User tokens expire and can be broken by an MFA or conditional-access policy change; a headless " +
				"connector running on one will fail unpredictably.",
		},
	}}
}

// remediateResourceContext is the ladder for the headline 2026-07-27 failure.
// Option 1 changes ONE workspace setting and grants no principal anything new.
// Option 2 grants a real role and is therefore ranked second.
func (a *AzureSP) remediateResourceContext(as assessment) []RemediationOption {
	rg, ws := a.Target.ResourceGroup, a.Target.WorkspaceName
	var opts []RemediationOption

	if rg != "" && ws != "" {
		opt := RemediationOption{
			Command: ShellCommand(fmt.Sprintf(
				"az monitor log-analytics workspace update --resource-group %s --workspace-name %s "+
					"--set properties.features.enableLogAccessUsingOnlyResourcePermissions=false",
				quoteArg(rg), quoteArg(ws))),
			BlastRadius: fmt.Sprintf(
				"Switches workspace %s to workspace-context access. Principals that ALREADY hold a "+
					"workspace-scoped Log Analytics Reader role on it can then run queries against every table "+
					"in it. It grants no role to anyone, and changes access to no other resource.", ws),
			KnownIssues: []string{
				"Observed live on 2026-07-27 (example-project prod): in resource-context mode a workspace-scoped " +
					"Log Analytics Reader assignment already existed and was silently ignored — the query still " +
					"returned 403 InsufficientAccessError. This setting, not the role, was the deficiency.",
				"ARM/AAD propagation can take several minutes; a Confirm run immediately after may still see 403.",
			},
			DryRun: a.accessModeDryRun(as),
		}
		opts = append(opts, opt)
	}

	// Second, broader rung: leave the workspace in resource-context mode and
	// give the principal read on the RESOURCES whose logs it needs — which is
	// what resource-context mode actually evaluates.
	if oid := as.evidence.Identity.OID; oid != "" {
		if scope := a.Target.resourceGroupScope(); scope != "" {
			opts = append(opts, RemediationOption{
				Command: ShellCommand(fmt.Sprintf(
					"az role assignment create --assignee %s --role %s --scope %s",
					quoteArg(oid), quoteArg("Reader"), quoteArg(scope))),
				BlastRadius: fmt.Sprintf(
					"Lets objectId %s read the configuration and metadata of EVERY resource in resource group %s, "+
						"not just this workspace. Broader than option 1 — prefer option 1 unless you specifically "+
						"want to keep resource-context access mode.", oid, a.Target.ResourceGroup),
				KnownIssues: []string{
					"Resource-context mode authorizes a workspace query from the caller's permissions on the " +
						"LOGGED RESOURCES, not on the workspace — which is why a workspace-scoped grant does nothing here.",
				},
				DryRun: dryRun(fmt.Sprintf(
					"az role assignment list --assignee %s --scope %s --include-inherited -o table",
					quoteArg(oid), quoteArg(scope))),
			})
		}
	}
	return opts
}

// accessModeDryRun builds a genuine side-effect-free ARM `--what-if` preview of
// the access-mode change when the probe learned the workspace's location (ARM
// what-if needs a template, and a template needs a location). When it did not,
// it degrades to a read-only preview of the value about to change rather than
// emitting a command with a placeholder the operator has to guess at.
func (a *AzureSP) accessModeDryRun(as assessment) *ShellCommand {
	rg, ws := a.Target.ResourceGroup, a.Target.WorkspaceName
	loc := ""
	if as.evidence.Workspace != nil {
		loc = as.evidence.Workspace.Location
	}
	if loc == "" {
		return dryRun(fmt.Sprintf(
			"az monitor log-analytics workspace show --resource-group %s --workspace-name %s "+
				"--query \"features.enableLogAccessUsingOnlyResourcePermissions\"",
			quoteArg(rg), quoteArg(ws)))
	}

	tmpl := map[string]any{
		"$schema":        "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
		"contentVersion": "1.0.0.0",
		"resources": []any{map[string]any{
			"type":       "Microsoft.OperationalInsights/workspaces",
			"apiVersion": workspaceAPIVersion,
			"name":       ws,
			"location":   loc,
			"properties": map[string]any{
				"features": map[string]any{
					"enableLogAccessUsingOnlyResourcePermissions": false,
				},
			},
		}},
	}
	// Marshal errors are impossible for this literal; ignoring one would still
	// only cost the dry run, never correctness of the emitted fix.
	b, err := json.Marshal(tmpl)
	if err != nil {
		return nil
	}
	return dryRun(fmt.Sprintf(
		"printf %s > /tmp/mallcop-doctor-accessmode.json && "+
			"az deployment group create --resource-group %s --name mallcop-doctor-accessmode "+
			"--template-file /tmp/mallcop-doctor-accessmode.json --what-if",
		quoteArg(string(b)), quoteArg(rg)))
}

func (a *AzureSP) remediateMissingWorkspaceGrant(as assessment) []RemediationOption {
	oid := as.evidence.Identity.OID
	scope := a.Target.workspaceScope()
	if oid == "" || scope == "" {
		return nil
	}
	opts := []RemediationOption{a.logAnalyticsReaderOption(oid, scope, fmt.Sprintf(
		"Lets objectId %s run queries against every table in workspace %s and read that workspace's "+
			"configuration. Scoped to this one workspace — it grants access to no other resource.",
		oid, a.Target.WorkspaceName))}

	if sub := a.Target.subscriptionScope(); sub != "" {
		opts = append(opts, RemediationOption{
			Command: ShellCommand(fmt.Sprintf(
				"az role assignment create --assignee %s --role %s --scope %s",
				quoteArg(oid), quoteArg("Log Analytics Reader"), quoteArg(sub))),
			BlastRadius: fmt.Sprintf(
				"Lets objectId %s query EVERY Log Analytics workspace in subscription %s, including ones this "+
					"connector never reads. Much broader than option 1 — only use it if you deliberately want "+
					"subscription-wide log read.", oid, a.Target.SubscriptionID),
			DryRun: dryRun(fmt.Sprintf(
				"az role assignment list --assignee %s --scope %s --include-inherited -o table",
				quoteArg(oid), quoteArg(sub))),
		})
	}
	return opts
}

func (a *AzureSP) remediateMissingResourceRead(as assessment) []RemediationOption {
	oid := as.evidence.Identity.OID
	scope := a.Target.workspaceScope()
	if oid == "" || scope == "" {
		return nil
	}
	return []RemediationOption{
		a.logAnalyticsReaderOption(oid, scope, fmt.Sprintf(
			"Lets objectId %s query every table in workspace %s and read its configuration. Scoped to this one "+
				"workspace — nothing else in the subscription becomes readable.", oid, a.Target.WorkspaceName)),
		{
			Command: ShellCommand(fmt.Sprintf(
				"az role assignment create --assignee %s --role %s --scope %s",
				quoteArg(oid), quoteArg("Reader"), quoteArg(a.Target.resourceGroupScope()))),
			BlastRadius: fmt.Sprintf(
				"Lets objectId %s read the configuration and metadata of every resource in resource group %s. "+
					"Broader than option 1; use it only if the connector must also see resources beyond the workspace.",
				oid, a.Target.ResourceGroup),
			DryRun: dryRun(fmt.Sprintf(
				"az role assignment list --assignee %s --scope %s --include-inherited -o table",
				quoteArg(oid), quoteArg(a.Target.resourceGroupScope()))),
		},
	}
}

func (a *AzureSP) logAnalyticsReaderOption(oid, scope, blast string) RemediationOption {
	return RemediationOption{
		Command: ShellCommand(fmt.Sprintf(
			"az role assignment create --assignee %s --role %s --scope %s",
			quoteArg(oid), quoteArg("Log Analytics Reader"), quoteArg(scope))),
		BlastRadius: blast,
		KnownIssues: []string{
			"`az role assignment create` has no `--what-if`; the dry run above is a read-only listing of what " +
				"this principal already holds at that scope.",
			"ARM/AAD role propagation can take several minutes — re-run the doctor rather than assuming failure.",
		},
		DryRun: dryRun(fmt.Sprintf(
			"az role assignment list --assignee %s --scope %s --include-inherited -o table",
			quoteArg(oid), quoteArg(scope))),
	}
}

// remediateARMAuthorizationFailed scopes the grant to EXACTLY the action and
// scope ARM named in its own denial, rather than to a broad guess. The role is
// chosen by what the denied action actually is — a real decision over the
// action string, in code.
func (a *AzureSP) remediateARMAuthorizationFailed(as assessment) []RemediationOption {
	oid := as.evidence.Identity.OID
	if oid == "" || as.deniedScpe == "" {
		return nil
	}
	role, why := builtInRoleForAction(as.deniedAct)
	if role == "" {
		return nil
	}

	opts := []RemediationOption{{
		Command: ShellCommand(fmt.Sprintf(
			"az role assignment create --assignee %s --role %s --scope %s",
			quoteArg(oid), quoteArg(role), quoteArg(as.deniedScpe))),
		BlastRadius: fmt.Sprintf(
			"Lets objectId %s act as %q at exactly the scope ARM denied (%s) and nowhere wider. %s",
			oid, role, as.deniedScpe, why),
		KnownIssues: []string{
			fmt.Sprintf("ARM denied the specific action %q; this built-in role is the narrowest one that covers it. "+
				"A custom role definition listing only that action is narrower still, at the cost of a role you "+
				"then own and maintain.", as.deniedAct),
			"ARM/AAD role propagation can take several minutes.",
		},
		DryRun: dryRun(fmt.Sprintf(
			"az role assignment list --assignee %s --scope %s --include-inherited -o table",
			quoteArg(oid), quoteArg(as.deniedScpe))),
	}}

	return opts
}

// interleaveNarrowestFirst merges two ranked ladders while preserving the
// narrowest-first invariant ACROSS them: it takes each ladder's rung n before
// either ladder's rung n+1, so a broad second rung of one ladder can never be
// presented above the narrow first rung of the other.
func interleaveNarrowestFirst(ladders ...[]RemediationOption) []RemediationOption {
	var out []RemediationOption
	for rung := 0; ; rung++ {
		emitted := false
		for _, l := range ladders {
			if rung < len(l) {
				out = append(out, l[rung])
				emitted = true
			}
		}
		if !emitted {
			return out
		}
	}
}

// builtInRoleForAction picks the narrowest Azure BUILT-IN role that covers a
// denied ARM action. This is a decision, written as code with its reasoning,
// not a data table an engine walks: each arm states why that role is the
// narrowest built-in that covers the action class.
func builtInRoleForAction(action string) (role, why string) {
	act := strings.ToLower(action)
	switch {
	case strings.HasPrefix(act, "microsoft.insights/eventtypes/"),
		strings.HasPrefix(act, "microsoft.insights/metrics/"),
		strings.HasPrefix(act, "microsoft.insights/diagnosticsettings/read"):
		// Activity Log / metric reads. Monitoring Reader is read-only over
		// monitoring data and is narrower than Reader for this purpose because
		// it does not confer read on every resource's configuration.
		return "Monitoring Reader", "Monitoring Reader is read-only: it can read monitoring data and settings, " +
			"and can change nothing."
	case strings.HasPrefix(act, "microsoft.operationalinsights/workspaces/query/"),
		strings.HasPrefix(act, "microsoft.operationalinsights/workspaces/read"):
		return "Log Analytics Reader", "Log Analytics Reader is read-only over workspace data and configuration."
	case strings.HasSuffix(act, "/read"):
		// A plain read on some other provider: Reader is the narrowest
		// built-in that covers an arbitrary provider read.
		return "Reader", "Reader is read-only across the scope; it can change nothing."
	case strings.HasPrefix(act, "microsoft.authorization/roleassignments/"):
		// Deliberately NOT emitted. Handing out the right to create role
		// assignments is privilege escalation, and this product never asks for
		// or recommends elevated rights (design §6, hard).
		return "", ""
	}
	// Anything mutating that we cannot name a narrow built-in for is left to a
	// human: emitting a broad write role "to be safe" is exactly the failure
	// mode §6 forbids.
	return "", ""
}

// applyStaleness implements design §6 safety property 4: past the threshold,
// every emitted command is presented as "proposed but unverified since <date>
// — review before running", never with the confidence of a freshly eval-proven
// one. It is applied to EVERY option, so no ladder rung can slip out unframed.
func (a *AzureSP) applyStaleness(opts []RemediationOption) []RemediationOption {
	if len(opts) == 0 {
		return opts
	}
	var note string
	switch {
	case a.LastVerifiedLive.IsZero():
		note = "PROPOSED BUT UNVERIFIED: mallcop's CI eval has never proven this command against a live Azure " +
			"account. Review it before running it."
	case a.now().Sub(a.LastVerifiedLive) > stalenessThreshold:
		note = fmt.Sprintf("PROPOSED BUT UNVERIFIED SINCE %s: mallcop's CI eval last proved this command against "+
			"a live Azure account %d days ago; Azure role names and API versions drift. Review it before running it.",
			a.LastVerifiedLive.Format("2006-01-02"), int(a.now().Sub(a.LastVerifiedLive).Hours()/24))
	default:
		note = fmt.Sprintf("Verified against a live Azure account by mallcop's CI eval on %s.",
			a.LastVerifiedLive.Format("2006-01-02"))
	}
	out := make([]RemediationOption, len(opts))
	for i, o := range opts {
		o.KnownIssues = append([]string{note}, o.KnownIssues...)
		out[i] = o
	}
	return out
}

// quoteArg single-quotes a shell argument so an operator can paste an emitted
// command verbatim. Any embedded single quote is escaped the POSIX way
// ('\” — close, escaped quote, reopen), so a hostile value read out of a
// provider response can never break out of the literal and become a second
// command in text the operator is about to run.
func quoteArg(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// workspaceAPIVersion is the Log Analytics workspaces ARM API version the
// doctor reads and previews with.
const workspaceAPIVersion = "2022-10-01"
