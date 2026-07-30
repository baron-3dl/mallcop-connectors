package doctor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// lawTarget is the real example-project prod Log Analytics workspace, as the
// mallcop config names it.
func lawTarget() Target {
	return Target{
		ConnectorID:    "loganalytics-law-example",
		SubscriptionID: "00000000-0000-4000-8000-000000000001",
		ResourceGroup:  "example-rg",
		WorkspaceName:  "law-example",
		WorkspaceResourceID: "/subscriptions/00000000-0000-4000-8000-000000000001/resourcegroups/" +
			"example-rg/providers/microsoft.operationalinsights/workspaces/law-example",
	}
}

// newLAWDoctor wires an AzureSP whose data plane returns dataPlane and whose
// alternate-scope control plane returns controlPlane (nil = not probed).
func newLAWDoctor(t *testing.T, token string, dataPlane CallOutcome, controlPlane *CallOutcome) *AzureSP {
	t.Helper()
	d := &AzureSP{
		Target:           lawTarget(),
		LastVerifiedLive: time.Date(2026, 7, 27, 0, 0, 0, 0, time.UTC),
		DataPlaneScope:   ScopeLogAnalytics,
		Now:              func() time.Time { return time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC) },
		MintToken:        func(context.Context, string) (string, error) { return token, nil },
		DataPlaneCall:    func(context.Context, string) CallOutcome { return dataPlane },
	}
	if controlPlane != nil {
		cp := *controlPlane
		d.ControlPlaneCall = func(context.Context, string) CallOutcome { return cp }
	}
	return d
}

func report(t *testing.T, d *AzureSP) DiagnosisReport {
	t.Helper()
	return d.Run(context.Background())
}

// --- ACCEPTANCE 1: a recorded WRONG-SP token => oid != expected, reported ---

func TestWrongServicePrincipalIsReportedFromTheTokenAlone(t *testing.T) {
	// The token the scan was really running with on 2026-07-27.
	token := makeToken(t, appTokenClaims(actualOID, "", "https://api.loganalytics.io"))

	d := newLAWDoctor(t, token, CallOutcome{
		Status: 403, Body: loadFixture(t, "law_403_insufficient_access.json"),
	}, nil)
	d.Expected = Expected{ObjectID: expectedOID, AppID: expectedAppID, DisplayName: expectedName}

	rep := report(t, d)

	if !rep.Diagnosis.Known {
		t.Fatalf("wrong-SP must be a KNOWN diagnosis, got %+v", rep.Diagnosis)
	}
	if !strings.Contains(rep.Diagnosis.Summary, actualOID) {
		t.Errorf("summary must name the oid actually in use (%s): %s", actualOID, rep.Diagnosis.Summary)
	}
	if !strings.Contains(rep.Diagnosis.Summary, expectedOID) {
		t.Errorf("summary must name the expected oid (%s): %s", expectedOID, rep.Diagnosis.Summary)
	}
	if !strings.Contains(rep.Diagnosis.Summary, expectedName) {
		t.Errorf("summary must name the expected principal (%s): %s", expectedName, rep.Diagnosis.Summary)
	}
	// The narrowest option must grant nothing at all.
	if len(rep.Remediation) == 0 {
		t.Fatal("wrong-SP must emit at least one remediation")
	}
	if strings.Contains(string(rep.Remediation[0].Command), "role assignment create") {
		t.Errorf("narrowest wrong-SP option must not grant a role, got %q", rep.Remediation[0].Command)
	}
}

// A wrong-SP verdict is reached with ZERO network calls (design §7 Azure
// offline fast path). If the doctor ever needed the network to answer "who am
// I", the CI-workflow-hack failure mode is back.
func TestWrongServicePrincipalNeedsNoNetworkCall(t *testing.T) {
	token := makeToken(t, appTokenClaims(actualOID, "", "https://api.loganalytics.io"))
	dataPlaneCalls := 0

	d := &AzureSP{
		Target:         lawTarget(),
		Expected:       Expected{ObjectID: expectedOID, DisplayName: expectedName},
		DataPlaneScope: ScopeLogAnalytics,
		Now:            func() time.Time { return time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC) },
		MintToken:      func(context.Context, string) (string, error) { return token, nil },
		DataPlaneCall: func(context.Context, string) CallOutcome {
			dataPlaneCalls++
			// Pretend the source is perfectly healthy. The wrong-SP verdict
			// must still be reached, from the token alone.
			return CallOutcome{Status: 200, Body: `{"tables":[]}`}
		},
	}
	claims, err := DecodeIdentity(token)
	if err != nil {
		t.Fatalf("DecodeIdentity: %v", err)
	}
	if claims.OID != actualOID {
		t.Fatalf("offline decode read oid %q, want %q", claims.OID, actualOID)
	}

	rep := d.Run(context.Background())
	if !strings.Contains(rep.Diagnosis.Summary, "WRONG SERVICE PRINCIPAL") {
		t.Fatalf("a healthy-looking source must not mask a wrong principal: %s", rep.Diagnosis.Summary)
	}
	// Probe does make the data-plane call (it gathers all evidence up front),
	// but the VERDICT does not depend on it: the same call returned 200.
	if dataPlaneCalls != 1 {
		t.Errorf("expected exactly one data-plane call, got %d", dataPlaneCalls)
	}
}

func TestMatchingPrincipalIsNotFlaggedWrong(t *testing.T) {
	token := makeToken(t, appTokenClaims(expectedOID, expectedAppID, "https://api.loganalytics.io"))
	d := newLAWDoctor(t, token, CallOutcome{Status: 200, Body: `{"tables":[]}`}, nil)
	d.Expected = Expected{ObjectID: expectedOID, AppID: expectedAppID, DisplayName: expectedName}

	rep := report(t, d)
	if strings.Contains(rep.Diagnosis.Summary, "WRONG SERVICE PRINCIPAL") {
		t.Fatalf("correct principal flagged wrong: %s", rep.Diagnosis.Summary)
	}
	if !rep.Diagnosis.Known || len(rep.Remediation) != 0 {
		t.Fatalf("healthy connector must need no remediation, got %+v", rep)
	}
}

func TestUndeclaredExpectationNeverFabricatesAWrongPrincipalVerdict(t *testing.T) {
	token := makeToken(t, appTokenClaims(actualOID, "", "https://api.loganalytics.io"))
	d := newLAWDoctor(t, token, CallOutcome{Status: 200, Body: `{"tables":[]}`}, nil)
	// d.Expected deliberately left zero.
	rep := report(t, d)
	if strings.Contains(rep.Diagnosis.Summary, "WRONG SERVICE PRINCIPAL") {
		t.Fatalf("no expectation was declared, so no wrong-principal verdict may be rendered: %s",
			rep.Diagnosis.Summary)
	}
}

// --- ACCEPTANCE 2: recorded resource-context 403 => ranked az grant with a
// --what-if dry run and a blast-radius line ---

func TestResourceContext403EmitsRankedRemediationWithWhatIfAndBlastRadius(t *testing.T) {
	token := makeToken(t, appTokenClaims(expectedOID, expectedAppID, "https://api.loganalytics.io"))
	cp := CallOutcome{Status: 200, Body: loadFixture(t, "arm_workspace_resource_context.json")}
	d := newLAWDoctor(t, token, CallOutcome{
		Status: 403, Body: loadFixture(t, "law_403_insufficient_access.json"),
	}, &cp)

	rep := report(t, d)

	if !rep.Diagnosis.Known {
		t.Fatalf("resource-context access mode is a KNOWN deficiency, got %+v", rep.Diagnosis)
	}
	if !strings.Contains(rep.Diagnosis.Summary, "enableLogAccessUsingOnlyResourcePermissions=true") {
		t.Errorf("summary must name the access-mode setting: %s", rep.Diagnosis.Summary)
	}
	if rep.Diagnosis.Confidence < 0.9 {
		t.Errorf("an unambiguous access-mode verdict should be high confidence, got %v", rep.Diagnosis.Confidence)
	}
	if len(rep.Remediation) < 2 {
		t.Fatalf("remediation must be a RANKED ladder, got %d option(s)", len(rep.Remediation))
	}

	first := rep.Remediation[0]
	if !strings.Contains(string(first.Command), "enableLogAccessUsingOnlyResourcePermissions=false") {
		t.Errorf("narrowest option must flip the access mode, got %q", first.Command)
	}
	// Narrowest-first: the access-mode flip grants no role; the second rung does.
	if strings.Contains(string(first.Command), "role assignment create") {
		t.Errorf("option 1 must not be a role grant: %q", first.Command)
	}
	if !strings.Contains(string(rep.Remediation[1].Command), "role assignment create") {
		t.Errorf("option 2 should be the broader role grant, got %q", rep.Remediation[1].Command)
	}
	for i, o := range rep.Remediation {
		if strings.TrimSpace(o.BlastRadius) == "" {
			t.Errorf("option %d has no blast-radius line", i)
		}
	}
	if first.DryRun == nil {
		t.Fatal("the access-mode option must carry a dry run")
	}
	if !strings.Contains(string(*first.DryRun), "--what-if") ||
		!strings.Contains(string(*first.DryRun), "az deployment group create") {
		t.Errorf("the access-mode dry run must be a real ARM what-if, got %q", *first.DryRun)
	}
	// The region must be the one the probe READ off the live ARM body, not a
	// plausible-looking constant. Assert the template's location field exactly:
	// "eastus" is a prefix of the real "eastus2", so a substring check on the
	// short form would pass against an invented region.
	if !strings.Contains(string(*first.DryRun), `\"location\":\"eastus2\"`) &&
		!strings.Contains(string(*first.DryRun), `"location":"eastus2"`) {
		t.Errorf("the what-if template must use the workspace location the probe read (eastus2): %q", *first.DryRun)
	}
	if strings.Contains(string(*first.DryRun), `"location":"eastus"`) {
		t.Errorf("what-if template pinned the wrong region: %q", *first.DryRun)
	}
	// Scoped to the right workspace, not a subscription-wide guess.
	if !strings.Contains(string(first.Command), "law-example") ||
		!strings.Contains(string(first.Command), "example-rg") {
		t.Errorf("command must be scoped to the target workspace/resource group: %q", first.Command)
	}
}

// The SAME data-plane body with the workspace in workspace-CONTEXT mode is a
// DIFFERENT deficiency and a different fix. This is the whole point of the
// alternate-scope probe: the data plane alone cannot tell them apart.
func TestSameBodyWorkspaceContextModeDiagnosesMissingGrantInstead(t *testing.T) {
	token := makeToken(t, appTokenClaims(expectedOID, expectedAppID, "https://api.loganalytics.io"))
	cp := CallOutcome{Status: 200, Body: loadFixture(t, "arm_workspace_workspace_context.json")}
	d := newLAWDoctor(t, token, CallOutcome{
		Status: 403, Body: loadFixture(t, "law_403_insufficient_access.json"),
	}, &cp)

	rep := report(t, d)

	if !rep.Diagnosis.Known {
		t.Fatalf("missing grant is a KNOWN deficiency, got %+v", rep.Diagnosis)
	}
	if strings.Contains(rep.Diagnosis.Summary, "resource-context access mode") {
		t.Errorf("workspace-context mode must NOT be diagnosed as resource-context: %s", rep.Diagnosis.Summary)
	}
	if len(rep.Remediation) == 0 {
		t.Fatal("missing grant must emit a remediation")
	}
	first := rep.Remediation[0]
	if !strings.Contains(string(first.Command), `--role 'Log Analytics Reader'`) {
		t.Errorf("narrowest fix is the workspace-scoped Log Analytics Reader grant, got %q", first.Command)
	}
	if !strings.Contains(string(first.Command), expectedOID) {
		t.Errorf("the grant must be assigned to the oid actually in use: %q", first.Command)
	}
	if !strings.Contains(string(first.Command), "workspaces/law-example") {
		t.Errorf("the grant must be scoped to the workspace, not the subscription: %q", first.Command)
	}
	if first.DryRun == nil || !strings.Contains(string(*first.DryRun), "role assignment list") {
		t.Errorf("the grant option must carry a side-effect-free preview, got %v", first.DryRun)
	}
}

func TestControlPlaneAlsoDeniedDiagnosesNoEffectiveRoleAtAll(t *testing.T) {
	token := makeToken(t, appTokenClaims(expectedOID, expectedAppID, "https://api.loganalytics.io"))
	cp := CallOutcome{Status: 403, Body: loadFixture(t, "arm_403_authorization_failed.json")}
	d := newLAWDoctor(t, token, CallOutcome{
		Status: 403, Body: loadFixture(t, "law_403_insufficient_access.json"),
	}, &cp)

	rep := report(t, d)
	if !rep.Diagnosis.Known {
		t.Fatalf("want a known diagnosis, got %+v", rep.Diagnosis)
	}
	if !strings.Contains(rep.Diagnosis.Summary, "control plane") {
		t.Errorf("summary should cite the control-plane denial: %s", rep.Diagnosis.Summary)
	}
}

func TestUnavailableControlPlaneStaysAmbiguousRatherThanGuessing(t *testing.T) {
	token := makeToken(t, appTokenClaims(expectedOID, expectedAppID, "https://api.loganalytics.io"))
	cp := CallOutcome{Err: "dial tcp: i/o timeout"}
	d := newLAWDoctor(t, token, CallOutcome{
		Status: 403, Body: loadFixture(t, "law_403_insufficient_access.json"),
	}, &cp)

	rep := report(t, d)
	if rep.Diagnosis.Confidence > 0.6 {
		t.Errorf("an undisambiguated denial must not be reported confidently, got %v", rep.Diagnosis.Confidence)
	}
	if len(rep.Remediation) < 2 {
		t.Errorf("an ambiguous denial should offer both ladders, got %d", len(rep.Remediation))
	}
}

// --- ACCEPTANCE 3: an unrecognized 403 => Known:false (a GRANT-MISS) ---

func TestUnmapped403IsAGrantMissNotAGuess(t *testing.T) {
	token := makeToken(t, appTokenClaims(expectedOID, expectedAppID, "https://api.loganalytics.io"))
	cp := CallOutcome{Status: 200, Body: loadFixture(t, "arm_workspace_workspace_context.json")}
	d := newLAWDoctor(t, token, CallOutcome{
		Status: 403, Body: loadFixture(t, "law_error_unmapped_code.json"),
	}, &cp)

	rep := report(t, d)
	if rep.Diagnosis.Known {
		t.Fatalf("an unmapped error code must be Known:false (a GRANT-MISS), got %+v", rep.Diagnosis)
	}
	if len(rep.Remediation) != 0 {
		t.Fatalf("a GRANT-MISS must emit NO command — guessing a grant is the failure mode §6 forbids; got %+v",
			rep.Remediation)
	}
	if !strings.Contains(rep.Diagnosis.Summary, "WorkspaceNotFoundError") {
		t.Errorf("the miss must carry the unrecognized code so the corpus can rank it: %s", rep.Diagnosis.Summary)
	}
}

func TestNonJSON403IsAlsoAGrantMiss(t *testing.T) {
	token := makeToken(t, appTokenClaims(expectedOID, expectedAppID, "https://api.loganalytics.io"))
	d := newLAWDoctor(t, token, CallOutcome{Status: 403, Body: "<html>403 Forbidden</html>"}, nil)
	rep := report(t, d)
	if rep.Diagnosis.Known {
		t.Fatalf("an unparseable body must be Known:false, got %+v", rep.Diagnosis)
	}
	if len(rep.Remediation) != 0 {
		t.Fatalf("no command may be emitted for an unparseable denial, got %+v", rep.Remediation)
	}
}

// --- ACCEPTANCE 4: still-403 after the grant => Confirm errors + GRANT-MISS ---

func TestConfirmClosesTheLoopWhenTheGrantWorked(t *testing.T) {
	token := makeToken(t, appTokenClaims(expectedOID, expectedAppID, "https://api.loganalytics.io"))
	// First call 403s (pre-grant), the re-probe succeeds (post-grant).
	calls := 0
	d := &AzureSP{
		Target:           lawTarget(),
		LastVerifiedLive: time.Date(2026, 7, 27, 0, 0, 0, 0, time.UTC),
		DataPlaneScope:   ScopeLogAnalytics,
		Now:              func() time.Time { return time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC) },
		MintToken:        func(context.Context, string) (string, error) { return token, nil },
		DataPlaneCall: func(context.Context, string) CallOutcome {
			calls++
			if calls == 1 {
				return CallOutcome{Status: 403, Body: loadFixture(t, "law_403_insufficient_access.json")}
			}
			return CallOutcome{Status: 200, Body: `{"tables":[]}`}
		},
		ControlPlaneCall: func(context.Context, string) CallOutcome {
			return CallOutcome{Status: 200, Body: loadFixture(t, "arm_workspace_resource_context.json")}
		},
	}

	rep := d.Run(context.Background())
	if len(rep.Remediation) == 0 {
		t.Fatal("expected a remediation to apply")
	}
	res, err := d.Confirm(context.Background(), rep.Remediation[0])
	if err != nil {
		t.Fatalf("a resolved deficiency must not error: %v", err)
	}
	if !res.Resolved {
		t.Fatalf("Confirm should report resolved, got %+v", res)
	}
	if res.CheckedAt.IsZero() {
		t.Error("Confirm must stamp when it re-probed")
	}
}

// THE headline case: the grant was applied, the command "succeeded", and the
// problem persisted. Emit-and-forget would record this as success.
func TestConfirmFailureIsItselfAGrantMissAndErrors(t *testing.T) {
	token := makeToken(t, appTokenClaims(expectedOID, expectedAppID, "https://api.loganalytics.io"))
	still403 := CallOutcome{Status: 403, Body: loadFixture(t, "law_403_insufficient_access.json")}
	cp := CallOutcome{Status: 200, Body: loadFixture(t, "arm_workspace_workspace_context.json")}
	d := newLAWDoctor(t, token, still403, &cp)

	rep := d.Run(context.Background())
	if len(rep.Remediation) == 0 {
		t.Fatal("expected a remediation to apply")
	}
	applied := rep.Remediation[0]

	res, err := d.Confirm(context.Background(), applied)
	if err == nil {
		t.Fatal("a remediation that did not resolve the deficiency MUST error — " +
			"silently reporting success is the exact 2026-07-27 failure mode")
	}
	var miss *GrantMissError
	if !errors.As(err, &miss) {
		t.Fatalf("want a *GrantMissError so the caller can persist the miss, got %T: %v", err, err)
	}
	if miss.Applied != applied.Command {
		t.Errorf("the miss must record which command was applied: %q", miss.Applied)
	}
	if res.Resolved {
		t.Error("Resolved must be false")
	}
	if res.Diagnosis.Known {
		t.Errorf("a failing Confirm is a GRANT-MISS (Known:false), got %+v", res.Diagnosis)
	}
	if !strings.Contains(res.Diagnosis.Summary, "GRANT-MISS") {
		t.Errorf("the summary must be identifiable as a GRANT-MISS: %s", res.Diagnosis.Summary)
	}
	if !strings.Contains(res.Diagnosis.Summary, string(applied.Command)) {
		t.Errorf("the miss must carry the applied command for the corpus: %s", res.Diagnosis.Summary)
	}
	// The miss renders as a structured report, not just an error string.
	missReport := miss.Report(lawTarget().ConnectorID)
	if missReport.Diagnosis.Known || missReport.ConnectorID != lawTarget().ConnectorID {
		t.Errorf("GrantMissError.Report is malformed: %+v", missReport)
	}
}

// --- ARM family (cmd/azure): AuthorizationFailed names its own scope ---

func TestARMAuthorizationFailedGrantsExactlyTheDeniedScope(t *testing.T) {
	token := makeToken(t, appTokenClaims(expectedOID, expectedAppID, "https://management.azure.com"))
	d := &AzureSP{
		Target:           Target{ConnectorID: "azure-sub", SubscriptionID: "00000000-0000-4000-8000-000000000001"},
		LastVerifiedLive: time.Date(2026, 7, 27, 0, 0, 0, 0, time.UTC),
		DataPlaneScope:   ScopeARM,
		Now:              func() time.Time { return time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC) },
		MintToken:        func(context.Context, string) (string, error) { return token, nil },
		DataPlaneCall: func(context.Context, string) CallOutcome {
			return CallOutcome{Status: 403, Body: loadFixture(t, "arm_403_authorization_failed.json")}
		},
	}

	rep := d.Run(context.Background())
	if !rep.Diagnosis.Known {
		t.Fatalf("AuthorizationFailed is a known class, got %+v", rep.Diagnosis)
	}
	if !strings.Contains(rep.Diagnosis.Summary, "Microsoft.Resources/deployments/validate/action") {
		t.Errorf("summary must name the denied action ARM reported: %s", rep.Diagnosis.Summary)
	}
	// The denied action is a mutating deployment action; no narrow built-in
	// read role covers it, so the doctor must NOT invent a broad write grant.
	for _, o := range rep.Remediation {
		if strings.Contains(string(o.Command), "--role 'Contributor'") ||
			strings.Contains(string(o.Command), "--role 'Owner'") ||
			strings.Contains(string(o.Command), "roleAssignments/write") {
			t.Errorf("the doctor must never propose a broad write/elevation role: %q", o.Command)
		}
	}
}

func TestARMActivityLogDenialGrantsMonitoringReaderAtTheDeniedScope(t *testing.T) {
	// A denial of the connector's REAL read action, in the recorded ARM
	// envelope shape.
	body := `{"error":{"code":"AuthorizationFailed","message":"The client '` + expectedAppID +
		`' with object id '` + expectedOID + `' does not have authorization to perform action ` +
		`'microsoft.insights/eventtypes/values/read' over scope ` +
		`'/subscriptions/00000000-0000-4000-8000-000000000001' or the scope is invalid. ` +
		`If access was recently granted, please refresh your credentials."}}`

	token := makeToken(t, appTokenClaims(expectedOID, expectedAppID, "https://management.azure.com"))
	d := &AzureSP{
		Target:           Target{ConnectorID: "azure-sub", SubscriptionID: "00000000-0000-4000-8000-000000000001"},
		LastVerifiedLive: time.Date(2026, 7, 27, 0, 0, 0, 0, time.UTC),
		DataPlaneScope:   ScopeARM,
		Now:              func() time.Time { return time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC) },
		MintToken:        func(context.Context, string) (string, error) { return token, nil },
		DataPlaneCall: func(context.Context, string) CallOutcome {
			return CallOutcome{Status: 403, Body: body}
		},
	}

	rep := d.Run(context.Background())
	if len(rep.Remediation) == 0 {
		t.Fatal("a denied read with a known narrow role must emit a remediation")
	}
	first := rep.Remediation[0]
	if !strings.Contains(string(first.Command), `--role 'Monitoring Reader'`) {
		t.Errorf("Monitoring Reader is the narrowest built-in covering an Activity Log read, got %q", first.Command)
	}
	if !strings.Contains(string(first.Command), "--scope '/subscriptions/00000000-0000-4000-8000-000000000001'") {
		t.Errorf("the grant must be scoped to exactly what ARM denied, got %q", first.Command)
	}
	if strings.TrimSpace(first.BlastRadius) == "" {
		t.Error("no blast-radius line")
	}
}

// --- Emit-step safety (§6) ---

func TestStalenessDowngradesEveryEmittedCommandOnceItAges(t *testing.T) {
	token := makeToken(t, appTokenClaims(expectedOID, expectedAppID, "https://api.loganalytics.io"))
	cp := CallOutcome{Status: 200, Body: loadFixture(t, "arm_workspace_resource_context.json")}
	d := newLAWDoctor(t, token, CallOutcome{
		Status: 403, Body: loadFixture(t, "law_403_insufficient_access.json"),
	}, &cp)
	// Same LastVerifiedLive, but "now" is a year later. The token is minted
	// valid at that later clock so this exercises STALENESS, not expiry.
	later := time.Date(2027, 7, 30, 0, 0, 0, 0, time.UTC)
	d.Now = func() time.Time { return later }
	claims := appTokenClaims(expectedOID, expectedAppID, "https://api.loganalytics.io")
	claims["exp"] = float64(later.Add(time.Hour).Unix())
	future := makeToken(t, claims)
	d.MintToken = func(context.Context, string) (string, error) { return future, nil }

	rep := report(t, d)
	if len(rep.Remediation) == 0 {
		t.Fatal("expected remediations")
	}
	for i, o := range rep.Remediation {
		if len(o.KnownIssues) == 0 || !strings.Contains(o.KnownIssues[0], "PROPOSED BUT UNVERIFIED SINCE 2026-07-27") {
			t.Errorf("option %d is not staleness-framed: %v", i, o.KnownIssues)
		}
	}
}

func TestFreshVerificationIsFramedAsVerified(t *testing.T) {
	token := makeToken(t, appTokenClaims(expectedOID, expectedAppID, "https://api.loganalytics.io"))
	cp := CallOutcome{Status: 200, Body: loadFixture(t, "arm_workspace_resource_context.json")}
	d := newLAWDoctor(t, token, CallOutcome{
		Status: 403, Body: loadFixture(t, "law_403_insufficient_access.json"),
	}, &cp)

	rep := report(t, d)
	if !strings.Contains(rep.Remediation[0].KnownIssues[0], "Verified against a live Azure account") {
		t.Errorf("a fresh stamp should read as verified: %v", rep.Remediation[0].KnownIssues)
	}
}

func TestNeverVerifiedIsFramedAsNeverProven(t *testing.T) {
	token := makeToken(t, appTokenClaims(expectedOID, expectedAppID, "https://api.loganalytics.io"))
	cp := CallOutcome{Status: 200, Body: loadFixture(t, "arm_workspace_resource_context.json")}
	d := newLAWDoctor(t, token, CallOutcome{
		Status: 403, Body: loadFixture(t, "law_403_insufficient_access.json"),
	}, &cp)
	d.LastVerifiedLive = time.Time{}

	rep := report(t, d)
	if !strings.Contains(rep.Remediation[0].KnownIssues[0], "never proven this command against a live Azure") {
		t.Errorf("a zero stamp must read as never proven: %v", rep.Remediation[0].KnownIssues)
	}
}

// A hostile value read out of a provider response must never be able to break
// out of the quoted argument in a command the operator is about to paste.
func TestEmittedCommandsQuoteInjectedValues(t *testing.T) {
	hostileOID := "abc'; rm -rf / #"
	claims := appTokenClaims(hostileOID, expectedAppID, "https://api.loganalytics.io")
	token := makeToken(t, claims)
	cp := CallOutcome{Status: 200, Body: loadFixture(t, "arm_workspace_workspace_context.json")}
	d := newLAWDoctor(t, token, CallOutcome{
		Status: 403, Body: loadFixture(t, "law_403_insufficient_access.json"),
	}, &cp)

	rep := report(t, d)
	if len(rep.Remediation) == 0 {
		t.Fatal("expected remediations")
	}
	cmd := string(rep.Remediation[0].Command)
	if strings.Contains(cmd, "'; rm -rf / #'") {
		// This is the SAFE form (the quote was escaped and the value stayed
		// inside the literal); the unsafe form would end the literal early.
		t.Logf("quoted form: %s", cmd)
	}
	if !strings.Contains(cmd, `'abc'\''; rm -rf / #'`) {
		t.Errorf("hostile oid was not POSIX-escaped into the argument: %s", cmd)
	}
}

// --- Trust boundary: the doctor emits, it never runs anything ---

func TestDoctorNeverProposesPrivilegeEscalation(t *testing.T) {
	role, _ := builtInRoleForAction("Microsoft.Authorization/roleAssignments/write")
	if role != "" {
		t.Fatalf("the doctor must never propose a role granting roleAssignments/write, got %q", role)
	}
	role, _ = builtInRoleForAction("Microsoft.Compute/virtualMachines/write")
	if role != "" {
		t.Fatalf("an unmapped MUTATING action must yield no role rather than a broad write grant, got %q", role)
	}
}

// --- Degenerate identity states ---

func TestUserTokenInAHeadlessConnectorIsNamed(t *testing.T) {
	claims := appTokenClaims(actualOID, "", "https://api.loganalytics.io")
	claims["idtyp"] = "user"
	delete(claims, "appid")
	token := makeToken(t, claims)

	d := newLAWDoctor(t, token, CallOutcome{Status: 200, Body: `{"tables":[]}`}, nil)
	rep := report(t, d)
	if !rep.Diagnosis.Known || !strings.Contains(rep.Diagnosis.Summary, "delegated USER identity") {
		t.Fatalf("a user token in a headless connector must be named: %+v", rep.Diagnosis)
	}
}

func TestUnreadableTokenIsAGrantMissNotAFabricatedIdentity(t *testing.T) {
	d := newLAWDoctor(t, "not-a-jwt", CallOutcome{Status: 403,
		Body: loadFixture(t, "law_403_insufficient_access.json")}, nil)
	d.Expected = Expected{ObjectID: expectedOID}

	rep := report(t, d)
	if rep.Diagnosis.Known {
		t.Fatalf("an unreadable identity must be Known:false, not a confident verdict: %+v", rep.Diagnosis)
	}
	if len(rep.Remediation) != 0 {
		t.Fatalf("no command may be emitted when the acting identity is unknown, got %+v", rep.Remediation)
	}
}

func TestNoCredentialsIsReportedNotCrashed(t *testing.T) {
	d := newLAWDoctor(t, "", CallOutcome{}, nil)
	d.MintToken = func(context.Context, string) (string, error) {
		return "", errors.New("token error 401: AADSTS7000215: Invalid client secret provided")
	}
	rep := report(t, d)
	if !rep.Diagnosis.Known {
		t.Fatalf("a bad credential is a known, nameable state: %+v", rep.Diagnosis)
	}
	if !strings.Contains(rep.Diagnosis.Summary, "AADSTS7000215") {
		t.Errorf("the AAD error should reach the operator: %s", rep.Diagnosis.Summary)
	}
}

func TestTransportFailureIsNotDiagnosedAsAPermissionProblem(t *testing.T) {
	token := makeToken(t, appTokenClaims(expectedOID, expectedAppID, "https://api.loganalytics.io"))
	d := newLAWDoctor(t, token, CallOutcome{Err: "dial tcp 20.1.2.3:443: connect: connection refused"}, nil)
	rep := report(t, d)
	if rep.Diagnosis.Known {
		t.Fatalf("a network failure is not a known grant deficiency: %+v", rep.Diagnosis)
	}
	if len(rep.Remediation) != 0 {
		t.Fatalf("no grant may be proposed for a network failure, got %+v", rep.Remediation)
	}
}

func TestRemediateWithoutDiagnoseEmitsNothing(t *testing.T) {
	d := &AzureSP{Target: lawTarget()}
	if opts := d.Remediate(Diagnosis{Known: true, Summary: "anything"}); len(opts) != 0 {
		t.Fatalf("Remediate must not emit commands scoped from evidence it does not have: %+v", opts)
	}
}

// Under ambiguity the two ladders are INTERLEAVED, so a broad rung of one can
// never be presented above a narrow rung of the other.
func TestAmbiguousDenialKeepsBothLaddersGloballyNarrowestFirst(t *testing.T) {
	token := makeToken(t, appTokenClaims(expectedOID, expectedAppID, "https://api.loganalytics.io"))
	cp := CallOutcome{Err: "dial tcp: i/o timeout"}
	d := newLAWDoctor(t, token, CallOutcome{
		Status: 403, Body: loadFixture(t, "law_403_insufficient_access.json"),
	}, &cp)

	rep := report(t, d)
	if len(rep.Remediation) < 4 {
		t.Fatalf("both ladders should be offered, got %d option(s)", len(rep.Remediation))
	}
	// Rung 1 of each ladder comes before rung 2 of either.
	if !strings.Contains(string(rep.Remediation[0].Command), "enableLogAccessUsingOnlyResourcePermissions=false") {
		t.Errorf("option 1 should be the ladder rung that grants nothing, got %q", rep.Remediation[0].Command)
	}
	if !strings.Contains(string(rep.Remediation[1].Command), "workspaces/law-example") {
		t.Errorf("option 2 should be the workspace-scoped grant, got %q", rep.Remediation[1].Command)
	}
	// The broad resource-group / subscription rungs come after both.
	for _, o := range rep.Remediation[:2] {
		if strings.Contains(string(o.Command), "--scope '/subscriptions/00000000-0000-4000-8000-000000000001'") {
			t.Errorf("a subscription-wide grant must not rank in the top two: %q", o.Command)
		}
	}
	for _, o := range rep.Remediation {
		if strings.TrimSpace(o.BlastRadius) == "" {
			t.Errorf("every rung needs a blast-radius line: %q", o.Command)
		}
	}
}
