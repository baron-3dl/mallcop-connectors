package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop-connectors/internal/doctor"
)

// The fixtures are the RECORDED Azure bodies under internal/doctor/testdata —
// referenced rather than copied so the two test suites can never drift onto
// different "real" bodies. Their capture provenance is documented in
// internal/doctor/fixtures_test.go.
func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "doctor", "testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(b)
}

const (
	testExpectedOID = "00000000-0000-4000-8000-000000000007" // mallcop-monitor
	testActualOID   = "00000000-0000-4000-8000-000000000008" // mallcop-pro-aci
	testTenant      = "00000000-0000-4000-8000-000000000002"
	testWorkspaceID = "11111111-2222-3333-4444-555555555555"
	testWorkspaceRe = "/subscriptions/00000000-0000-4000-8000-000000000001/resourcegroups/example-rg" +
		"/providers/microsoft.operationalinsights/workspaces/law-example"
)

// mintTestJWT builds an AAD-shaped client-credentials token. No real bearer
// token is ever recorded in this repo (that would be a live credential leak).
func mintTestJWT(t *testing.T, oid string) string {
	t.Helper()
	seg := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	claims := map[string]any{
		"aud": "https://api.loganalytics.io", "iss": "https://sts.windows.net/" + testTenant + "/",
		"appid": "00000000-0000-4000-8000-000000000003", "appidacr": "1", "idtyp": "app",
		"oid": oid, "sub": oid, "tid": testTenant, "ver": "1.0",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
		"nbf": float64(time.Now().Add(-time.Minute).Unix()),
	}
	return seg(map[string]any{"typ": "JWT", "alg": "RS256"}) + "." + seg(claims) + ".not-a-real-signature"
}

// stubAzure stands up the three endpoints the connector really talks to and
// points the package's endpoint vars at them for the duration of the test.
// Only the ENDPOINTS are stubbed: the request construction, the auth header,
// the JSON decoding, the diagnosis and the report rendering are all the real
// production code paths.
func stubAzure(t *testing.T, oid string, lawStatus int, lawBody string, armStatus int, armBody string) {
	t.Helper()

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("token request not form-encoded: %v", err)
		}
		if r.Form.Get("grant_type") != "client_credentials" {
			t.Errorf("grant_type = %q, want client_credentials", r.Form.Get("grant_type"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": mintTestJWT(t, oid), "expires_in": 3600,
		})
	}))
	t.Cleanup(tokenSrv.Close)

	lawSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ey") {
			t.Errorf("data-plane call did not present the minted bearer token: %q", got)
		}
		w.WriteHeader(lawStatus)
		_, _ = w.Write([]byte(lawBody))
	}))
	t.Cleanup(lawSrv.Close)

	armSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "law-example") {
			t.Errorf("control-plane GET hit an unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(armStatus)
		_, _ = w.Write([]byte(armBody))
	}))
	t.Cleanup(armSrv.Close)

	oldToken, oldQuery, oldMgmt := tokenEndpoint, queryBase, managementBase
	tokenEndpoint = tokenSrv.URL + "/%s/oauth2/v2.0/token"
	queryBase = lawSrv.URL + "/v1/workspaces/%s/query"
	managementBase = armSrv.URL
	t.Cleanup(func() { tokenEndpoint, queryBase, managementBase = oldToken, oldQuery, oldMgmt })
}

// runDoctorInto drives the real --doctor entry point and decodes its stdout the
// same way mallcop's ExecConnector.Diagnose does.
func runDoctorInto(t *testing.T, oid string) doctor.DiagnosisReport {
	t.Helper()
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out,
		doctorConnectorID(testWorkspaceRe, testWorkspaceID),
		testWorkspaceID, testWorkspaceRe, testTenant, "client-id", "client-secret")
	if err != nil {
		t.Fatalf("runDoctor: %v", err)
	}
	var rep doctor.DiagnosisReport
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rep); err != nil {
		t.Fatalf("--doctor stdout is not a DiagnosisReport: %v\ngot: %s", err, out.String())
	}
	// stdout must be EXACTLY one JSON object; a second value would break the
	// sibling contract.
	if dec.More() {
		t.Fatalf("--doctor printed more than one JSON value: %s", out.String())
	}
	if rep.ConnectorID != "loganalytics-law-example" {
		t.Errorf("connector_id = %q", rep.ConnectorID)
	}
	return rep
}

// ACCEPTANCE: the recorded resource-context 403 through the whole CLI path.
func TestDoctorResourceContext403EndToEnd(t *testing.T) {
	stubAzure(t, testExpectedOID,
		http.StatusForbidden, fixture(t, "law_403_insufficient_access.json"),
		http.StatusOK, fixture(t, "arm_workspace_resource_context.json"))

	rep := runDoctorInto(t, testExpectedOID)

	if !rep.Diagnosis.Known {
		t.Fatalf("want a known diagnosis, got %+v", rep.Diagnosis)
	}
	if !strings.Contains(rep.Diagnosis.Summary, "resource-context access mode") {
		t.Errorf("summary: %s", rep.Diagnosis.Summary)
	}
	if len(rep.Remediation) < 2 {
		t.Fatalf("want a ranked ladder, got %d", len(rep.Remediation))
	}
	first := rep.Remediation[0]
	if !strings.Contains(string(first.Command), "enableLogAccessUsingOnlyResourcePermissions=false") {
		t.Errorf("option 1: %q", first.Command)
	}
	if first.BlastRadius == "" {
		t.Error("option 1 has no blast-radius line")
	}
	if first.DryRun == nil || !strings.Contains(string(*first.DryRun), "--what-if") {
		t.Errorf("option 1 dry run: %v", first.DryRun)
	}
	if !strings.Contains(string(first.Command), "'example-rg'") {
		t.Errorf("command not scoped to the resource group parsed from the workspace ARM id: %q", first.Command)
	}
}

// ACCEPTANCE: the wrong service principal, through the CLI path, decided from
// the token the real token endpoint handed back.
func TestDoctorWrongServicePrincipalEndToEnd(t *testing.T) {
	t.Setenv("AZURE_EXPECTED_PRINCIPAL_OBJECT_ID", testExpectedOID)
	t.Setenv("AZURE_EXPECTED_PRINCIPAL_NAME", "mallcop-monitor")

	stubAzure(t, testActualOID,
		http.StatusForbidden, fixture(t, "law_403_insufficient_access.json"),
		http.StatusOK, fixture(t, "arm_workspace_resource_context.json"))

	rep := runDoctorInto(t, testActualOID)

	if !strings.Contains(rep.Diagnosis.Summary, "WRONG SERVICE PRINCIPAL") {
		t.Fatalf("want a wrong-principal verdict, got %+v", rep.Diagnosis)
	}
	if !strings.Contains(rep.Diagnosis.Summary, testActualOID) ||
		!strings.Contains(rep.Diagnosis.Summary, testExpectedOID) {
		t.Errorf("summary must name both oids: %s", rep.Diagnosis.Summary)
	}
}

// ACCEPTANCE: an unmapped denial is a GRANT-MISS with no command.
func TestDoctorUnmappedDenialIsAGrantMissEndToEnd(t *testing.T) {
	stubAzure(t, testExpectedOID,
		http.StatusForbidden, fixture(t, "law_error_unmapped_code.json"),
		http.StatusOK, fixture(t, "arm_workspace_workspace_context.json"))

	rep := runDoctorInto(t, testExpectedOID)

	if rep.Diagnosis.Known {
		t.Fatalf("want Known:false, got %+v", rep.Diagnosis)
	}
	if len(rep.Remediation) != 0 {
		t.Fatalf("a GRANT-MISS must emit no command, got %+v", rep.Remediation)
	}
}

// ACCEPTANCE: Confirm after a still-403 errors AND produces a GRANT-MISS,
// driven through the same wiring the CLI builds.
func TestDoctorConfirmStill403IsAGrantMissEndToEnd(t *testing.T) {
	stubAzure(t, testExpectedOID,
		http.StatusForbidden, fixture(t, "law_403_insufficient_access.json"),
		http.StatusOK, fixture(t, "arm_workspace_workspace_context.json"))

	d := newAzureSPDoctor("loganalytics-law-example", testWorkspaceID, testWorkspaceRe,
		testTenant, "client-id", "client-secret")

	rep := d.Run(context.Background())
	if len(rep.Remediation) == 0 {
		t.Fatal("expected a remediation to apply")
	}
	// The operator "applies" it; the endpoint keeps returning the recorded 403.
	res, err := d.Confirm(context.Background(), rep.Remediation[0])
	if err == nil {
		t.Fatal("Confirm must error when the deficiency persists after the grant")
	}
	if res.Resolved || res.Diagnosis.Known {
		t.Fatalf("want an unresolved GRANT-MISS, got %+v", res)
	}
	if !strings.Contains(res.Diagnosis.Summary, "GRANT-MISS") {
		t.Errorf("summary: %s", res.Diagnosis.Summary)
	}
}

func TestDoctorHealthyConnectorNeedsNoRemediationEndToEnd(t *testing.T) {
	stubAzure(t, testExpectedOID, http.StatusOK, `{"tables":[]}`, http.StatusOK, "{}")
	rep := runDoctorInto(t, testExpectedOID)
	if !rep.Diagnosis.Known || len(rep.Remediation) != 0 {
		t.Fatalf("healthy connector: %+v", rep)
	}
}

func TestParseWorkspaceResourceID(t *testing.T) {
	sub, rg, ws := parseWorkspaceResourceID(testWorkspaceRe)
	if sub != "00000000-0000-4000-8000-000000000001" || rg != "example-rg" || ws != "law-example" {
		t.Fatalf("got %q %q %q", sub, rg, ws)
	}
	if s, r, w := parseWorkspaceResourceID(""); s != "" || r != "" || w != "" {
		t.Fatalf("an empty id must yield empty scope parts, got %q %q %q", s, r, w)
	}
}

// --- The sibling contract mallcop's ExecConnector depends on ---

// TestMain lets this test binary re-exec itself AS the connector, so the
// --doctor flag wiring, stdout and EXIT CODE are exercised through the real
// main() — ExecConnector treats a non-zero exit as "this sibling does not
// support --doctor", so a doctor that found a problem must still exit 0.
func TestMain(m *testing.M) {
	if os.Getenv("MALLCOP_CONNECTOR_SUBPROCESS") == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

func TestDoctorFlagExitsZeroAndPrintsOneJSONReport(t *testing.T) {
	cmd := exec.Command(os.Args[0], "--doctor", "--workspace-id", testWorkspaceID)
	cmd.Env = append(os.Environ(), "MALLCOP_CONNECTOR_SUBPROCESS=1")
	// Deliberately NO Azure credentials: the doctor must still produce a
	// structured report rather than the bare error the scan path returns.
	cmd.Env = append(cmd.Env, "AZURE_TENANT_ID=", "AZURE_CLIENT_ID=", "AZURE_CLIENT_SECRET=")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("--doctor must exit 0 even when it finds a problem (a non-zero exit tells mallcop the "+
			"sibling does not support --doctor): %v\nstderr: %s", err, stderr.String())
	}

	var rep doctor.DiagnosisReport
	dec := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rep); err != nil {
		t.Fatalf("--doctor stdout is not a DiagnosisReport: %v\ngot: %q", err, stdout.String())
	}
	if dec.More() {
		t.Fatalf("--doctor printed more than one JSON value: %q", stdout.String())
	}
	if !rep.Diagnosis.Known || !strings.Contains(rep.Diagnosis.Summary, "AZURE_TENANT_ID") {
		t.Errorf("missing credentials should be a named, known state: %+v", rep.Diagnosis)
	}
	if strings.Contains(stdout.String(), "client-secret") {
		t.Error("stdout must never carry credential material")
	}
}

// The scan path must be untouched by the doctor work: without --doctor, absent
// credentials are still the same hard error.
func TestScanPathStillFailsLoudWithoutCredentials(t *testing.T) {
	cmd := exec.Command(os.Args[0], "--workspace-id", testWorkspaceID)
	cmd.Env = append(os.Environ(), "MALLCOP_CONNECTOR_SUBPROCESS=1",
		"AZURE_TENANT_ID=", "AZURE_CLIENT_ID=", "AZURE_CLIENT_SECRET=")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("the scan path must still exit non-zero without credentials")
	}
	if !strings.Contains(stderr.String(), "AZURE_TENANT_ID") {
		t.Errorf("stderr: %s", stderr.String())
	}
}
