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

// Fixtures are the RECORDED Azure bodies under internal/doctor/testdata —
// referenced rather than copied so the suites cannot drift onto different
// "real" bodies. Capture provenance: internal/doctor/fixtures_test.go.
func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "doctor", "testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(b)
}

const (
	testSubscription = "00000000-0000-4000-8000-000000000001"
	testExpectedOID  = "00000000-0000-4000-8000-000000000007" // mallcop-monitor
	testActualOID    = "00000000-0000-4000-8000-000000000008" // mallcop-pro-aci
	testTenant       = "00000000-0000-4000-8000-000000000002"
)

// mintTestJWT builds an AAD-shaped client-credentials token for the ARM
// audience. No real bearer token is ever recorded in this repo.
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
		"aud": "https://management.azure.com", "iss": "https://sts.windows.net/" + testTenant + "/",
		"appid": "00000000-0000-4000-8000-000000000003", "appidacr": "1", "idtyp": "app",
		"oid": oid, "sub": oid, "tid": testTenant, "ver": "1.0",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
		"nbf": float64(time.Now().Add(-time.Minute).Unix()),
	}
	return seg(map[string]any{"typ": "JWT", "alg": "RS256"}) + "." + seg(claims) + ".not-a-real-signature"
}

// stubARM points token minting and the Activity Log endpoint at httptest
// servers. Only the ENDPOINTS are stubbed — request construction, auth header,
// diagnosis and report rendering are the real production paths.
func stubARM(t *testing.T, oid string, status int, body string) {
	t.Helper()

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if got := r.Form.Get("scope"); got != "https://management.azure.com/.default" {
			t.Errorf("scope = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": mintTestJWT(t, oid), "expires_in": 3600,
		})
	}))
	t.Cleanup(tokenSrv.Close)

	armSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ey") {
			t.Errorf("data-plane call did not present the minted bearer token: %q", got)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(armSrv.Close)

	oldToken, oldBase := tokenEndpoint, activityLogBase
	tokenEndpoint = tokenSrv.URL + "/%s/oauth2/v2.0/token"
	activityLogBase = armSrv.URL + "/subscriptions/%s/providers/microsoft.insights/eventtypes/management/values"
	t.Cleanup(func() { tokenEndpoint, activityLogBase = oldToken, oldBase })
}

func runDoctorInto(t *testing.T) doctor.DiagnosisReport {
	t.Helper()
	var out bytes.Buffer
	if err := runDoctor(context.Background(), &out, testSubscription, testTenant, "cid", "csecret"); err != nil {
		t.Fatalf("runDoctor: %v", err)
	}
	var rep doctor.DiagnosisReport
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rep); err != nil {
		t.Fatalf("--doctor stdout is not a DiagnosisReport: %v\ngot: %s", err, out.String())
	}
	if dec.More() {
		t.Fatalf("--doctor printed more than one JSON value: %s", out.String())
	}
	return rep
}

// ACCEPTANCE: the recorded ARM 403 AuthorizationFailed, end to end.
func TestDoctorARMAuthorizationFailedEndToEnd(t *testing.T) {
	stubARM(t, testExpectedOID, http.StatusForbidden, fixture(t, "arm_403_authorization_failed.json"))

	rep := runDoctorInto(t)

	if !rep.Diagnosis.Known {
		t.Fatalf("AuthorizationFailed is a known class, got %+v", rep.Diagnosis)
	}
	if !strings.Contains(rep.Diagnosis.Summary, "Microsoft.Resources/deployments/validate/action") ||
		!strings.Contains(rep.Diagnosis.Summary, "resourcegroups/example-rg") {
		t.Errorf("summary must carry the denied action and scope ARM itself reported: %s", rep.Diagnosis.Summary)
	}
	// The denied action is a mutating deployment action with no narrow built-in
	// read role, so the doctor must decline rather than propose a write grant.
	for _, o := range rep.Remediation {
		if strings.Contains(string(o.Command), "Contributor") || strings.Contains(string(o.Command), "Owner") {
			t.Errorf("must never propose a broad write/elevation role: %q", o.Command)
		}
	}
}

// The connector's own read being denied yields a scope-exact Monitoring Reader
// grant with a blast-radius line and a side-effect-free preview.
func TestDoctorActivityLogReadDeniedEmitsScopeExactGrant(t *testing.T) {
	body := `{"error":{"code":"AuthorizationFailed","message":"The client '00000000-0000-4000-8000-000000000003'` +
		` with object id '` + testExpectedOID + `' does not have authorization to perform action ` +
		`'microsoft.insights/eventtypes/values/read' over scope '/subscriptions/` + testSubscription +
		`' or the scope is invalid. If access was recently granted, please refresh your credentials."}}`
	stubARM(t, testExpectedOID, http.StatusForbidden, body)

	rep := runDoctorInto(t)
	if len(rep.Remediation) == 0 {
		t.Fatal("expected a remediation")
	}
	first := rep.Remediation[0]
	if !strings.Contains(string(first.Command), "'Monitoring Reader'") {
		t.Errorf("want the narrowest built-in for an Activity Log read: %q", first.Command)
	}
	if !strings.Contains(string(first.Command), "--scope '/subscriptions/"+testSubscription+"'") {
		t.Errorf("grant must be scoped to exactly what ARM denied: %q", first.Command)
	}
	if first.BlastRadius == "" {
		t.Error("no blast-radius line")
	}
	if first.DryRun == nil || !strings.Contains(string(*first.DryRun), "role assignment list") {
		t.Errorf("want a side-effect-free preview, got %v", first.DryRun)
	}
	if len(first.KnownIssues) == 0 || !strings.Contains(first.KnownIssues[0], "2026-07-27") {
		t.Errorf("want staleness framing keyed on LastVerifiedLive: %v", first.KnownIssues)
	}
}

func TestDoctorWrongServicePrincipalEndToEnd(t *testing.T) {
	t.Setenv("AZURE_EXPECTED_PRINCIPAL_OBJECT_ID", testExpectedOID)
	t.Setenv("AZURE_EXPECTED_PRINCIPAL_NAME", "mallcop-monitor")
	stubARM(t, testActualOID, http.StatusForbidden, fixture(t, "arm_403_authorization_failed.json"))

	rep := runDoctorInto(t)
	if !strings.Contains(rep.Diagnosis.Summary, "WRONG SERVICE PRINCIPAL") {
		t.Fatalf("want a wrong-principal verdict: %+v", rep.Diagnosis)
	}
	if !strings.Contains(rep.Diagnosis.Summary, testActualOID) {
		t.Errorf("summary must name the oid in use: %s", rep.Diagnosis.Summary)
	}
}

func TestDoctorUnmappedDenialIsAGrantMissEndToEnd(t *testing.T) {
	stubARM(t, testExpectedOID, http.StatusForbidden, fixture(t, "law_error_unmapped_code.json"))
	rep := runDoctorInto(t)
	if rep.Diagnosis.Known {
		t.Fatalf("want Known:false, got %+v", rep.Diagnosis)
	}
	if len(rep.Remediation) != 0 {
		t.Fatalf("a GRANT-MISS must emit no command, got %+v", rep.Remediation)
	}
}

func TestDoctorHealthyConnectorNeedsNoRemediation(t *testing.T) {
	stubARM(t, testExpectedOID, http.StatusOK, `{"value":[]}`)
	rep := runDoctorInto(t)
	if !rep.Diagnosis.Known || len(rep.Remediation) != 0 {
		t.Fatalf("healthy connector: %+v", rep)
	}
}

// --- The sibling contract mallcop's ExecConnector depends on ---

func TestMain(m *testing.M) {
	if os.Getenv("MALLCOP_CONNECTOR_SUBPROCESS") == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

func TestDoctorFlagExitsZeroAndPrintsOneJSONReport(t *testing.T) {
	cmd := exec.Command(os.Args[0], "--doctor", "--subscription-id", testSubscription)
	cmd.Env = append(os.Environ(), "MALLCOP_CONNECTOR_SUBPROCESS=1",
		"AZURE_TENANT_ID=", "AZURE_CLIENT_ID=", "AZURE_CLIENT_SECRET=")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("--doctor must exit 0 even when it finds a problem: %v\nstderr: %s", err, stderr.String())
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
	if rep.ConnectorID != "azure-"+testSubscription {
		t.Errorf("connector_id = %q", rep.ConnectorID)
	}
	if !rep.Diagnosis.Known || !strings.Contains(rep.Diagnosis.Summary, "AZURE_TENANT_ID") {
		t.Errorf("missing credentials should be a named, known state: %+v", rep.Diagnosis)
	}
}

func TestScanPathStillFailsLoudWithoutCredentials(t *testing.T) {
	cmd := exec.Command(os.Args[0], "--subscription-id", testSubscription)
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
