package doctor

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// This file pins the CROSS-MODULE WIRE CONTRACT. mallcop execs these sibling
// binaries with --doctor and json.Unmarshals their stdout straight into
// connect.DiagnosisReport (mallcop connect/exec/exec.go). mallcop-connectors
// deliberately does not import mallcop, so the contract cannot be enforced by
// the type system — it is enforced here, by decoding this package's real
// output into a VERBATIM COPY of the kernel structs.
//
// Source of the copy: github.com/mallcop-app/mallcop core/connect/diagnose.go
// as merged by mallcoppro-b1f. If the kernel changes, this file fails and this
// package must be updated with it — that is the point.
//
// The decode uses DisallowUnknownFields, so a key this package emits that the
// kernel does not know is a FAILURE, not a silently dropped field. Combined
// with the reflect-based tag comparison below (which catches the reverse: a
// kernel field this package never emits), the two directions are covered.

type kernelShellCommand string

// kernelProbeResult is the verbatim copy of core/connect.ProbeResult. The
// kernel deliberately keeps it opaque — "its contents are owned by the
// connector family that produces it… core/connect only needs the envelope to
// exist so Diagnose has something to consume; it does not interpret Raw
// itself" — so this family's Evidence is NOT assignable to it, and pretending
// otherwise is what the previous version of this file did.
type kernelProbeResult struct {
	Raw map[string]any `json:"raw,omitempty"`
}

type kernelDiagnosis struct {
	Known      bool    `json:"known"`
	Summary    string  `json:"summary"`
	Confidence float64 `json:"confidence"`
}

type kernelRemediationOption struct {
	Command     kernelShellCommand  `json:"command"`
	BlastRadius string              `json:"blast_radius"`
	KnownIssues []string            `json:"known_issues,omitempty"`
	DryRun      *kernelShellCommand `json:"dry_run,omitempty"`
}

type kernelConfirmResult struct {
	Resolved  bool            `json:"resolved"`
	Diagnosis kernelDiagnosis `json:"diagnosis"`
	CheckedAt time.Time       `json:"checked_at"`
}

type kernelDiagnosisReport struct {
	ConnectorID string                    `json:"connector_id,omitempty"`
	Diagnosis   kernelDiagnosis           `json:"diagnosis"`
	Remediation []kernelRemediationOption `json:"remediation,omitempty"`
}

// jsonTags returns the ordered json tag names of a struct type.
func jsonTags(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		out = append(out, t.Field(i).Tag.Get("json"))
	}
	return out
}

func TestReportTypesMatchTheKernelTagForTag(t *testing.T) {
	pairs := []struct {
		name       string
		ours, them reflect.Type
	}{
		{"Diagnosis", reflect.TypeOf(Diagnosis{}), reflect.TypeOf(kernelDiagnosis{})},
		{"RemediationOption", reflect.TypeOf(RemediationOption{}), reflect.TypeOf(kernelRemediationOption{})},
		{"ConfirmResult", reflect.TypeOf(ConfirmResult{}), reflect.TypeOf(kernelConfirmResult{})},
		{"DiagnosisReport", reflect.TypeOf(DiagnosisReport{}), reflect.TypeOf(kernelDiagnosisReport{})},
	}
	for _, p := range pairs {
		ours, them := jsonTags(p.ours), jsonTags(p.them)
		if !reflect.DeepEqual(ours, them) {
			t.Errorf("%s json tags drifted from the kernel:\n ours: %v\n kernel: %v", p.name, ours, them)
		}
	}
}

// The real --doctor output for the headline case must decode into the kernel
// struct with NO unknown fields and with every value preserved.
func TestRealDoctorReportRoundTripsIntoTheKernelStruct(t *testing.T) {
	token := makeToken(t, appTokenClaims(expectedOID, expectedAppID, "https://api.loganalytics.io"))
	cp := CallOutcome{Status: 200, Body: loadFixture(t, "arm_workspace_resource_context.json")}
	d := newLAWDoctor(t, token, CallOutcome{
		Status: 403, Body: loadFixture(t, "law_403_insufficient_access.json"),
	}, &cp)

	rep := d.Run(context.Background())
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}

	var got kernelDiagnosisReport
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("--doctor output does not decode into connect.DiagnosisReport: %v\npayload: %s", err, raw)
	}

	if got.ConnectorID != rep.ConnectorID {
		t.Errorf("connector_id lost: %q vs %q", got.ConnectorID, rep.ConnectorID)
	}
	if got.Diagnosis.Known != rep.Diagnosis.Known ||
		got.Diagnosis.Summary != rep.Diagnosis.Summary ||
		got.Diagnosis.Confidence != rep.Diagnosis.Confidence {
		t.Errorf("diagnosis lost in transit: %+v vs %+v", got.Diagnosis, rep.Diagnosis)
	}
	if len(got.Remediation) != len(rep.Remediation) {
		t.Fatalf("remediation count %d != %d", len(got.Remediation), len(rep.Remediation))
	}
	for i := range got.Remediation {
		g, w := got.Remediation[i], rep.Remediation[i]
		if string(g.Command) != string(w.Command) || g.BlastRadius != w.BlastRadius {
			t.Errorf("option %d lost in transit: %+v vs %+v", i, g, w)
		}
		if !reflect.DeepEqual(g.KnownIssues, w.KnownIssues) {
			t.Errorf("option %d known_issues lost: %v vs %v", i, g.KnownIssues, w.KnownIssues)
		}
		if (g.DryRun == nil) != (w.DryRun == nil) {
			t.Errorf("option %d dry_run presence changed", i)
		}
		if g.DryRun != nil && string(*g.DryRun) != string(*w.DryRun) {
			t.Errorf("option %d dry_run lost: %q vs %q", i, *g.DryRun, *w.DryRun)
		}
	}

	// Every non-empty field of the headline report must actually be populated;
	// a round-trip of an empty report proves nothing.
	if got.ConnectorID == "" || got.Diagnosis.Summary == "" || len(got.Remediation) == 0 ||
		got.Remediation[0].BlastRadius == "" || got.Remediation[0].DryRun == nil ||
		len(got.Remediation[0].KnownIssues) == 0 {
		t.Fatalf("round-trip did not carry a fully populated report: %+v", got)
	}
}

func TestConfirmResultRoundTripsIntoTheKernelStruct(t *testing.T) {
	token := makeToken(t, appTokenClaims(expectedOID, expectedAppID, "https://api.loganalytics.io"))
	cp := CallOutcome{Status: 200, Body: loadFixture(t, "arm_workspace_workspace_context.json")}
	d := newLAWDoctor(t, token, CallOutcome{
		Status: 403, Body: loadFixture(t, "law_403_insufficient_access.json"),
	}, &cp)

	rep := d.Run(context.Background())
	res, _ := d.Confirm(context.Background(), rep.Remediation[0])

	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal confirm result: %v", err)
	}
	var got kernelConfirmResult
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("ConfirmResult does not decode into connect.ConfirmResult: %v\npayload: %s", err, raw)
	}
	if got.Resolved != res.Resolved || got.Diagnosis.Summary != res.Diagnosis.Summary {
		t.Errorf("confirm result lost in transit: %+v vs %+v", got, res)
	}
	if got.CheckedAt.IsZero() {
		t.Error("checked_at did not survive the round trip")
	}
}

// TestRemediateAndConfirmSatisfyTheKernelFunctionShapes pins the two GrantClaim
// function fields whose signatures are ENTIRELY made of kernel-mirrored types.
// The right-hand sides use only this package's Diagnosis / RemediationOption /
// ConfirmResult, and TestReportTypesMatchTheKernelTagForTag above pins those
// tag-for-tag against the kernel copies — so these assignments genuinely fail
// when the kernel's shapes drift.
//
// Probe and Diagnose are deliberately NOT asserted here. Their signatures name
// core/connect.ProbeResult, which this package cannot be assignable to: the
// kernel defines ProbeResult as an opaque `Raw map[string]any` envelope whose
// contents it never interprets, while this family's Probe returns a typed
// Evidence. Writing `var _ func(Evidence) (Diagnosis, error) = a.Diagnose` — as
// an earlier version of this file did — compares this package against ITSELF
// and cannot fail on kernel drift. What is actually provable is below.
func TestRemediateAndConfirmSatisfyTheKernelFunctionShapes(t *testing.T) {
	a := &AzureSP{}
	var (
		_ func(Diagnosis) []RemediationOption                             = a.Remediate
		_ func(context.Context, RemediationOption) (ConfirmResult, error) = a.Confirm
	)
}

// TestEvidenceSurvivesTheKernelProbeResultEnvelope is the real Probe/Diagnose
// claim: mallcop hands a connector family an opaque `Raw map[string]any` to
// carry whatever its Probe gathered, so the binding question is whether THIS
// family's Evidence fits through that envelope without losing anything Diagnose
// branches on. The adapters below are exactly the lift/lower a kernel-side
// GrantClaim would need, and the test asserts the diagnosis is identical on
// both sides of the round trip. It fails if Evidence ever grows a
// diagnosis-relevant field the envelope cannot carry (an unexported field, a
// func, a channel) — which is the drift that would actually break the wiring.
func TestEvidenceSurvivesTheKernelProbeResultEnvelope(t *testing.T) {
	token := makeToken(t, appTokenClaims(expectedOID, expectedAppID, "https://api.loganalytics.io"))
	cp := CallOutcome{Status: 200, Body: loadFixture(t, "arm_workspace_resource_context.json")}
	a := newLAWDoctor(t, token, CallOutcome{
		Status: 403, Body: loadFixture(t, "law_403_insufficient_access.json"),
	}, &cp)

	// lift: Evidence -> the kernel's opaque envelope.
	lift := func(ev Evidence) (kernelProbeResult, error) {
		b, err := json.Marshal(ev)
		if err != nil {
			return kernelProbeResult{}, err
		}
		var raw map[string]any
		if err := json.Unmarshal(b, &raw); err != nil {
			return kernelProbeResult{}, err
		}
		return kernelProbeResult{Raw: raw}, nil
	}
	// lower: the envelope -> Evidence, on the far side of the boundary.
	lower := func(pr kernelProbeResult) (Evidence, error) {
		b, err := json.Marshal(pr.Raw)
		if err != nil {
			return Evidence{}, err
		}
		var ev Evidence
		return ev, json.Unmarshal(b, &ev)
	}

	// These two assignments DO exercise the kernel's declared shapes, because
	// the envelope type is the kernel's, not this package's.
	var kernelProbe func(context.Context) (kernelProbeResult, error) = func(ctx context.Context) (kernelProbeResult, error) {
		ev, err := a.Probe(ctx)
		if err != nil {
			return kernelProbeResult{}, err
		}
		return lift(ev)
	}
	var kernelDiagnose func(kernelProbeResult) (kernelDiagnosis, error) = func(pr kernelProbeResult) (kernelDiagnosis, error) {
		ev, err := lower(pr)
		if err != nil {
			return kernelDiagnosis{}, err
		}
		d, err := a.Diagnose(ev)
		return kernelDiagnosis(d), err
	}

	direct, err := a.Probe(context.Background())
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	want, err := a.Diagnose(direct)
	if err != nil {
		t.Fatalf("diagnose: %v", err)
	}
	if !want.Known || want.Summary == "" {
		t.Fatalf("round-tripping an empty diagnosis proves nothing: %+v", want)
	}

	pr, err := kernelProbe(context.Background())
	if err != nil {
		t.Fatalf("probe through the kernel envelope: %v", err)
	}
	if len(pr.Raw) == 0 {
		t.Fatal("Evidence lifted into an EMPTY kernel envelope — nothing would reach Diagnose")
	}
	got, err := kernelDiagnose(pr)
	if err != nil {
		t.Fatalf("diagnose through the kernel envelope: %v", err)
	}
	if got != kernelDiagnosis(want) {
		t.Errorf("the kernel's ProbeResult envelope lost evidence Diagnose branches on:\n"+
			" direct: %+v\n via envelope: %+v", want, got)
	}
}
