// Package doctor implements the Azure service-principal SELF-DIAGNOSIS family
// (design docs/design/onboarding-self-service.md §3/§6/§7) for the connector
// sibling binaries in this module.
//
// It is hand-written, code-first Go — Probe/Diagnose/Remediate/Confirm are
// real functions with real branching, NOT a table of failure signatures walked
// by a generic interpreter (R2 hard invariant, docs/design-rulings.md). The
// branching in Diagnose reads a locally-decoded JWT, parses the provider's own
// 403 body, and consults an ALTERNATE-SCOPE control-plane probe to tell two
// deficiencies apart that are byte-identical at the data plane.
//
// TRUST BOUNDARY (design §6, hard): this package NEVER runs a grant and NEVER
// requests elevated rights. It only ever EMITS command text the operator reads
// and decides to run. It also never logs, echoes, or serializes a bearer token
// or client secret — the only credential material it touches is a JWT it
// decodes in memory to read the identity claims, and only those claims (never
// the token) reach a report.
//
// # Wire compatibility with the mallcop kernel
//
// The types below MIRROR github.com/mallcop-app/mallcop/core/connect's
// self-diagnosis kernel (Diagnosis, RemediationOption, ConfirmResult,
// DiagnosisReport, ShellCommand — added by mallcoppro-b1f) FIELD-FOR-FIELD AND
// JSON-TAG-FOR-JSON-TAG. They are re-declared here rather than imported because
// mallcop-connectors is a SEPARATE Go module that deliberately does not depend
// on mallcop: mallcop execs these binaries across a process boundary and parses
// their stdout, so the contract between the two modules is the JSON on the
// wire, not a shared Go type. report_kernel_test.go pins that contract by
// decoding this package's output into a verbatim copy of the kernel structs
// with DisallowUnknownFields.
package doctor

import "time"

// ShellCommand is the least-privilege command an operator runs by hand to
// apply a RemediationOption. This package NEVER executes it.
type ShellCommand string

// Diagnosis is what Diagnose turns a Probe into: either a known, named
// deficiency, or Known:false — a GRANT-MISS the corpus has not mapped yet
// (design §3/§4).
type Diagnosis struct {
	Known      bool    `json:"known"`
	Summary    string  `json:"summary"`
	Confidence float64 `json:"confidence"`
}

// RemediationOption is one ranked, narrowest-first fix. The product never runs
// Command — only the operator does.
type RemediationOption struct {
	Command     ShellCommand  `json:"command"`
	BlastRadius string        `json:"blast_radius"`
	KnownIssues []string      `json:"known_issues,omitempty"`
	DryRun      *ShellCommand `json:"dry_run,omitempty"`
}

// ConfirmResult is what Confirm returns after re-probing immediately following
// an operator-applied RemediationOption.
type ConfirmResult struct {
	Resolved  bool      `json:"resolved"`
	Diagnosis Diagnosis `json:"diagnosis"`
	CheckedAt time.Time `json:"checked_at"`
}

// DiagnosisReport is the structured payload a --doctor run prints as ONE JSON
// object on stdout. mallcop's connect/exec ExecConnector.Diagnose parses it
// straight back into connect.DiagnosisReport.
type DiagnosisReport struct {
	ConnectorID string              `json:"connector_id,omitempty"`
	Diagnosis   Diagnosis           `json:"diagnosis"`
	Remediation []RemediationOption `json:"remediation,omitempty"`
}

// dryRun is a small helper so call sites can attach a preview command without
// a named temporary at every option.
func dryRun(s string) *ShellCommand {
	c := ShellCommand(s)
	return &c
}
