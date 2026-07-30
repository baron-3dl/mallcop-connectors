package doctor

import (
	"context"
	"fmt"
)

// GrantMissError is what Confirm returns when a remediation was applied and
// the deficiency PERSISTED. This is the headline case the whole design exists
// for (design §3 / NEW-A19): on 2026-07-27 a workspace-scoped Log Analytics
// Reader grant was applied, reported success, and the query kept returning
// 403 — and from an emit-and-forget vantage the remediation had "worked", so
// nothing was ever recorded. Confirm turns that silence into an error the
// caller cannot ignore AND a GRANT-MISS row it can persist.
type GrantMissError struct {
	// Applied is the command the operator ran that did not resolve it.
	Applied ShellCommand
	// Diagnosis is the GRANT-MISS (Known:false, per design §4).
	Diagnosis Diagnosis
	// Persisting is the fresh diagnosis from the re-probe, for context.
	Persisting Diagnosis
}

func (e *GrantMissError) Error() string {
	return fmt.Sprintf("GRANT-MISS: remediation was applied but the deficiency persists: %s", e.Persisting.Summary)
}

// Report renders the GRANT-MISS as a DiagnosisReport, so a --doctor --confirm
// run still prints one structured JSON object rather than a bare error.
func (e *GrantMissError) Report(connectorID string) DiagnosisReport {
	return DiagnosisReport{ConnectorID: connectorID, Diagnosis: e.Diagnosis}
}

// Confirm re-Probes IMMEDIATELY after the operator applied a
// RemediationOption. It is the loop-closer, and it is kernel shape rather than
// a per-connector nicety precisely because a Remediate that emits a command
// and walks away never learns that it did not work.
//
// A passing Confirm closes the loop (Resolved:true, nil error). A FAILING
// Confirm — grant applied, problem persists — is itself a high-value
// GRANT-MISS: it returns Resolved:false, a Known:false Diagnosis, AND a
// *GrantMissError, so no caller can mistake it for success.
func (a *AzureSP) Confirm(ctx context.Context, applied RemediationOption) (ConfirmResult, error) {
	ev, err := a.Probe(ctx)
	if err != nil {
		return ConfirmResult{CheckedAt: a.now()}, fmt.Errorf("confirm: re-probe: %w", err)
	}
	as := a.assess(ev)
	a.last = &as

	if as.def == defHealthy {
		return ConfirmResult{
			Resolved:  true,
			Diagnosis: as.diagnosis,
			CheckedAt: ev.CheckedAt,
		}, nil
	}

	miss := Diagnosis{
		// Known:false is what makes this a GRANT-MISS row by the kernel's own
		// semantics (design §4: "Known:false ⇒ emit a GRANT-MISS row"). The
		// corpus knew a remediation for this deficiency; the remediation did
		// not work, so what the corpus knows is now wrong, and that is exactly
		// the thing worth recording.
		Known: false,
		Summary: fmt.Sprintf(
			"GRANT-MISS: the applied remediation did not resolve the deficiency. Applied: %s. "+
				"Still observed: %s", applied.Command, as.diagnosis.Summary),
		Confidence: 0,
	}
	return ConfirmResult{
			Resolved:  false,
			Diagnosis: miss,
			CheckedAt: ev.CheckedAt,
		}, &GrantMissError{
			Applied:    applied.Command,
			Diagnosis:  miss,
			Persisting: as.diagnosis,
		}
}

// Run is the --doctor entry point: Probe → Diagnose → ranked Remediate,
// rendered as the ONE JSON DiagnosisReport object the sibling prints on
// stdout. It never returns an error — an unreadable failure is itself a
// structured Known:false report (a GRANT-MISS), which is what mallcop's
// ExecConnector.Diagnose expects to parse.
func (a *AzureSP) Run(ctx context.Context) DiagnosisReport {
	ev, err := a.Probe(ctx)
	if err != nil {
		return DiagnosisReport{
			ConnectorID: a.Target.ConnectorID,
			Diagnosis: Diagnosis{
				Known:   false,
				Summary: fmt.Sprintf("the doctor could not gather evidence: %v", err),
			},
		}
	}
	d, err := a.Diagnose(ev)
	if err != nil {
		return DiagnosisReport{
			ConnectorID: a.Target.ConnectorID,
			Diagnosis: Diagnosis{
				Known:   false,
				Summary: fmt.Sprintf("the doctor could not interpret its own evidence: %v", err),
			},
		}
	}
	return DiagnosisReport{
		ConnectorID: a.Target.ConnectorID,
		Diagnosis:   d,
		Remediation: a.Remediate(d),
	}
}
