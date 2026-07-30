package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop-connectors/internal/doctor"
)

// lawLastVerifiedLive stamps when mallcop last proved this connector's Azure-SP
// remediations against a LIVE Azure account (design §6 safety property 4).
//
// 2026-07-27: the resource-context access-mode diagnosis and its fix were both
// proven live on example-project prod — the workspace query returned
// `403 InsufficientAccessError` while a workspace-scoped Log Analytics Reader
// assignment was in place and being ignored (<operator deploy repo, private> run
// 30295666850), and flipping enableLogAccessUsingOnlyResourcePermissions to
// false made the same scan green.
//
// This is deliberately NOT bumped by hand on every release: past
// doctor's staleness threshold the emitted commands present themselves as
// "proposed but unverified", which is the honest state until a CI eval job
// re-proves them.
var lawLastVerifiedLive = time.Date(2026, 7, 27, 0, 0, 0, 0, time.UTC)

// workspaceARMAPIVersion is the API version for the ARM control-plane GET on a
// Log Analytics workspace.
const workspaceARMAPIVersion = "2022-10-01"

// parseWorkspaceResourceID splits a Log Analytics workspace ARM id into the
// three things an emitted `az` command has to be scoped by. It returns empty
// strings for anything the id did not contain — a partially-known scope must
// narrow what the doctor is willing to emit, never be filled in with a guess.
func parseWorkspaceResourceID(id string) (subscriptionID, resourceGroup, workspaceName string) {
	parts := strings.Split(strings.TrimPrefix(id, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		switch strings.ToLower(parts[i]) {
		case "subscriptions":
			subscriptionID = parts[i+1]
		case "resourcegroups":
			resourceGroup = parts[i+1]
		case "workspaces":
			workspaceName = parts[i+1]
		}
	}
	return subscriptionID, resourceGroup, workspaceName
}

// expectedPrincipal reads the identity the operator DECLARED this connector
// should authenticate as. Undeclared means no wrong-principal verdict is ever
// rendered — the doctor does not invent an expectation.
func expectedPrincipal() doctor.Expected {
	return doctor.Expected{
		ObjectID:    os.Getenv("AZURE_EXPECTED_PRINCIPAL_OBJECT_ID"),
		AppID:       os.Getenv("AZURE_EXPECTED_PRINCIPAL_APP_ID"),
		DisplayName: os.Getenv("AZURE_EXPECTED_PRINCIPAL_NAME"),
	}
}

// newAzureSPDoctor builds the Azure service-principal doctor for this
// connector. Every network call it makes is the connector's OWN call, issued
// through the same code the scan path uses.
func newAzureSPDoctor(connectorID, workspaceID, workspaceResourceID, tenantID, clientID, clientSecret string) *doctor.AzureSP {
	sub, rg, ws := parseWorkspaceResourceID(workspaceResourceID)
	client := http.DefaultClient

	return &doctor.AzureSP{
		Target: doctor.Target{
			ConnectorID:         connectorID,
			SubscriptionID:      sub,
			ResourceGroup:       rg,
			WorkspaceName:       ws,
			WorkspaceResourceID: workspaceResourceID,
		},
		Expected:         expectedPrincipal(),
		LastVerifiedLive: lawLastVerifiedLive,
		DataPlaneScope:   lawScope,

		MintToken: func(_ context.Context, scope string) (string, error) {
			// getAccessToken never logs or echoes the secret it sends; its
			// error carries only AAD's own response body.
			return getAccessToken(tenantID, clientID, clientSecret, scope)
		},

		DataPlaneCall: func(ctx context.Context, token string) doctor.CallOutcome {
			c := &connector{client: client, accessToken: token, workspaceID: workspaceID}
			// Zero floor: the doctor asks whether the query is ALLOWED, so it
			// issues the widest form of the connector's own query. Its rows
			// are never emitted as events.
			status, body, err := c.queryRaw(ctx, time.Time{})
			if err != nil {
				return doctor.CallOutcome{Err: err.Error()}
			}
			return doctor.CallOutcome{Status: status, Body: body}
		},

		ControlPlaneCall: func(ctx context.Context, armToken string) doctor.CallOutcome {
			if workspaceResourceID == "" {
				return doctor.CallOutcome{
					Err: "no --workspace-resource-id configured, so the workspace's ARM record cannot be read",
				}
			}
			return armGet(ctx, client, armToken,
				managementBase+workspaceResourceID+"?api-version="+workspaceARMAPIVersion)
		},
	}
}

// armGet performs a control-plane GET and records its outcome as evidence. It
// never returns an error: a failed control-plane read is itself a fact the
// diagnosis has to weigh, not a reason to abort the diagnosis.
func armGet(ctx context.Context, client *http.Client, token, rawURL string) doctor.CallOutcome {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return doctor.CallOutcome{Err: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return doctor.CallOutcome{Err: err.Error()}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return doctor.CallOutcome{Status: resp.StatusCode, Err: err.Error()}
	}
	return doctor.CallOutcome{Status: resp.StatusCode, Body: string(body)}
}

// emitReport writes the ONE JSON DiagnosisReport object --doctor contracts to
// print on stdout. mallcop's connect/exec ExecConnector.Diagnose parses exactly
// this and treats a NON-ZERO exit as "this sibling does not support --doctor",
// so a doctor run that found a problem still exits 0 — the problem is in the
// report, not in the exit code.
func emitReport(w io.Writer, report doctor.DiagnosisReport) error {
	enc := json.NewEncoder(w)
	return enc.Encode(report)
}

// runDoctor is the --doctor path. It returns no error for a DIAGNOSED failure;
// only a failure to print the report is an error.
func runDoctor(ctx context.Context, w io.Writer, connectorID, workspaceID, workspaceResourceID, tenantID, clientID, clientSecret string) error {
	if tenantID == "" || clientID == "" || clientSecret == "" {
		return emitReport(w, doctor.DiagnosisReport{
			ConnectorID: connectorID,
			Diagnosis: doctor.Diagnosis{
				Known: true,
				Summary: "AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET are not all set, so this " +
					"connector has no identity to diagnose",
				Confidence: 1,
			},
			Remediation: []doctor.RemediationOption{{
				Command: "export AZURE_TENANT_ID=<tenant-guid> AZURE_CLIENT_ID=<app-id> " +
					"AZURE_CLIENT_SECRET=<secret>  # set these where the connector runs",
				BlastRadius: "Grants nothing. This only tells the connector which existing service principal " +
					"to authenticate as.",
			}},
		})
	}
	d := newAzureSPDoctor(connectorID, workspaceID, workspaceResourceID, tenantID, clientID, clientSecret)
	return emitReport(w, d.Run(ctx))
}

// doctorConnectorID names this connector in its report. It matches the id the
// mallcop config gives the connector when it is not overridden.
func doctorConnectorID(workspaceResourceID, workspaceID string) string {
	if _, _, ws := parseWorkspaceResourceID(workspaceResourceID); ws != "" {
		return fmt.Sprintf("loganalytics-%s", ws)
	}
	return "loganalytics-" + workspaceID
}
