package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/mallcop-app/mallcop-connectors/internal/doctor"
)

// armScope is the OAuth2 scope this connector's own Activity Log read needs.
// It is the SAME string getAccessToken hardcodes at the token request
// (main.go's "https://management.azure.com/.default"); naming it here keeps
// the doctor's audience check comparing against what the scan path really asks
// for.
const armScope = doctor.ScopeARM

// azureLastVerifiedLive stamps when mallcop last proved this connector's
// Azure-SP remediations against a LIVE Azure account (design §6 safety
// property 4). 2026-07-27: an ARM `403 AuthorizationFailed` naming a denied
// action and scope was observed live (<operator infra repo, private> run 30289332141) and
// the scope-exact role assignment it implies was what unblocked the deploy.
//
// Past internal/doctor's staleness threshold every emitted command presents
// itself as "proposed but unverified", which is the honest state until a CI
// eval job re-proves it.
var azureLastVerifiedLive = time.Date(2026, 7, 27, 0, 0, 0, 0, time.UTC)

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

// newAzureSPDoctor builds the Azure service-principal doctor for the Activity
// Log connector. Its data plane IS ARM, so there is no separate control plane
// to probe at an alternate scope — ARM's own AuthorizationFailed body names
// the denied action and scope, which is the disambiguation the Log Analytics
// plane cannot give.
func newAzureSPDoctor(connectorID, subscriptionID, tenantID, clientID, clientSecret string) *doctor.AzureSP {
	client := http.DefaultClient
	return &doctor.AzureSP{
		Target: doctor.Target{
			ConnectorID:    connectorID,
			SubscriptionID: subscriptionID,
		},
		Expected:         expectedPrincipal(),
		LastVerifiedLive: azureLastVerifiedLive,
		DataPlaneScope:   armScope,

		MintToken: func(_ context.Context, _ string) (string, error) {
			// getAccessToken already hardcodes the ARM scope, which is the
			// only scope this connector uses. It never logs or echoes the
			// secret it sends.
			return getAccessToken(tenantID, clientID, clientSecret)
		},

		DataPlaneCall: func(ctx context.Context, token string) doctor.CallOutcome {
			c := &connector{client: client, accessToken: token, subscriptionID: subscriptionID}
			// The FIRST page of the connector's own Activity Log query, with
			// no $filter: the doctor asks whether the read is ALLOWED. Its
			// rows are never emitted as events.
			u := fmt.Sprintf(activityLogBase, subscriptionID) + "?" +
				url.Values{"api-version": {apiVersion}}.Encode()
			resp, err := c.get(ctx, u)
			if err != nil {
				return doctor.CallOutcome{Err: err.Error()}
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return doctor.CallOutcome{Status: resp.StatusCode, Err: err.Error()}
			}
			return doctor.CallOutcome{Status: resp.StatusCode, Body: string(body)}
		},
	}
}

// emitReport writes the ONE JSON DiagnosisReport object --doctor contracts to
// print on stdout. mallcop's connect/exec ExecConnector.Diagnose parses exactly
// this and treats a NON-ZERO exit as "this sibling does not support --doctor",
// so a doctor run that found a problem still exits 0.
func emitReport(w io.Writer, report doctor.DiagnosisReport) error {
	return json.NewEncoder(w).Encode(report)
}

// runDoctor is the --doctor path. It returns no error for a DIAGNOSED failure;
// only a failure to print the report is an error.
func runDoctor(ctx context.Context, w io.Writer, subscriptionID, tenantID, clientID, clientSecret string) error {
	connectorID := "azure-" + subscriptionID
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
	d := newAzureSPDoctor(connectorID, subscriptionID, tenantID, clientID, clientSecret)
	return emitReport(w, d.Run(ctx))
}
