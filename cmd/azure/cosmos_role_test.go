package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// managementBaseOverride points the package-level managementBase var at a
// test server for the duration of the returned restore func (mirrors
// activityLogBaseOverride above / mercury's apiBaseOverride idiom).
func managementBaseOverride(serverURL string) func() {
	orig := managementBase
	managementBase = serverURL
	return func() { managementBase = orig }
}

const cosmosRoleAssignmentResourceID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-nostr-relay-prod/sqlRoleAssignments/ra1"

func serveCosmosRoleAssignment(t *testing.T, statusCode int, body any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != cosmosRoleAssignmentResourceID {
			t.Errorf("request path = %q, want %q", got, cosmosRoleAssignmentResourceID)
		}
		if v := r.URL.Query().Get("api-version"); v != cosmosSQLRoleAPIVersion {
			t.Errorf("api-version = %q, want %q", v, cosmosSQLRoleAPIVersion)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if body != nil {
			json.NewEncoder(w).Encode(body)
		}
	}))
}

// TestResolveCosmosRoleBuiltInDataContributor pins the Data Contributor
// builtin GUID mapping (mallcoppro-32e).
func TestResolveCosmosRoleBuiltInDataContributor(t *testing.T) {
	srv := serveCosmosRoleAssignment(t, http.StatusOK, map[string]any{
		"properties": map[string]any{
			"principalId":      "principal-guid-1",
			"roleDefinitionId": "/subscriptions/s/providers/Microsoft.DocumentDB/databaseAccounts/acct/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002",
		},
	})
	defer srv.Close()
	defer managementBaseOverride(srv.URL)()

	c := &connector{client: srv.Client(), accessToken: "tok"}
	role, principal, ok := c.resolveCosmosRole(cosmosRoleAssignmentResourceID)
	if !ok {
		t.Fatal("resolveCosmosRole: ok = false, want true")
	}
	if role != "Cosmos DB Built-in Data Contributor" {
		t.Errorf("role = %q, want Cosmos DB Built-in Data Contributor", role)
	}
	if principal != "principal-guid-1" {
		t.Errorf("principal = %q, want principal-guid-1", principal)
	}
}

// TestResolveCosmosRoleBuiltInDataReader pins the Data Reader builtin GUID
// mapping.
func TestResolveCosmosRoleBuiltInDataReader(t *testing.T) {
	srv := serveCosmosRoleAssignment(t, http.StatusOK, map[string]any{
		"properties": map[string]any{
			"principalId":      "principal-guid-2",
			"roleDefinitionId": "/subscriptions/s/providers/Microsoft.DocumentDB/databaseAccounts/acct/sqlRoleDefinitions/00000000-0000-0000-0000-000000000001",
		},
	})
	defer srv.Close()
	defer managementBaseOverride(srv.URL)()

	c := &connector{client: srv.Client(), accessToken: "tok"}
	role, principal, ok := c.resolveCosmosRole(cosmosRoleAssignmentResourceID)
	if !ok {
		t.Fatal("resolveCosmosRole: ok = false, want true")
	}
	if role != "Cosmos DB Built-in Data Reader" {
		t.Errorf("role = %q, want Cosmos DB Built-in Data Reader", role)
	}
	if principal != "principal-guid-2" {
		t.Errorf("principal = %q, want principal-guid-2", principal)
	}
}

// TestResolveCosmosRoleCustomRoleFallsBackToGUID: a non-builtin
// roleDefinitionId doesn't get a second GET to resolve its display name --
// it falls back to the raw GUID (last path segment), per spec (one GET only).
func TestResolveCosmosRoleCustomRoleFallsBackToGUID(t *testing.T) {
	customGUID := "11111111-2222-3333-4444-555555555555"
	srv := serveCosmosRoleAssignment(t, http.StatusOK, map[string]any{
		"properties": map[string]any{
			"principalId":      "principal-guid-3",
			"roleDefinitionId": "/subscriptions/s/providers/Microsoft.DocumentDB/databaseAccounts/acct/sqlRoleDefinitions/" + customGUID,
		},
	})
	defer srv.Close()
	defer managementBaseOverride(srv.URL)()

	c := &connector{client: srv.Client(), accessToken: "tok"}
	role, principal, ok := c.resolveCosmosRole(cosmosRoleAssignmentResourceID)
	if !ok {
		t.Fatal("resolveCosmosRole: ok = false, want true")
	}
	if role != customGUID {
		t.Errorf("role = %q, want raw custom GUID %q", role, customGUID)
	}
	if principal != "principal-guid-3" {
		t.Errorf("principal = %q, want principal-guid-3", principal)
	}
}

// TestResolveCosmosRoleNotFoundReturnsFalse: a 404 (or any non-200) must
// return ok=false, not error/panic -- enrichment is best-effort.
func TestResolveCosmosRoleNotFoundReturnsFalse(t *testing.T) {
	srv := serveCosmosRoleAssignment(t, http.StatusNotFound, map[string]any{"error": "not found"})
	defer srv.Close()
	defer managementBaseOverride(srv.URL)()

	c := &connector{client: srv.Client(), accessToken: "tok"}
	_, _, ok := c.resolveCosmosRole(cosmosRoleAssignmentResourceID)
	if ok {
		t.Error("resolveCosmosRole: ok = true on 404, want false")
	}
}

// TestResolveCosmosRoleServerErrorReturnsFalse: a 500 must also degrade
// gracefully.
func TestResolveCosmosRoleServerErrorReturnsFalse(t *testing.T) {
	srv := serveCosmosRoleAssignment(t, http.StatusInternalServerError, map[string]any{"error": "boom"})
	defer srv.Close()
	defer managementBaseOverride(srv.URL)()

	c := &connector{client: srv.Client(), accessToken: "tok"}
	_, _, ok := c.resolveCosmosRole(cosmosRoleAssignmentResourceID)
	if ok {
		t.Error("resolveCosmosRole: ok = true on 500, want false")
	}
}
