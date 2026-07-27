package normalize

import "testing"

// TestACRPushIsDependencyAdd uses REAL values captured from
// acrnostrrelayprod (`az acr repository show-manifests -n acrnostrrelayprod
// --repository nostr-relay-prod`, 2026-07-22): repository "nostr-relay-prod",
// tag "mallcoppro-813", digest
// sha256:a598cf1f801a80d5d822772d4da4de4759069cc48a60c102231bc5aadaca20b4 —
// the real image pushed by this session's own deploy-prod.yml run. Type MUST
// be byte-equal to mallcop/core/detect/dependency_tamper.go's
// depTamperEventTypes map key "dependency_add" (verified by reading that file
// directly, 2026-07-22) so a registry push reaches the dependency-tamper
// gate.
func TestACRPushIsDependencyAdd(t *testing.T) {
	got := ACR("Push", "nostr-relay-prod", "mallcoppro-813",
		"sha256:a598cf1f801a80d5d822772d4da4de4759069cc48a60c102231bc5aadaca20b4",
		"mallcop-deploy-sp", "20.42.10.7", "acrnostrrelayprod.azurecr.io", "Success")
	if len(got) != 1 {
		t.Fatalf("want 1 result, got %d: %+v", len(got), got)
	}
	r := got[0]
	if r.Type != "dependency_add" {
		t.Errorf("Type = %q, want dependency_add (dependency_tamper.go's gate literal)", r.Type)
	}
	p := decode(t, r, map[string]any{"OperationName": "Push"})
	if p["package"] != "nostr-relay-prod" {
		t.Errorf("package = %v, want nostr-relay-prod", p["package"])
	}
	if p["ecosystem"] != "oci" {
		t.Errorf("ecosystem = %v, want oci", p["ecosystem"])
	}
	if p["new_version"] != "mallcoppro-813" {
		t.Errorf("new_version = %v, want mallcoppro-813", p["new_version"])
	}
	if p["actual_hash"] != "sha256:a598cf1f801a80d5d822772d4da4de4759069cc48a60c102231bc5aadaca20b4" {
		t.Errorf("actual_hash = %v", p["actual_hash"])
	}
	if p["registry"] != "acrnostrrelayprod.azurecr.io" {
		t.Errorf("registry = %v", p["registry"])
	}
	if p["direct"] != true {
		t.Errorf("direct = %v, want true (a Push is a new direct dependency, dependency_tamper.go Rule 4)", p["direct"])
	}
	if p["action"] != "push" {
		t.Errorf("action = %v, want push", p["action"])
	}
	raw, ok := p["raw"].(map[string]any)
	if !ok {
		t.Fatalf("payload missing raw sub-object: %+v", p)
	}
	if raw["OperationName"] != "Push" {
		t.Errorf("raw.OperationName = %v, want Push (verbatim source row preserved)", raw["OperationName"])
	}
}

// TestACRDeleteIsDependencyAddNotDirect asserts a Delete reaches the SAME
// gate Type as Push (both are "the artifact that runs the relay changed")
// but never sets Direct, so dependency_tamper.go's Rule 4 ("new direct
// dependency added") never fires spuriously for content leaving the
// registry.
func TestACRDeleteIsDependencyAddNotDirect(t *testing.T) {
	got := ACR("Delete", "nostr-relay-prod", "c96-1",
		"sha256:22c17dd55a99b3fcc4099ee4c52ae5babab07e69d7a1eb5ca6ef8c4978817cea",
		"operator@3dl.dev", "203.0.113.9", "acrnostrrelayprod.azurecr.io", "Success")
	if len(got) != 1 {
		t.Fatalf("want 1 result, got %d: %+v", len(got), got)
	}
	r := got[0]
	if r.Type != "dependency_add" {
		t.Errorf("Type = %q, want dependency_add", r.Type)
	}
	p := decode(t, r, map[string]any{})
	if _, present := p["direct"]; present {
		t.Errorf("direct should be absent (falsy) for a Delete, got %v", p["direct"])
	}
	if p["action"] != "delete" {
		t.Errorf("action = %v, want delete", p["action"])
	}
}

// TestACRImportImageIsDependencyAddDirect asserts importImage (ACR's
// operation for `az acr import`, verified live 2026-07-27 landing in
// ContainerRegistryRepositoryEvents as its own distinct OperationName) reaches
// the SAME gate Type as Push, "dependency_add", and sets Direct — an import
// pulls an image from an arbitrary external source registry into ours, which
// ADDS a new direct dependency exactly like a Push does, so
// dependency_tamper.go's Rule 4 must fire on it too.
func TestACRImportImageIsDependencyAddDirect(t *testing.T) {
	got := ACR("importImage", "someimage", "v1",
		"sha256:b6f9c3e2a1d8f7e6c5b4a3928170695847362f1e0d9c8b7a6958473625140abc",
		"mallcop-deploy-sp", "20.42.10.7", "acrnostrrelayprod.azurecr.io", "Success")
	if len(got) != 1 {
		t.Fatalf("want 1 result, got %d: %+v", len(got), got)
	}
	r := got[0]
	if r.Type != "dependency_add" {
		t.Errorf("Type = %q, want dependency_add (dependency_tamper.go's gate literal)", r.Type)
	}
	p := decode(t, r, map[string]any{"OperationName": "importImage"})
	if p["package"] != "someimage" {
		t.Errorf("package = %v, want someimage", p["package"])
	}
	if p["direct"] != true {
		t.Errorf("direct = %v, want true (importImage adds a new direct dependency, dependency_tamper.go Rule 4)", p["direct"])
	}
	if p["action"] != "importimage" {
		t.Errorf("action = %v, want importimage", p["action"])
	}
}

// TestACRPullFallsThroughToCatchAll asserts a read-shaped operation never
// reaches dependency_add — Pull carries no supply-chain-mutation signal.
// (Defensive: cmd/acrpush's KQL already filters OperationName server-side to
// Push/Delete only, so a live Pull row should never actually reach this
// function — this test guards the function's own behavior independently of
// that KQL filter.)
func TestACRPullFallsThroughToCatchAll(t *testing.T) {
	got := ACR("Pull", "nostr-relay-prod", "mallcoppro-813", "sha256:abc",
		"anonymous", "198.51.100.4", "acrnostrrelayprod.azurecr.io", "Success")
	if len(got) != 1 {
		t.Fatalf("want 1 result, got %d: %+v", len(got), got)
	}
	if got[0].Type != CatchAll {
		t.Errorf("Type = %q, want CatchAll for a Pull", got[0].Type)
	}
}
