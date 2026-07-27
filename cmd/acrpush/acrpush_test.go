package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// queryBaseOverride points the package-level queryBase var at a test server
// for the duration of the returned restore func (same idiom as
// cmd/loganalytics/loganalytics_test.go's queryBaseOverride).
func queryBaseOverride(serverURL string) func() {
	orig := queryBase
	queryBase = serverURL + "/v1/workspaces/%s/query"
	return func() { queryBase = orig }
}

// --- cursor roundtrip / tamper detection (byte-identical pattern to cmd/loganalytics) ---

func TestCursorRoundtrip(t *testing.T) {
	key := sigKey("ws-12345")
	raw := "2026-07-20T15:08:57.6958849Z"

	encoded := encodeCursor(raw, key)
	if encoded == "" {
		t.Fatal("encodeCursor returned empty string")
	}
	decoded, err := decodeCursor(encoded, key)
	if err != nil {
		t.Fatalf("decodeCursor: %v", err)
	}
	if decoded != raw {
		t.Errorf("roundtrip mismatch: got %q, want %q", decoded, raw)
	}
}

func TestCursorTamperDetection(t *testing.T) {
	key := sigKey("ws-abc")
	raw := "2026-07-20T15:08:57Z"

	encoded := encodeCursor(raw, key)
	parts := strings.SplitN(encoded, ".", 2)
	if len(parts) != 2 {
		t.Fatal("encoded cursor has no dot separator")
	}
	payload := []byte(parts[0])
	payload[len(payload)-1] ^= 0x01
	tampered := string(payload) + "." + parts[1]

	_, err := decodeCursor(tampered, key)
	if err == nil {
		t.Fatal("expected error for tampered cursor, got nil")
	}
}

// --- resolveFloor ---

func TestResolveFloorSinceOnly(t *testing.T) {
	key := sigKey("ws-x")
	since := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	floor, err := resolveFloor("", since, key)
	if err != nil {
		t.Fatalf("resolveFloor: %v", err)
	}
	if !floor.Equal(since) {
		t.Errorf("floor = %v, want %v", floor, since)
	}
}

func TestResolveFloorCursorLaterThanSinceWins(t *testing.T) {
	key := sigKey("ws-y")
	since := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	cursorTime := time.Date(2026, 7, 20, 15, 8, 57, 0, time.UTC)
	cursor := encodeCursor(cursorTime.Format(time.RFC3339Nano), key)

	floor, err := resolveFloor(cursor, since, key)
	if err != nil {
		t.Fatalf("resolveFloor: %v", err)
	}
	if !floor.Equal(cursorTime) {
		t.Errorf("floor = %v, want cursor time %v (later of the two)", floor, cursorTime)
	}
}

// --- query: timespan is the ONLY thing that varies; KQL text is constant ---

func TestQueryOmitsTimespanWhenFloorZero(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(lawQueryResponse{Tables: []lawTable{{Name: "PrimaryResult"}}})
	}))
	defer srv.Close()
	defer queryBaseOverride(srv.URL)()

	conn := &connector{client: srv.Client(), accessToken: "tok", workspaceID: "ws-1"}
	if _, err := conn.query(context.Background(), time.Time{}); err != nil {
		t.Fatalf("query: %v", err)
	}
	if gotBody["query"] != kqlQuery {
		t.Errorf("query body's KQL text was not the constant kqlQuery verbatim: %v", gotBody["query"])
	}
	if _, ok := gotBody["timespan"]; ok {
		t.Errorf("timespan should be omitted when floor is zero, got %v", gotBody["timespan"])
	}
	if !strings.Contains(kqlQuery, `OperationName in ("Push", "Delete", "importImage")`) {
		t.Errorf("kqlQuery must filter to Push/Delete/importImage server-side")
	}
}

// --- processTable: parses a fixture built from REAL captured values ---

func loadFixture(t *testing.T, path string) lawQueryResponse {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var resp lawQueryResponse
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatalf("decode fixture %s: %v", path, err)
	}
	return resp
}

// TestProcessTableRealCapturedPushFixture is the TDD anchor for
// mallcoppro-29f's live proof. The fixture's Repository ("nostr-relay-prod"),
// Tag ("mallcoppro-813"), Digest
// (sha256:a598cf1f801a80d5d822772d4da4de4759069cc48a60c102231bc5aadaca20b4),
// and TimeGenerated (2026-07-20T15:08:57.6958849Z) are BYTE-IDENTICAL to the
// real live manifest captured via `az acr repository show-manifests -n
// acrnostrrelayprod --repository nostr-relay-prod` (2026-07-22) — this is the
// actual image this session's own deploy pinned into prod.bicep's
// containerImage default. LoginServer is also the real registry hostname.
// OperationName/Identity/CallerIpAddress/ResultType are the DOCUMENTED table
// shape (Microsoft Learn: learn.microsoft.com/azure/azure-monitor/reference/
// tables/containerregistryrepositoryevents, fetched 2026-07-22) applied to
// those real values — NOT yet a byte-for-byte capture of an actual
// ContainerRegistryRepositoryEvents row, because diagnostic-log ingestion
// had not visibly propagated a live row by the time this item closed (the
// acr-diag-to-law setting was applied ~30min prior; see rd progress on
// mallcoppro-29f for the live poll that was still empty at close). This is
// the item's own documented fallback: prove the query+normalize code path
// against real identifiers, note the propagation-timing gap.
func TestProcessTableRealCapturedPushFixture(t *testing.T) {
	resp := loadFixture(t, "../../internal/normalize/testdata/acr_push_response.json")
	if len(resp.Tables) != 1 {
		t.Fatalf("want 1 table in fixture, got %d", len(resp.Tables))
	}

	events, maxSeen, err := processTable(resp.Tables[0], "org-test")
	if err != nil {
		t.Fatalf("processTable: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 normalized event from the fixture, got %d", len(events))
	}
	ev := events[0]

	if ev.Type != "dependency_add" {
		t.Errorf("Type = %q, want dependency_add (the dependency_tamper.go gate literal)", ev.Type)
	}
	if ev.Source != "acrpush" {
		t.Errorf("Source = %q, want acrpush", ev.Source)
	}
	wantTS := time.Date(2026, 7, 20, 15, 8, 57, 695884900, time.UTC)
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("Timestamp = %v, want %v", ev.Timestamp, wantTS)
	}
	if maxSeen.IsZero() {
		t.Error("maxSeen is zero, want the row's TimeGenerated")
	}

	var p map[string]any
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if p["package"] != "nostr-relay-prod" {
		t.Errorf("payload package = %v, want nostr-relay-prod", p["package"])
	}
	if p["new_version"] != "mallcoppro-813" {
		t.Errorf("payload new_version = %v, want mallcoppro-813", p["new_version"])
	}
	if p["actual_hash"] != "sha256:a598cf1f801a80d5d822772d4da4de4759069cc48a60c102231bc5aadaca20b4" {
		t.Errorf("payload actual_hash = %v", p["actual_hash"])
	}
	if p["direct"] != true {
		t.Errorf("payload direct = %v, want true", p["direct"])
	}
	raw, ok := p["raw"].(map[string]any)
	if !ok {
		t.Fatalf("payload missing raw sub-object: %+v", p)
	}
	if raw["Repository"] != "nostr-relay-prod" {
		t.Errorf("raw.Repository = %v, want nostr-relay-prod (verbatim source row preserved)", raw["Repository"])
	}
}

func TestProcessTableSkipsUnparseableTimestamp(t *testing.T) {
	tbl := lawTable{
		Columns: []lawColumn{
			{Name: "TimeGenerated"}, {Name: "OperationName"}, {Name: "Repository"},
		},
		Rows: [][]any{
			{"not-a-timestamp", "Push", "nostr-relay-prod"},
		},
	}
	events, maxSeen, err := processTable(tbl, "org-test")
	if err != nil {
		t.Fatalf("processTable should not hard-fail on malformed rows: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("want 0 events for an unparseable timestamp, got %d", len(events))
	}
	if !maxSeen.IsZero() {
		t.Errorf("maxSeen = %v, want zero", maxSeen)
	}
}

func TestProcessTableEmptyRowsZeroEventsZeroCursor(t *testing.T) {
	tbl := lawTable{
		Columns: []lawColumn{{Name: "TimeGenerated"}, {Name: "OperationName"}},
		Rows:    [][]any{},
	}
	events, maxSeen, err := processTable(tbl, "org-test")
	if err != nil {
		t.Fatalf("processTable: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("want 0 events for an empty window, got %d", len(events))
	}
	if !maxSeen.IsZero() {
		t.Errorf("maxSeen = %v, want zero (no cursor should advance across an empty poll)", maxSeen)
	}
}

func TestProcessTableDeleteRowNotDirect(t *testing.T) {
	tbl := lawTable{
		Columns: []lawColumn{
			{Name: "TimeGenerated"}, {Name: "OperationName"}, {Name: "Repository"}, {Name: "Tag"}, {Name: "Digest"},
		},
		Rows: [][]any{
			{"2026-07-19T15:29:29.3539934Z", "Delete", "nostr-relay-prod", "c96-1", "sha256:22c17dd55a99b3fcc4099ee4c52ae5babab07e69d7a1eb5ca6ef8c4978817cea"},
		},
	}
	events, _, err := processTable(tbl, "org-test")
	if err != nil {
		t.Fatalf("processTable: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if events[0].Type != "dependency_add" {
		t.Errorf("Type = %q, want dependency_add", events[0].Type)
	}
	var p map[string]any
	json.Unmarshal(events[0].Payload, &p)
	if _, present := p["direct"]; present {
		t.Errorf("direct should be absent for a Delete row, got %v", p["direct"])
	}
}

// --- resolveFloor / validateCursor edge cases ---

func TestValidateCursorRejectsControlCharacters(t *testing.T) {
	if err := validateCursor("abc\x00def"); err == nil {
		t.Fatal("expected error for control character in cursor, got nil")
	}
}

func TestValidateCursorRejectsOverlong(t *testing.T) {
	long := strings.Repeat("a", cursorMaxLen+1)
	if err := validateCursor(long); err == nil {
		t.Fatal("expected error for overlong cursor, got nil")
	}
}
