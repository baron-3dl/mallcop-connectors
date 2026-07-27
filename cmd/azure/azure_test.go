package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop-connectors/internal/normalize"
	"github.com/mallcop-app/mallcop-connectors/pkg/event"
)

// activityLogBaseOverride points the package-level activityLogBase var at a
// test server for the duration of the returned restore func (mirrors
// mercury's apiBaseOverride idiom in cmd/mercury/mercury_test.go).
func activityLogBaseOverride(serverURL string) func() {
	orig := activityLogBase
	activityLogBase = serverURL + "/subscriptions/%s/providers/microsoft.insights/eventtypes/management/values"
	return func() { activityLogBase = orig }
}

func TestCursorRoundtrip(t *testing.T) {
	key := sigKey("sub-12345")
	raw := "https://management.azure.com/subscriptions/sub-12345?nextPage=token123"

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
	key := sigKey("sub-abc")
	raw := "next-link-value"

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
	if !strings.Contains(err.Error(), "signature mismatch") && !strings.Contains(err.Error(), "invalid cursor") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCursorWrongKey(t *testing.T) {
	key1 := sigKey("sub-aaa")
	key2 := sigKey("sub-bbb")
	raw := "cursor-value"

	encoded := encodeCursor(raw, key1)
	_, err := decodeCursor(encoded, key2)
	if err == nil {
		t.Fatal("expected error decoding cursor with wrong key, got nil")
	}
}

func TestNormalizeEntry(t *testing.T) {
	entry := map[string]interface{}{
		"id":     "/subscriptions/sub-123/resourceGroups/rg/providers/foo/operations/bar",
		"caller": "admin@example.com",
		"operationName": map[string]interface{}{
			"value": "Microsoft.Authorization/roleAssignments/write",
		},
		"eventTimestamp": "2024-06-01T12:00:00Z",
		"properties": map[string]interface{}{
			"roleDefinitionName": "Owner",
			"principalId":        "victim-obj-id",
		},
		"status": map[string]interface{}{
			"value": "Succeeded",
		},
	}

	evs, tsReliable, err := normalizeEntry(entry, "sub-123")
	if err != nil {
		t.Fatalf("normalizeEntry: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	ev := evs[0]

	if ev.Source != "azure" {
		t.Errorf("Source = %q, want azure", ev.Source)
	}
	if !tsReliable {
		t.Error("tsReliable = false, want true when eventTimestamp is present and parseable")
	}
	// The raw operationName gates no detector; it MUST map to canonical
	// "role_assignment" for the priv-escalation detector to fire.
	if ev.Type != "role_assignment" {
		t.Errorf("Type = %q, want role_assignment", ev.Type)
	}
	if ev.Actor != "admin@example.com" {
		t.Errorf("Actor = %q, want admin@example.com", ev.Actor)
	}
	// Payload must carry the detector-read fields at the top level.
	var p map[string]any
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if p["role"] != "Owner" {
		t.Errorf("payload role = %v, want Owner", p["role"])
	}
	if p["target_user"] != "victim-obj-id" {
		t.Errorf("payload target_user = %v, want victim-obj-id", p["target_user"])
	}
	if p["action"] != "role_assignment" {
		t.Errorf("payload action = %v, want role_assignment", p["action"])
	}
	expectedTS := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	if ev.Timestamp != expectedTS {
		t.Errorf("Timestamp = %v, want %v", ev.Timestamp, expectedTS)
	}
	if ev.Org != "sub-123" {
		t.Errorf("Org = %q, want sub-123", ev.Org)
	}
	if ev.ID == "" {
		t.Error("ID is empty")
	}
}

func TestNormalizeEntryMissingFields(t *testing.T) {
	entry := map[string]interface{}{}
	evs, tsReliable, err := normalizeEntry(entry, "sub-xyz")
	if err != nil {
		t.Fatalf("normalizeEntry with empty entry: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	ev := evs[0]
	if ev.Source != "azure" {
		t.Errorf("Source = %q, want azure", ev.Source)
	}
	// Empty/unmapped operation falls through to the inert catch-all type.
	if ev.Type != normalize.CatchAll {
		t.Errorf("Type = %q, want %q", ev.Type, normalize.CatchAll)
	}
	if ev.Timestamp.IsZero() {
		t.Error("Timestamp is zero")
	}
	// The fabricated fallback timestamp must never be reported as reliable —
	// the caller (fetchActivityLog) must not let it advance the resume
	// high-water mark.
	if tsReliable {
		t.Error("tsReliable = true, want false when eventTimestamp is missing (would poison the resume cursor to wall-clock now)")
	}
}

func TestNormalizeEntrySchemaRoundtrip(t *testing.T) {
	entry := map[string]interface{}{
		"id":     "entry-001",
		"caller": "user@corp.com",
		"operationName": map[string]interface{}{
			"value": "Microsoft.Compute/virtualMachines/delete",
		},
		"eventTimestamp": "2024-01-15T08:30:00Z",
	}

	evs, _, err := normalizeEntry(entry, "sub-roundtrip")
	if err != nil {
		t.Fatalf("normalizeEntry: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	ev := evs[0]

	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded event.Event
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ID != ev.ID {
		t.Errorf("ID mismatch: got %q, want %q", decoded.ID, ev.ID)
	}
	if decoded.Source != "azure" {
		t.Errorf("Source mismatch: %q", decoded.Source)
	}
}

// --- mallcoppro-bb2: high-water cursor semantics ---

func serveActivityLogPages(t *testing.T, pages [][]map[string]interface{}) *httptest.Server {
	t.Helper()
	call := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if call >= len(pages) {
			t.Fatalf("unexpected extra request %d (only %d pages configured)", call+1, len(pages))
		}
		resp := activityLogResponse{Value: pages[call]}
		call++
		if call < len(pages) {
			// Point NextLink back at this same server; the real per-run
			// pagination loop should follow it to completion, but it must
			// NEVER be what a resumed run starts from (see run()).
			resp.NextLink = "http://" + r.Host + "/next-page"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
}

// (a) complete pagination emits a cursor whose decoded payload is the max
// emitted event timestamp (RFC3339Nano), NOT a pagination token.
func TestFetchActivityLogCompletePaginationHighWaterCursor(t *testing.T) {
	page1 := []map[string]interface{}{
		{"id": "1", "eventTimestamp": "2024-06-01T12:00:00Z", "caller": "a@example.com"},
	}
	page2 := []map[string]interface{}{
		{"id": "2", "eventTimestamp": "2024-06-01T13:30:00.123Z", "caller": "b@example.com"},
	}
	srv := serveActivityLogPages(t, [][]map[string]interface{}{page1, page2})
	defer srv.Close()
	defer activityLogBaseOverride(srv.URL)()

	conn := &connector{client: srv.Client(), accessToken: "tok", subscriptionID: "sub-hw"}
	events, maxSeen, err := conn.fetchActivityLog(context.Background())
	if err != nil {
		t.Fatalf("fetchActivityLog: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 events (full pagination), got %d", len(events))
	}
	want := time.Date(2024, 6, 1, 13, 30, 0, 123000000, time.UTC)
	if !maxSeen.Equal(want) {
		t.Fatalf("maxSeen = %v, want %v", maxSeen, want)
	}

	key := sigKey("sub-hw")
	encoded := encodeCursor(maxSeen.UTC().Format(time.RFC3339Nano), key)
	decoded, err := decodeCursor(encoded, key)
	if err != nil {
		t.Fatalf("decodeCursor: %v", err)
	}
	parsed, err := time.Parse(time.RFC3339Nano, decoded)
	if err != nil {
		t.Fatalf("cursor payload is not a timestamp (looks like a pagination token): %v", err)
	}
	if !parsed.Equal(want) {
		t.Errorf("cursor payload = %v, want %v", parsed, want)
	}
}

// (a2) a page mixing a good-timestamp entry with a missing-eventTimestamp
// entry must advance maxSeen to the good entry's time, NOT to the fabricated
// time.Now() fallback used for the missing-timestamp entry's own Timestamp
// field. Regression test for the high-water cursor poisoning bug.
func TestFetchActivityLogMissingTimestampDoesNotPoisonMaxSeen(t *testing.T) {
	page := []map[string]interface{}{
		{"id": "1", "eventTimestamp": "2024-06-01T12:00:00Z", "caller": "a@example.com"},
		// No eventTimestamp: normalizeEntry falls back to time.Now().UTC(),
		// which is always AFTER the good entry's timestamp.
		{"id": "2", "caller": "b@example.com"},
	}
	srv := serveActivityLogPages(t, [][]map[string]interface{}{page})
	defer srv.Close()
	defer activityLogBaseOverride(srv.URL)()

	conn := &connector{client: srv.Client(), accessToken: "tok", subscriptionID: "sub-hw"}
	events, maxSeen, err := conn.fetchActivityLog(context.Background())
	if err != nil {
		t.Fatalf("fetchActivityLog: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 events emitted (both, even the unreliable one), got %d", len(events))
	}
	want := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	if !maxSeen.Equal(want) {
		t.Fatalf("maxSeen = %v, want %v (the fabricated now() timestamp on the missing-eventTimestamp entry must not advance the cursor)", maxSeen, want)
	}
}

// mallcoppro-38c: --exclude-resource-group must drop events whose resourceId
// falls under an excluded RG (e.g. throwaway bench infra sharing a
// subscription with the monitored resource) while still advancing the
// cursor past those entries' timestamps — otherwise every future run
// re-fetches (and re-discards) the same excluded backlog forever.
func TestExtractResourceGroup(t *testing.T) {
	cases := []struct {
		name       string
		resourceID string
		want       string
	}{
		{"lowercase segment", "/subscriptions/s/resourceGroups/nostr-relay-prod/providers/Microsoft.App/containerApps/nostr-relay-prod", "nostr-relay-prod"},
		{"inconsistent casing", "/subscriptions/s/resourcegroups/nostr-relay-bench/providers/Microsoft.App/containerApps/x", "nostr-relay-bench"},
		{"subscription-scoped, no RG segment", "/subscriptions/s/providers/Microsoft.Authorization/roleAssignments/x", ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractResourceGroup(tc.resourceID)
			if got != tc.want {
				t.Errorf("extractResourceGroup(%q) = %q, want %q", tc.resourceID, got, tc.want)
			}
		})
	}
}

func TestConnectorIsExcluded(t *testing.T) {
	c := &connector{excludeResourceGroups: map[string]bool{"nostr-relay-bench": true}}

	excluded := map[string]interface{}{"resourceId": "/subscriptions/s/resourceGroups/Nostr-Relay-Bench/providers/Microsoft.App/containerApps/x"}
	if !c.isExcluded(excluded) {
		t.Error("expected bench RG entry (mixed case) to be excluded")
	}

	notExcluded := map[string]interface{}{"resourceId": "/subscriptions/s/resourceGroups/nostr-relay-prod/providers/Microsoft.App/containerApps/x"}
	if c.isExcluded(notExcluded) {
		t.Error("expected prod RG entry to NOT be excluded")
	}

	noRG := map[string]interface{}{"resourceId": "/subscriptions/s/providers/Microsoft.Authorization/roleAssignments/x"}
	if c.isExcluded(noRG) {
		t.Error("expected subscription-scoped entry (no RG segment) to NOT be excluded")
	}

	empty := &connector{}
	if empty.isExcluded(excluded) {
		t.Error("expected connector with no excludeResourceGroups to never exclude")
	}
}

func TestFetchActivityLogExcludesResourceGroupButStillAdvancesCursor(t *testing.T) {
	page := []map[string]interface{}{
		{"id": "1", "eventTimestamp": "2024-06-01T12:00:00Z", "caller": "prod-actor", "resourceId": "/subscriptions/s/resourceGroups/nostr-relay-prod/providers/Microsoft.App/containerApps/nostr-relay-prod"},
		// Later timestamp, but in the excluded bench RG: must not be emitted,
		// yet its timestamp must still be the one that wins maxSeen.
		{"id": "2", "eventTimestamp": "2024-06-01T13:30:00Z", "caller": "bench-actor", "resourceId": "/subscriptions/s/resourceGroups/nostr-relay-bench/providers/Microsoft.App/containerApps/nostr-relay-bench"},
	}
	srv := serveActivityLogPages(t, [][]map[string]interface{}{page})
	defer srv.Close()
	defer activityLogBaseOverride(srv.URL)()

	conn := &connector{
		client:                srv.Client(),
		accessToken:           "tok",
		subscriptionID:        "sub-excl",
		excludeResourceGroups: map[string]bool{"nostr-relay-bench": true},
	}
	events, maxSeen, err := conn.fetchActivityLog(context.Background())
	if err != nil {
		t.Fatalf("fetchActivityLog: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event (bench RG excluded), got %d", len(events))
	}
	if events[0].Actor != "prod-actor" {
		t.Errorf("emitted event Actor = %q, want %q (bench entry must not leak through)", events[0].Actor, "prod-actor")
	}
	want := time.Date(2024, 6, 1, 13, 30, 0, 0, time.UTC)
	if !maxSeen.Equal(want) {
		t.Fatalf("maxSeen = %v, want %v (excluded entry's timestamp must still advance the cursor, or its backlog is re-fetched forever)", maxSeen, want)
	}
}

// (b) resume with a timestamp cursor queries from that timestamp
// inclusively — assert the actual $filter request parameter reflects T.
func TestFetchActivityLogResumeUsesInclusiveFilter(t *testing.T) {
	var gotFilter string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotFilter = r.URL.Query().Get("$filter")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(activityLogResponse{})
	}))
	defer srv.Close()
	defer activityLogBaseOverride(srv.URL)()

	floor := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	conn := &connector{client: srv.Client(), accessToken: "tok", subscriptionID: "sub-resume", since: floor}
	if _, _, err := conn.fetchActivityLog(context.Background()); err != nil {
		t.Fatalf("fetchActivityLog: %v", err)
	}

	want := `eventTimestamp ge '2024-06-01T12:00:00Z'`
	if gotFilter != want {
		t.Errorf("$filter = %q, want %q (must be inclusive \"ge\", not exclusive)", gotFilter, want)
	}
}

// (c) a legacy pagination-token cursor (HMAC-valid, non-timestamp payload)
// warns and falls back to the 24h window — the run SUCCEEDS.
func TestResolveFloorLegacyPaginationTokenFallsBack(t *testing.T) {
	key := sigKey("sub-legacy")
	legacyCursor := encodeCursor("https://management.azure.com/subscriptions/sub-legacy?$skiptoken=abc123", key)

	before := time.Now().UTC()
	floor, legacy, err := resolveFloor(legacyCursor, time.Time{}, key)
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("resolveFloor: legacy cursor must not hard-fail, got: %v", err)
	}
	if !legacy {
		t.Error("legacy = false, want true for a non-timestamp HMAC-valid payload")
	}
	wantMin := before.Add(-legacyCursorFallback)
	wantMax := after.Add(-legacyCursorFallback)
	if floor.Before(wantMin) || floor.After(wantMax) {
		t.Errorf("floor = %v, want within [%v, %v] (now - 24h)", floor, wantMin, wantMax)
	}

	// Prove the run actually succeeds end-to-end with the fallback floor.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(activityLogResponse{})
	}))
	defer srv.Close()
	defer activityLogBaseOverride(srv.URL)()

	conn := &connector{client: srv.Client(), accessToken: "tok", subscriptionID: "sub-legacy", since: floor}
	if _, _, err := conn.fetchActivityLog(context.Background()); err != nil {
		t.Fatalf("fetchActivityLog after legacy-cursor fallback: %v", err)
	}
}

// (d) zero events emitted -> caller (run()) must not print a "cursor:" line.
// fetchActivityLog itself signals this via a zero maxSeen.
func TestFetchActivityLogZeroEventsNoCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(activityLogResponse{})
	}))
	defer srv.Close()
	defer activityLogBaseOverride(srv.URL)()

	conn := &connector{client: srv.Client(), accessToken: "tok", subscriptionID: "sub-empty"}
	events, maxSeen, err := conn.fetchActivityLog(context.Background())
	if err != nil {
		t.Fatalf("fetchActivityLog: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("want 0 events, got %d", len(events))
	}
	if !maxSeen.IsZero() {
		t.Errorf("maxSeen = %v, want zero (no cursor should be emitted)", maxSeen)
	}
}

// (e) a tampered (HMAC-invalid) cursor still hard-fails.
func TestResolveFloorTamperedCursorHardFails(t *testing.T) {
	key := sigKey("sub-tamper")
	encoded := encodeCursor("2024-06-01T12:00:00Z", key)
	parts := strings.SplitN(encoded, ".", 2)
	payload := []byte(parts[0])
	payload[len(payload)-1] ^= 0x01
	tampered := string(payload) + "." + parts[1]

	_, _, err := resolveFloor(tampered, time.Time{}, key)
	if err == nil {
		t.Fatal("expected hard failure for tampered cursor, got nil")
	}
}
