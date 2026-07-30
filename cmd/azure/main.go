// Command azure polls Azure Monitor Activity Logs via the REST API
// and emits normalized mallcop events as JSONL to stdout.
//
// Usage:
//
//	azure --subscription-id <id> [--since <iso-timestamp>] [--cursor <cursor>]
//
// Auth: service principal via AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET.
package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop-connectors/internal/normalize"
	"github.com/mallcop-app/mallcop-connectors/pkg/event"
)

const (
	cursorMaxLen    = 2000
	tokenEndpointFn = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	apiVersion      = "2015-04-01"

	// legacyCursorFallback is the re-scan window used when an HMAC-valid
	// cursor is found to carry a pre-highwater pagination token (nextLink)
	// instead of a timestamp. See run()'s cursor decode for the migration.
	legacyCursorFallback = 24 * time.Hour
)

// activityLogBase is a var (not const) so tests can point it at an
// httptest.Server instead of the real Azure management endpoint.
var activityLogBase = "https://management.azure.com/subscriptions/%s/providers/microsoft.insights/eventtypes/management/values"

// managementBase is the ARM control-plane host used by supplementary GETs
// (currently just resolveCosmosRole). A var (not const), mirroring
// activityLogBase's override idiom, so tests can point it at an
// httptest.Server.
var managementBase = "https://management.azure.com"

// cosmosSQLRoleAPIVersion is the Cosmos DB SQL RBAC control-plane API
// version used to GET a sqlRoleAssignments resource (mallcoppro-32e).
const cosmosSQLRoleAPIVersion = "2023-04-15"

// cosmosBuiltInRoleNames maps the two well-known BUILT-IN Cosmos DB SQL role
// definition GUIDs (Azure-documented, stable across every subscription) to
// their display names, so priv-escalation's detectors see a human-readable
// role instead of a bare GUID.
var cosmosBuiltInRoleNames = map[string]string{
	"00000000-0000-0000-0000-000000000001": "Cosmos DB Built-in Data Reader",
	"00000000-0000-0000-0000-000000000002": "Cosmos DB Built-in Data Contributor",
}

var cursorRE = regexp.MustCompile(`^[A-Za-z0-9+/=_\-&?%:.]+$`)

func validateCursor(cursor string) error {
	if len(cursor) > cursorMaxLen {
		return fmt.Errorf("invalid cursor: length %d exceeds maximum %d", len(cursor), cursorMaxLen)
	}
	if strings.ContainsAny(cursor, "\n\r\x00") {
		return fmt.Errorf("invalid cursor: contains control characters")
	}
	return nil
}

func sigKey(subscriptionID string) []byte {
	return []byte(fmt.Sprintf("mallcop-azure-cursor:%s", subscriptionID))
}

func encodeCursor(raw string, key []byte) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(raw))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(b64))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return b64 + "." + sig
}

func decodeCursor(encoded string, key []byte) (string, error) {
	parts := strings.SplitN(encoded, ".", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid cursor format: missing signature")
	}
	b64, sig := parts[0], parts[1]
	if err := validateCursor(b64); err != nil {
		return "", fmt.Errorf("invalid cursor payload: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(b64))
	expectedSig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return "", fmt.Errorf("invalid cursor: signature mismatch (tampered cursor rejected)")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("invalid cursor: base64 decode failed: %w", err)
	}
	return string(raw), nil
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:])
}

// resolveFloor decodes an optional checkpoint cursor and combines it with
// --since to produce the effective query floor (the later of the two
// timestamps wins). An HMAC-valid cursor whose payload does not parse as a
// timestamp is a legacy pre-highwater pagination token: resolveFloor never
// resumes it and never hard-fails on it — it self-heals by falling back to
// legacyCursorFallback and reports legacy=true so the caller can log the
// one-line warning. An HMAC-invalid (tampered) cursor still hard-fails.
func resolveFloor(cursorArg string, sinceTime time.Time, key []byte) (floor time.Time, legacy bool, err error) {
	var cursorMark time.Time
	if cursorArg != "" {
		raw, err := decodeCursor(cursorArg, key)
		if err != nil {
			return time.Time{}, false, fmt.Errorf("invalid checkpoint cursor: %w", err)
		}
		ts, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			legacy = true
			cursorMark = time.Now().UTC().Add(-legacyCursorFallback)
		} else {
			cursorMark = ts.UTC()
		}
	}

	// When both --cursor and --since are supplied, the later (more recent)
	// timestamp wins.
	floor = sinceTime
	if cursorMark.After(floor) {
		floor = cursorMark
	}
	return floor, legacy, nil
}

type azureTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// tokenEndpoint is a var (not const) so tests can point token minting at an
// httptest.Server, mirroring cmd/loganalytics' idiom.
var tokenEndpoint = tokenEndpointFn

func getAccessToken(tenantID, clientID, clientSecret string) (string, error) {
	tokenURL := fmt.Sprintf(tokenEndpoint, tenantID)
	vals := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {"https://management.azure.com/.default"},
	}
	resp, err := http.PostForm(tokenURL, vals)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token error %d: %s", resp.StatusCode, string(body))
	}
	var tr azureTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	return tr.AccessToken, nil
}

// activityLogEntry represents a single Azure Activity Log entry (subset of fields).
type activityLogEntry struct {
	ID            string `json:"id"`
	OperationName struct {
		Value string `json:"value"`
	} `json:"operationName"`
	Caller    string `json:"caller"`
	EventName struct {
		Value string `json:"value"`
	} `json:"eventName"`
	EventTimestamp string `json:"eventTimestamp"`
	Status         struct {
		Value string `json:"value"`
	} `json:"status"`
}

// normalizeEntry maps a raw Azure Activity Log entry to one or more mallcop
// events. The canonical Type and detector-readable Payload come from the shared
// normalize library (NOT the raw operationName, which gates no detector).
//
// The second return value, tsReliable, is true only when the Timestamp on the
// returned events came from the entry's own eventTimestamp field. When
// eventTimestamp is missing or unparseable, ts falls back to time.Now().UTC()
// so the event still has SOME timestamp for display/dedupe purposes — but
// that fabricated value must never be allowed to advance the resume
// high-water mark (it would silently poison the cursor to "now" and cause
// the next run to skip every real event between the true high-water mark and
// now). Callers must gate maxSeen updates on tsReliable, not merely on
// ev.Timestamp being non-zero.
//
// azureOpts is passed straight through to normalize.Azure (currently just
// carries WithCosmosRoleResolver from fetchActivityLog); it's variadic so
// every existing 2-arg call (tests included) keeps compiling unchanged.
func normalizeEntry(entry map[string]interface{}, subscriptionID string, azureOpts ...normalize.AzureOption) ([]*event.Event, bool, error) {
	// Extract caller (actor).
	actor, _ := entry["caller"].(string)

	// Extract operation name for mapping.
	opName := ""
	if op, ok := entry["operationName"].(map[string]interface{}); ok {
		opName, _ = op["value"].(string)
	}

	// Parse timestamp.
	ts := time.Now().UTC()
	tsReliable := false
	if tsStr, ok := entry["eventTimestamp"].(string); ok && tsStr != "" {
		var err error
		ts, err = time.Parse(time.RFC3339, tsStr)
		if err != nil {
			// Try with nanoseconds.
			ts, err = time.Parse("2006-01-02T15:04:05.9999999Z", tsStr)
			if err != nil {
				log.Printf("warn: failed to parse eventTimestamp %q: %v", tsStr, err)
				ts = time.Now().UTC()
			} else {
				tsReliable = true
			}
		} else {
			tsReliable = true
		}
	}

	// Build ID from the Azure event ID or derive from content.
	idStr := ""
	if id, ok := entry["id"].(string); ok && id != "" {
		idStr = "azure:" + id
	} else {
		idStr = fmt.Sprintf("azure:%s:%s:%d", subscriptionID, opName, ts.UnixNano())
	}
	baseID := sha256Hex(idStr)

	results := normalize.Azure(opName, entry, azureOpts...)
	out := make([]*event.Event, 0, len(results))
	for i, r := range results {
		payload, err := r.PayloadJSON(entry)
		if err != nil {
			return nil, false, fmt.Errorf("marshal payload: %w", err)
		}
		id := baseID
		if i > 0 {
			id = sha256Hex(fmt.Sprintf("%s:%d", idStr, i))
		}
		out = append(out, &event.Event{
			ID:        id,
			Source:    "azure",
			Type:      r.Type,
			Actor:     actor,
			Timestamp: ts,
			Org:       subscriptionID,
			Payload:   payload,
		})
	}
	return out, tsReliable, nil
}

type activityLogResponse struct {
	Value    []map[string]interface{} `json:"value"`
	NextLink string                   `json:"nextLink"`
}

type connector struct {
	client         *http.Client
	accessToken    string
	subscriptionID string
	since          time.Time // effective query floor: max(--since, cursor high-water mark)
}

func (c *connector) get(ctx context.Context, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")
	return c.client.Do(req)
}

// cosmosRoleAssignmentGet is the subset of a Cosmos DB SQL role-assignment
// resource's ARM GET response this connector needs.
type cosmosRoleAssignmentGet struct {
	Properties struct {
		PrincipalID      string `json:"principalId"`
		RoleDefinitionID string `json:"roleDefinitionId"`
	} `json:"properties"`
}

// lastPathSegment returns the final "/"-delimited segment of s (e.g. the bare
// GUID off the end of a roleDefinitionId resource path).
func lastPathSegment(s string) string {
	if s == "" {
		return ""
	}
	parts := strings.Split(s, "/")
	return parts[len(parts)-1]
}

// resolveCosmosRole is a normalize.CosmosRoleResolver: it makes a
// supplementary ARM control-plane GET on a Cosmos DB SQL role-assignment
// resource to recover role/principal detail the Activity Log entry itself
// never carries (mallcoppro-32e -- live-verified 2026-07-21/27: the Cosmos
// sqlRoleAssignments BeginRequest event has NO requestbody at all, unlike
// Microsoft.Authorization/roleAssignments/write and ContainerRegistry/
// registries/write, which do and so never need this).
//
// resourceID already starts with "/subscriptions/..." (as read straight off
// the Activity Log entry's resourceId field), so it's appended directly to
// managementBase. Deliberately a SINGLE GET: builtin role GUIDs are mapped to
// names locally; a custom (non-builtin) roleDefinitionId falls back to its
// raw last path segment rather than triggering a second GET to resolve a
// custom role's display name.
//
// Best-effort only -- enrichment must never fail or crash a scan. Any
// transport error, non-200 status, or unparseable body logs a warning to
// stderr and returns ok=false; the caller (normalize.Azure) keeps its
// pre-existing best-effort-empty behavior in that case.
func (c *connector) resolveCosmosRole(resourceID string) (roleName, principalID string, ok bool) {
	u := managementBase + resourceID + "?api-version=" + cosmosSQLRoleAPIVersion
	resp, err := c.get(context.Background(), u)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: resolveCosmosRole GET %s: %v\n", resourceID, err)
		return "", "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "warn: resolveCosmosRole GET %s: status %d: %s\n", resourceID, resp.StatusCode, string(body))
		return "", "", false
	}
	var result cosmosRoleAssignmentGet
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Fprintf(os.Stderr, "warn: resolveCosmosRole GET %s: decode response: %v\n", resourceID, err)
		return "", "", false
	}
	principalID = result.Properties.PrincipalID
	if principalID == "" {
		// Nothing usable came back -- ok=false so the caller keeps its
		// pre-existing best-effort-empty behavior rather than "succeeding"
		// with an empty principal.
		return "", "", false
	}
	roleDefID := result.Properties.RoleDefinitionID
	if name, known := cosmosBuiltInRoleNames[lastPathSegment(roleDefID)]; known {
		roleName = name
	} else {
		roleName = lastPathSegment(roleDefID)
	}
	return roleName, principalID, true
}

// fetchActivityLog runs the Activity Log query to full pagination completion
// (following NextLink until exhausted) and returns every event plus the
// maximum eventTimestamp among them. It always starts a fresh query anchored
// on c.since ($filter eventTimestamp ge <floor>, server-side and inclusive)
// rather than resuming a prior run's NextLink: NextLink is a one-shot
// continuation of THAT query and is never safe to persist across runs (see
// mallcoppro-bb2). The returned max timestamp is what run() turns into the
// next cursor.
func (c *connector) fetchActivityLog(ctx context.Context) ([]*event.Event, time.Time, error) {
	u := fmt.Sprintf(activityLogBase, c.subscriptionID)
	params := url.Values{"api-version": {apiVersion}}
	if !c.since.IsZero() {
		// Inclusive ("ge", not "gt"): a resumed run must never lose an event
		// that shares the exact high-water timestamp with the last emitted
		// event of the prior run. Re-emitted boundary duplicates are dropped
		// downstream by mallcop core's per-ID dedupe (v0.11.3+).
		filter := fmt.Sprintf("eventTimestamp ge '%s'", c.since.UTC().Format(time.RFC3339))
		params.Set("$filter", filter)
	}
	currentURL := u + "?" + params.Encode()

	var allEvents []*event.Event
	var maxSeen time.Time

	for {
		resp, err := c.get(ctx, currentURL)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("GET %s: %w", currentURL, err)
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, time.Time{}, fmt.Errorf("Azure API error %d: %s", resp.StatusCode, string(body))
		}

		var result activityLogResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			return nil, time.Time{}, fmt.Errorf("decode response: %w", err)
		}
		resp.Body.Close()

		for _, entry := range result.Value {
			evs, tsReliable, err := normalizeEntry(entry, c.subscriptionID, normalize.WithCosmosRoleResolver(c.resolveCosmosRole))
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: skipping entry: %v\n", err)
				continue
			}
			allEvents = append(allEvents, evs...)
			// Only a real source timestamp may advance the resume high-water
			// mark. A fabricated time.Now() fallback (missing/unparseable
			// eventTimestamp) must never poison maxSeen to "now" — that would
			// silently skip every real event between the true high-water
			// mark and now on the next run.
			if tsReliable {
				for _, ev := range evs {
					if ev.Timestamp.After(maxSeen) {
						maxSeen = ev.Timestamp
					}
				}
			}
		}

		if result.NextLink == "" {
			break
		}
		currentURL = result.NextLink
	}

	return allEvents, maxSeen, nil
}

func run() error {
	var (
		subscriptionID = flag.String("subscription-id", "", "Azure subscription ID")
		since          = flag.String("since", "", "ISO 8601 timestamp to filter events (e.g. 2024-01-01T00:00:00Z)")
		cursorArg      = flag.String("cursor", "", "Checkpoint cursor from previous run (HMAC-signed)")
		doctorMode     = flag.Bool("doctor", false, "Self-diagnose this connector's Azure access and print one JSON DiagnosisReport on stdout, instead of scanning")
	)
	flag.Parse()

	if *subscriptionID == "" {
		*subscriptionID = os.Getenv("AZURE_SUBSCRIPTION_ID")
	}
	if *subscriptionID == "" {
		return fmt.Errorf("--subscription-id or AZURE_SUBSCRIPTION_ID is required")
	}

	tenantID := os.Getenv("AZURE_TENANT_ID")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")

	// --doctor short-circuits BEFORE the credential precondition below: a
	// connector with no usable credential is exactly one of the states the
	// doctor exists to name, so it must produce a report rather than the same
	// bare error the operator already could not act on.
	if *doctorMode {
		return runDoctor(context.Background(), os.Stdout, *subscriptionID, tenantID, clientID, clientSecret)
	}

	if tenantID == "" || clientID == "" || clientSecret == "" {
		return fmt.Errorf("AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET must be set")
	}

	var sinceTime time.Time
	if *since != "" {
		var err error
		sinceTime, err = time.Parse(time.RFC3339, *since)
		if err != nil {
			return fmt.Errorf("invalid --since timestamp %q: must be RFC3339", *since)
		}
	}

	key := sigKey(*subscriptionID)
	floor, legacy, err := resolveFloor(*cursorArg, sinceTime, key)
	if err != nil {
		return err
	}
	if legacy {
		fmt.Fprintf(os.Stderr, "warn: legacy pagination-token cursor detected; discarding and re-scanning the last 24h\n")
	}

	token, err := getAccessToken(tenantID, clientID, clientSecret)
	if err != nil {
		return fmt.Errorf("get access token: %w", err)
	}

	conn := &connector{
		client:         http.DefaultClient,
		accessToken:    token,
		subscriptionID: *subscriptionID,
		since:          floor,
	}

	ctx := context.Background()
	events, maxSeen, err := conn.fetchActivityLog(ctx)
	if err != nil {
		return fmt.Errorf("fetch activity log: %w", err)
	}

	bw := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(bw)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("encode event: %w", err)
		}
	}

	// Only emit a cursor when at least one event was emitted this run; zero
	// events means the caller should keep using its previous cursor.
	if !maxSeen.IsZero() {
		encoded := encodeCursor(maxSeen.UTC().Format(time.RFC3339Nano), key)
		fmt.Fprintf(os.Stderr, "cursor: %s\n", encoded)
	}

	return bw.Flush()
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
