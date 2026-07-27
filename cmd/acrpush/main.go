// Command acrpush is a one-shot poller of the Azure Log Analytics query API
// (mallcoppro-29f), sibling to cmd/loganalytics. It surfaces
// acrnostrrelayprod's DATA-PLANE registry-content events — image pushes,
// deletes, and imports (`az acr import`, a distinct OperationName that pulls
// an image from an arbitrary external source registry into ours) surfaced
// via the acr-diag-to-law diagnostic setting (nostr-relay/infra/prod.bicep)
// into the ContainerRegistryRepositoryEvents Log Analytics table — as
// normalized mallcop events.
//
// Why a separate command rather than extending cmd/loganalytics: that
// connector is hardcoded to ONE table (ContainerAppConsoleLogs_CL) and ONE
// row shape (a freeform JSON `Log_s` line matching the relay's own
// seclog.go format). ContainerRegistryRepositoryEvents is a structurally
// different table (its own typed columns — OperationName, Repository, Tag,
// Digest, Identity, CallerIpAddress — not a JSON blob to decode), so sharing
// cmd/loganalytics's processTable would mean branching its row-shape logic
// on which table produced the row. A second small, single-purpose command
// mirrors this repo's existing one-table-per-command convention
// (cmd/cloudwatch is CloudWatch's own analog to cmd/aws) more than it
// duplicates cmd/loganalytics's boilerplate.
//
// Usage:
//
//	acrpush --workspace-id <law-workspace-guid> [--workspace-resource-id <arm-id>] [--since <iso-timestamp>] [--cursor <cursor>]
//
// Auth: service principal via AZURE_TENANT_ID, AZURE_CLIENT_ID,
// AZURE_CLIENT_SECRET — same env convention as cmd/loganalytics and cmd/azure.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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

	// lawScope is the AAD app ID URI scope for the Log Analytics Data Query
	// API — same scope cmd/loganalytics uses, since both query the same
	// workspace type via the same client-credentials flow.
	lawScope = "https://api.loganalytics.io/.default"
)

// queryBase is a var (not const) so tests can point it at an httptest.Server
// instead of the real Log Analytics endpoint.
var queryBase = "https://api.loganalytics.io/v1/workspaces/%s/query"

// kqlQuery is THE query, verbatim, every run — a constant string, never
// string-interpolated with config or the time window (same discipline as
// cmd/loganalytics's kqlQuery). Filtered server-side to Push/Delete/
// importImage only: Pull and other read-shaped operations carry no
// supply-chain-mutation signal (see internal/normalize/acr.go's doc comment)
// and would otherwise dominate the row volume for no detection value.
// importImage (ACR's operation for `az acr import`) is included alongside
// Push/Delete because it pulls an image from an ARBITRARY EXTERNAL source
// registry into ours — a supply-chain injection vector, verified live
// 2026-07-27 landing as its own distinct OperationName in
// ContainerRegistryRepositoryEvents (previously silently excluded here,
// 0 rows). The time window is bound separately via the request body's
// "timespan" field (see connector.query).
//
// Repository is NOT filtered to "nostr-relay-prod" (unlike cmd/loganalytics's
// ContainerAppName_s filter): acrnostrrelayprod is a single-repository
// registry today, but nothing about this query depends on that being
// permanent, and repository name is carried in the payload either way.
const kqlQuery = `ContainerRegistryRepositoryEvents
| where OperationName in ("Push", "Delete", "importImage")
| order by TimeGenerated asc
| project TimeGenerated, OperationName, Repository, Tag, Digest, Identity, CallerIpAddress, LoginServer, ResultType`

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

// sigKey derives the cursor HMAC key from AZURE_CLIENT_SECRET (a real secret),
// mirroring cmd/loganalytics's sigKey and cmd/mercury's sigKey(token). The
// workspace GUID is a PUBLIC identifier (portal URLs, ARM IDs), so keying on it
// gives an attacker who knows the workspace the ability to forge a far-future
// cursor and skip an arbitrary window of ACR Push/Delete events — hiding a
// malicious image push. Keying on the secret closes that (mallcoppro-900).
func sigKey(clientSecret string) []byte {
	return []byte(fmt.Sprintf("mallcop-acrpush-cursor:%s", clientSecret))
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

// resolveFloor decodes an optional checkpoint cursor (an HMAC-signed
// RFC3339Nano timestamp) and combines it with --since to produce the
// effective query floor (the later of the two wins). Byte-identical logic to
// cmd/loganalytics's resolveFloor.
func resolveFloor(cursorArg string, sinceTime time.Time, key []byte) (floor time.Time, err error) {
	var cursorMark time.Time
	if cursorArg != "" {
		raw, err := decodeCursor(cursorArg, key)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid checkpoint cursor: %w", err)
		}
		ts, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid checkpoint cursor: payload is not a timestamp: %w", err)
		}
		cursorMark = ts.UTC()
	}

	floor = sinceTime
	if cursorMark.After(floor) {
		floor = cursorMark
	}
	return floor, nil
}

type azureTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// tokenEndpoint is a var so tests can override it.
var tokenEndpoint = tokenEndpointFn

func getAccessToken(tenantID, clientID, clientSecret, scope string) (string, error) {
	tokenURL := fmt.Sprintf(tokenEndpoint, tenantID)
	vals := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {scope},
	}
	resp, err := http.PostForm(tokenURL, vals)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		// Never echo vals (which carries client_secret) into an error — only
		// the upstream response body is surfaced.
		return "", fmt.Errorf("token error %d: %s", resp.StatusCode, string(body))
	}
	var tr azureTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	return tr.AccessToken, nil
}

// lawColumn is one column descriptor in a Log Analytics query response table.
type lawColumn struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// lawTable is one table in a Log Analytics query response.
type lawTable struct {
	Name    string      `json:"name"`
	Columns []lawColumn `json:"columns"`
	Rows    [][]any     `json:"rows"`
}

// lawQueryResponse is the Log Analytics v1 query API response envelope.
type lawQueryResponse struct {
	Tables []lawTable `json:"tables"`
}

type connector struct {
	client      *http.Client
	accessToken string
	workspaceID string
}

// query runs kqlQuery against c.workspaceID, bounding the time window via the
// API's own "timespan" field rather than any KQL text — since is the
// effective floor (max of --since and the resumed cursor); a zero since
// omits "timespan" entirely.
func (c *connector) query(ctx context.Context, since time.Time) (*lawQueryResponse, error) {
	body := map[string]any{"query": kqlQuery}
	if !since.IsZero() {
		body["timespan"] = since.UTC().Format(time.RFC3339) + "/" + time.Now().UTC().Format(time.RFC3339)
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal query body: %w", err)
	}

	u := fmt.Sprintf(queryBase, c.workspaceID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", u, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Log Analytics API error %d: %s", resp.StatusCode, string(respBody))
	}

	var result lawQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode query response: %w", err)
	}
	return &result, nil
}

func columnIndex(cols []lawColumn, name string) int {
	for i, c := range cols {
		if c.Name == name {
			return i
		}
	}
	return -1
}

// parseLAWTimestamp parses a Log Analytics TimeGenerated value, which comes
// back as RFC3339 with a variable-precision fractional-second component.
// Same parsing as cmd/loganalytics's parseLAWTimestamp.
func parseLAWTimestamp(s string) (time.Time, error) {
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts, nil
	}
	return time.Parse(time.RFC3339, s)
}

// rowStr reads row[idx] as a string, tolerating a missing column (idx < 0,
// e.g. an older query-response shape without that column) or a non-string /
// null cell (returns "" rather than panicking).
func rowStr(row []any, idx int) string {
	if idx < 0 || idx >= len(row) {
		return ""
	}
	s, _ := row[idx].(string)
	return s
}

// processTable maps every row of a lawTable (a batch of ACR repository
// events) to normalized mallcop events, returning the events and the maximum
// TimeGenerated seen — the next run's resume high-water mark. A row whose
// TimeGenerated fails to parse is skipped with a warning, never fabricated or
// silently dropped without a trace. OperationName, Repository, Tag, Digest,
// Identity, CallerIpAddress, LoginServer, and ResultType are all optional
// columns defensively (rowStr tolerates a missing index) since the KQL
// projection is this file's own constant and could in principle be edited
// without updating this function in lockstep.
func processTable(tbl lawTable, org string) ([]*event.Event, time.Time, error) {
	tsIdx := columnIndex(tbl.Columns, "TimeGenerated")
	opIdx := columnIndex(tbl.Columns, "OperationName")
	repoIdx := columnIndex(tbl.Columns, "Repository")
	tagIdx := columnIndex(tbl.Columns, "Tag")
	digestIdx := columnIndex(tbl.Columns, "Digest")
	identityIdx := columnIndex(tbl.Columns, "Identity")
	callerIPIdx := columnIndex(tbl.Columns, "CallerIpAddress")
	loginServerIdx := columnIndex(tbl.Columns, "LoginServer")
	resultTypeIdx := columnIndex(tbl.Columns, "ResultType")
	if tsIdx < 0 || opIdx < 0 {
		return nil, time.Time{}, fmt.Errorf("query response missing TimeGenerated/OperationName column (got %+v)", tbl.Columns)
	}

	var events []*event.Event
	var maxSeen time.Time

	for _, row := range tbl.Rows {
		tsStr := rowStr(row, tsIdx)
		ts, err := parseLAWTimestamp(tsStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: skipping row: bad TimeGenerated %q: %v\n", tsStr, err)
			continue
		}

		operationName := rowStr(row, opIdx)
		repository := rowStr(row, repoIdx)
		tag := rowStr(row, tagIdx)
		digest := rowStr(row, digestIdx)
		identity := rowStr(row, identityIdx)
		callerIP := rowStr(row, callerIPIdx)
		loginServer := rowStr(row, loginServerIdx)
		resultType := rowStr(row, resultTypeIdx)

		raw := map[string]any{
			"TimeGenerated":   tsStr,
			"OperationName":   operationName,
			"Repository":      repository,
			"Tag":             tag,
			"Digest":          digest,
			"Identity":        identity,
			"CallerIpAddress": callerIP,
			"LoginServer":     loginServer,
			"ResultType":      resultType,
		}

		results := normalize.ACR(operationName, repository, tag, digest, identity, callerIP, loginServer, resultType)
		idBase := sha256Hex(fmt.Sprintf("acrpush:%s:%s:%s:%s", tsStr, operationName, repository, digest))
		for i, r := range results {
			payload, err := r.PayloadJSON(raw)
			if err != nil {
				return nil, time.Time{}, fmt.Errorf("marshal payload: %w", err)
			}
			id := idBase
			if i > 0 {
				id = sha256Hex(fmt.Sprintf("%s:%d", idBase, i))
			}
			events = append(events, &event.Event{
				ID:        id,
				Source:    "acrpush",
				Type:      r.Type,
				Actor:     identity,
				Timestamp: ts,
				Org:       org,
				Payload:   payload,
			})
		}
		if ts.After(maxSeen) {
			maxSeen = ts
		}
	}

	return events, maxSeen, nil
}

func run() error {
	var (
		workspaceID         = flag.String("workspace-id", "", "Log Analytics workspace GUID (customerId), used in the query URL")
		workspaceResourceID = flag.String("workspace-resource-id", "", "Log Analytics workspace ARM resource ID (optional; recorded as the event Org)")
		since               = flag.String("since", "", "ISO 8601 timestamp to filter events (e.g. 2024-01-01T00:00:00Z)")
		cursorArg           = flag.String("cursor", "", "Checkpoint cursor from previous run (HMAC-signed)")
	)
	flag.Parse()

	if *workspaceID == "" {
		*workspaceID = os.Getenv("AZURE_LOGANALYTICS_WORKSPACE_ID")
	}
	if *workspaceID == "" {
		return fmt.Errorf("--workspace-id or AZURE_LOGANALYTICS_WORKSPACE_ID is required")
	}
	if *workspaceResourceID == "" {
		*workspaceResourceID = os.Getenv("AZURE_LOGANALYTICS_WORKSPACE_RESOURCE_ID")
	}
	org := *workspaceResourceID
	if org == "" {
		org = *workspaceID
	}

	tenantID := os.Getenv("AZURE_TENANT_ID")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
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

	key := sigKey(clientSecret)
	floor, err := resolveFloor(*cursorArg, sinceTime, key)
	if err != nil {
		return err
	}

	token, err := getAccessToken(tenantID, clientID, clientSecret, lawScope)
	if err != nil {
		return fmt.Errorf("get access token: %w", err)
	}

	conn := &connector{client: http.DefaultClient, accessToken: token, workspaceID: *workspaceID}

	ctx := context.Background()
	resp, err := conn.query(ctx, floor)
	if err != nil {
		return fmt.Errorf("query Log Analytics: %w", err)
	}

	var events []*event.Event
	var maxSeen time.Time
	if len(resp.Tables) > 0 {
		events, maxSeen, err = processTable(resp.Tables[0], org)
		if err != nil {
			return err
		}
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
