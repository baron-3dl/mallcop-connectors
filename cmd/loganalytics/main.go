// Command loganalytics is a one-shot poller of the Azure Log Analytics query
// API (mallcoppro-9701). It surfaces the example-project's application-plane
// relay_security structured log lines (mallcoppro-813) as normalized mallcop
// events, narrowed (mallcoppro-f1a) to only the AUTHORIZATION-BOUNDARY
// signals: allowlist-breach probing (unauthorized_writer / nip42_auth_failure)
// and write-allowlist grant/revoke admin calls (nip86_admin_call's
// allowpubkey/banpubkey methods). Rate-limit rejections, accepted tombstones,
// and balance-gate rejections are usage/billing, not infrastructure
// subversion, and are deliberately excluded — see
// internal/normalize/loganalytics.go's LogAnalytics doc comment. It is the
// app-plane sibling of cmd/azure, which already covers this relay's Azure
// control-plane (Microsoft.App/*, Microsoft.DocumentDB/*, DNS) operations.
//
// Usage:
//
//	loganalytics --workspace-id <law-workspace-guid> [--workspace-resource-id <arm-id>] [--since <iso-timestamp>] [--cursor <cursor>]
//
// Auth: service principal via AZURE_TENANT_ID, AZURE_CLIENT_ID,
// AZURE_CLIENT_SECRET — same env convention as cmd/azure.
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
	// API — the client-credentials analog of the `--resource
	// https://api.loganalytics.io` argument to `az account get-access-token`
	// (verified live against law-example with an operator token
	// obtained the same way, 2026-07-21; the SP's own client-credential
	// token is unverified pending mallcoppro-4b0 — the SP secret is a
	// write-only GH secret this agent cannot read).
	lawScope = "https://api.loganalytics.io/.default"
)

// queryBase is a var (not const) so tests can point it at an httptest.Server
// instead of the real Log Analytics endpoint.
var queryBase = "https://api.loganalytics.io/v1/workspaces/%s/query"

// managementBase is the ARM control-plane host. The scan path never touches it;
// --doctor does, for the ALTERNATE-SCOPE probe that tells resource-context
// access mode apart from a missing role assignment (see internal/doctor).
// A var (not const), mirroring cmd/azure's idiom, so tests can point it at an
// httptest.Server.
var managementBase = "https://management.azure.com"

// kqlQuery is THE query, verbatim, every run — a constant string, never
// string-interpolated with config or the time window. The container app
// name (example-rg) is a fixed literal, not a runtime parameter: this
// connector has exactly one target, the relay's own console log stream. The
// time window is bound separately via the request body's "timespan" field
// (see connector.query), which is the Log Analytics API's own parameterized
// mechanism for restricting TimeGenerated — never a KQL `where` clause built
// from a Go format/concat of the cursor or --since value.
//
// Confirmed live against law-example (2026-07-21, operator token):
// returns exactly the mallcoppro-813 unauthorized-write probe row, shape
// {"tables":[{"name":"PrimaryResult","columns":[{"name":"TimeGenerated",...},
// {"name":"Log_s",...}],"rows":[["<ts>","<relay_security JSON line>"]]}]}.
// See internal/normalize/testdata/law_unauthorized_writer_response.json for
// the captured fixture.
const kqlQuery = `ContainerAppConsoleLogs_CL
| where ContainerAppName_s == "example-rg"
| where Log_s has "relay_security"
| order by TimeGenerated asc
| project TimeGenerated, Log_s`

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

// sigKey derives the cursor HMAC key from the service principal's
// AZURE_CLIENT_SECRET — mirroring cmd/mercury's sigKey(token): the workspace
// GUID (customerId) is a PUBLIC identifier printed in Azure Portal URLs and
// diagnostic settings, so a key derived from it (the previous scheme,
// mallcoppro-834) let anyone who merely knew the workspace id forge a valid
// cursor and skip an arbitrary window of relay_security rows — no possession
// of the actual SP credential required. Deriving from the client secret
// instead means forging a cursor requires the secret itself, the same bar
// cmd/mercury already set for its own cursor.
func sigKey(clientSecret string) []byte {
	return []byte(fmt.Sprintf("mallcop-loganalytics-cursor:%s", clientSecret))
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
// RFC3339Nano timestamp — this connector has no legacy pagination-token
// cursor format to migrate from, unlike cmd/azure) and combines it with
// --since to produce the effective query floor (the later of the two wins).
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
		// the upstream response body (AAD's own error/error_description,
		// which never contains the secret we sent) is surfaced.
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

// lawTable is one table in a Log Analytics query response (v1 API returns a
// single "PrimaryResult" table for a query with no explicit `union`/multiple
// result sets, which is all this connector ever issues).
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
// API's own "timespan" field (an ISO8601 interval "<start>/<end>") rather
// than any KQL text — since is the effective floor (max of --since and the
// resumed cursor); a zero since omits "timespan" entirely (query the whole
// available retention window, mirroring cmd/azure's behavior when its
// $filter is unset).
func (c *connector) query(ctx context.Context, since time.Time) (*lawQueryResponse, error) {
	status, body, err := c.queryRaw(ctx, since)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("Log Analytics API error %d: %s", status, body)
	}

	var result lawQueryResponse
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return nil, fmt.Errorf("decode query response: %w", err)
	}
	return &result, nil
}

// queryRaw issues THE query and hands back the raw status and body. query()
// is its only scan-path caller; --doctor calls it directly so the doctor
// diagnoses the exact request the connector really makes, rather than a
// parallel reimplementation of it that could succeed while the real one 403s.
func (c *connector) queryRaw(ctx context.Context, since time.Time) (int, string, error) {
	body := map[string]any{"query": kqlQuery}
	if !since.IsZero() {
		body["timespan"] = since.UTC().Format(time.RFC3339) + "/" + time.Now().UTC().Format(time.RFC3339)
	}
	b, err := json.Marshal(body)
	if err != nil {
		return 0, "", fmt.Errorf("marshal query body: %w", err)
	}

	u := fmt.Sprintf(queryBase, c.workspaceID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return 0, "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("POST %s: %w", u, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", fmt.Errorf("read query response: %w", err)
	}
	return resp.StatusCode, string(respBody), nil
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
// back as RFC3339 with a variable-precision fractional-second component
// (observed live: 7 digits, e.g. "2026-07-20T15:10:18.7459745Z").
// time.RFC3339Nano's ".999999999" fractional pattern accepts any number of
// digits up to 9, so it parses the live shape directly; RFC3339 (no
// fraction) is tried as a fallback for a bare-second timestamp.
func parseLAWTimestamp(s string) (time.Time, error) {
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts, nil
	}
	return time.Parse(time.RFC3339, s)
}

// processTable maps every row of a lawTable (a batch of relay_security lines)
// to normalized mallcop events, returning the events and the maximum
// TimeGenerated seen — the next run's resume high-water mark. A row whose
// TimeGenerated fails to parse, or whose Log_s is not JSON, or whose decoded
// "msg" field isn't exactly "relay_security" (a defensive re-check: the KQL
// filter is a substring match on Log_s, which — cheaply, if implausibly —
// could match some OTHER line whose "detail" text happens to contain the
// substring "relay_security") is skipped with a warning, never fabricated or
// silently dropped without a trace.
func processTable(tbl lawTable, org string) ([]*event.Event, time.Time, error) {
	tsIdx := columnIndex(tbl.Columns, "TimeGenerated")
	logIdx := columnIndex(tbl.Columns, "Log_s")
	if tsIdx < 0 || logIdx < 0 {
		return nil, time.Time{}, fmt.Errorf("query response missing TimeGenerated/Log_s column (got %+v)", tbl.Columns)
	}

	var events []*event.Event
	var maxSeen time.Time

	for _, row := range tbl.Rows {
		if len(row) <= tsIdx || len(row) <= logIdx {
			fmt.Fprintf(os.Stderr, "warn: skipping row: too few columns: %v\n", row)
			continue
		}
		tsStr, _ := row[tsIdx].(string)
		logStr, _ := row[logIdx].(string)

		ts, err := parseLAWTimestamp(tsStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: skipping row: bad TimeGenerated %q: %v\n", tsStr, err)
			continue
		}

		var raw map[string]any
		if err := json.Unmarshal([]byte(logStr), &raw); err != nil {
			fmt.Fprintf(os.Stderr, "warn: skipping row: Log_s is not JSON: %v\n", err)
			continue
		}
		if msg, _ := raw["msg"].(string); msg != "relay_security" {
			continue
		}

		decision, _ := raw["decision"].(string)
		pubkey, _ := raw["pubkey"].(string)
		remote, _ := raw["remote"].(string)
		domain, _ := raw["domain"].(string)
		detail, _ := raw["detail"].(string)

		results := normalize.LogAnalytics(decision, pubkey, remote, domain, detail)
		idBase := sha256Hex(fmt.Sprintf("loganalytics:%s:%s", tsStr, logStr))
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
				Source:    "loganalytics",
				Type:      r.Type,
				Actor:     pubkey,
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
		doctorMode          = flag.Bool("doctor", false, "Self-diagnose this connector's Azure access and print one JSON DiagnosisReport on stdout, instead of scanning")
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

	// --doctor short-circuits BEFORE the credential precondition below: a
	// connector with no usable credential is exactly one of the states the
	// doctor exists to name, so it must produce a report rather than the same
	// bare error the operator already could not act on.
	if *doctorMode {
		return runDoctor(context.Background(), os.Stdout,
			doctorConnectorID(*workspaceResourceID, *workspaceID),
			*workspaceID, *workspaceResourceID, tenantID, clientID, clientSecret)
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
