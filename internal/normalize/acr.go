package normalize

import "strings"

// ACR maps a single Azure Container Registry ContainerRegistryRepositoryEvents
// row (surfaced via the acr-diag-to-law diagnostic setting on
// acrnostrrelayprod, nostr-relay's infra/prod.bicep, mallcoppro-29f) to a
// canonical mallcop event.
//
// Why this exists: the image running the relay (acrnostrrelayprod's
// nostr-relay-prod repository) IS this system's software supply chain — a
// push replaces what's deployed exactly the way a new npm/pip dependency
// replaces code that runs. ACR's diagnostic log does not emit this to the
// subscription/RG-scoped Activity Log (mallcoppro-f8d's connectorPrincipalId
// grant covers that); it is its own data-plane category
// (ContainerRegistryRepositoryEvents), queried by cmd/acrpush.
//
// This connector queries ONLY OperationName in ("Push", "Delete",
// "importImage") — Pull and other read-shaped operations carry no
// supply-chain-mutation signal and are filtered out server-side in the KQL
// (see cmd/acrpush's kqlQuery), so they never reach this function.
// importImage is ACR's operation for `az acr import` — it pulls an image
// from an ARBITRARY EXTERNAL source registry into ours, which is a
// supply-chain injection vector at least as dangerous as a Push (an
// attacker with import rights lands a poisoned image without ever pushing
// through the normal build pipeline); verified live 2026-07-27 that
// importImage lands in ContainerRegistryRepositoryEvents as its own
// OperationName, distinct from Push, and was previously silently dropped
// (0 rows reached this function). All three operations are mapped to the
// SAME Type, "dependency_add", byte-identical to
// mallcop/core/detect/dependency_tamper.go's depTamperEventTypes map key and
// its Rule 4 literal (`ev.Type == "dependency_add"`) — a Type any other
// spelling ("dependency-add", "DependencyAdd", ...) would silently never
// reach that gate. Push, Delete, and importImage share one Type
// deliberately: this gate's job is "did the artifact that runs the relay
// change," and all three answer yes; Push and importImage both set Direct
// so dependency_tamper.go's Rule 4 ("new direct dependency added") fires on
// the write that actually replaces running code, while a Delete still
// reaches Rules 1/2/5 and the type-less detectors (unusual-timing,
// volume-anomaly, new-actor) without producing a Rule-4 false positive for
// content leaving the registry.
func ACR(operationName, repository, tag, digest, identity, callerIP, loginServer, resultType string) []Result {
	switch operationName {
	case "Push", "Delete", "importImage":
		p := map[string]any{
			"action":    strings.ToLower(operationName),
			"package":   repository,
			"ecosystem": "oci",
		}
		set(p, "new_version", tag)
		set(p, "actual_hash", digest)
		set(p, "registry", loginServer)
		set(p, "ip", callerIP)
		set(p, "source_ip", callerIP)
		set(p, "identity", identity)
		set(p, "result", resultType)
		if operationName == "Push" || operationName == "importImage" {
			// A Push or an importImage is a "new direct dependency" in
			// dependency_tamper.go's Rule 4 sense — a Delete removes
			// content, it doesn't add it, so Direct stays unset (false)
			// and Rule 4 correctly never fires for it.
			p["direct"] = true
		}
		return []Result{{Type: "dependency_add", Payload: p}}
	}

	return []Result{{Type: CatchAll, Payload: map[string]any{"action": "acr:" + operationName}}}
}
