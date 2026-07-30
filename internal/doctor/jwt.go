package doctor

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// IdentityClaims is the subset of an AAD access token's claims the Azure
// doctor reads. Claim names and shape were taken from a REAL AAD token minted
// against https://api.loganalytics.io (claim key set captured 2026-07-30; the
// token itself was never written anywhere).
//
// Only these decoded claims ever leave DecodeIdentity — the token string does
// not, and must never be logged, wrapped into an error, or serialized.
type IdentityClaims struct {
	// OID is the AAD OBJECT id of the acting principal. This is the id role
	// assignments are made against (`az role assignment create --assignee <oid>`)
	// and the id an ARM AuthorizationFailed body names.
	OID string `json:"oid"`
	// AppID is the application (client) id of a service principal. Present on
	// client-credentials tokens; absent on a plain user token.
	AppID string `json:"appid"`
	// TID is the AAD tenant the token was issued in.
	TID string `json:"tid"`
	// Audience is the resource the token was minted FOR. A token whose
	// audience is not the endpoint being called is a distinct, diagnosable
	// failure from a permission denial.
	Audience string `json:"-"`
	// IDType is "app" for a client-credentials (service principal) token and
	// "user" for a delegated user token. The Azure SP doctor's whole premise is
	// an app token; a user token here means the operator wired an interactive
	// identity into a headless connector.
	IDType string `json:"idtyp"`
	// Expiry is the token's exp claim as a time.
	Expiry time.Time `json:"-"`
}

// errNotAJWT is returned when the token is not a three-segment JWS. AAD access
// tokens for Azure resources are JWTs; a non-JWT here means the token endpoint
// handed back something the doctor cannot read offline.
var errNotAJWT = errors.New("access token is not a three-segment JWT")

// DecodeIdentity decodes an AAD access token's claims set LOCALLY — zero
// network calls (design §7: "Azure client-cred / managed-identity tokens are
// self-describing JWTs — decode oid/appid locally").
//
// It deliberately does NOT verify the signature: the doctor is not an
// authorization decision point, it is reading which identity the connector is
// about to present. AAD already verified the token when it minted it, and the
// endpoint being probed verifies it again on the wire. Trusting these claims
// for anything other than reporting would be wrong; reporting is all this does.
//
// SECURITY: no error returned by this function contains any part of the token.
// Callers must preserve that — an error mentioning the token would leak a live
// bearer credential into logs and into the DiagnosisReport.
func DecodeIdentity(token string) (IdentityClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return IdentityClaims{}, errNotAJWT
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return IdentityClaims{}, fmt.Errorf("access token payload is not base64url: %w", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return IdentityClaims{}, fmt.Errorf("access token payload is not JSON: %w", err)
	}

	var c IdentityClaims
	c.OID, _ = raw["oid"].(string)
	c.AppID, _ = raw["appid"].(string)
	c.TID, _ = raw["tid"].(string)
	c.IDType, _ = raw["idtyp"].(string)
	// aud is a string on v1.0 AAD tokens; the JWT spec also permits an array.
	switch aud := raw["aud"].(type) {
	case string:
		c.Audience = aud
	case []any:
		if len(aud) > 0 {
			c.Audience, _ = aud[0].(string)
		}
	}
	if exp, ok := raw["exp"].(float64); ok {
		c.Expiry = time.Unix(int64(exp), 0).UTC()
	}

	if c.OID == "" {
		// A token with no oid is not something this doctor can attribute an
		// identity to. Report it as unreadable rather than silently claiming
		// "identity ok" — the whole wrong-SP case turns on this claim.
		return c, errors.New("access token carries no oid claim")
	}
	return c, nil
}

// IsAppToken reports whether the claims describe a client-credentials
// (service principal) token rather than a delegated user token.
func (c IdentityClaims) IsAppToken() bool {
	// idtyp is present on current AAD tokens; appid+no upn is the fallback
	// signal on older ones.
	if c.IDType != "" {
		return c.IDType == "app"
	}
	return c.AppID != ""
}
