package doctor

import (
	"strings"
	"testing"
	"time"
)

func TestDecodeIdentityReadsOIDAndAppIDOffline(t *testing.T) {
	token := makeToken(t, appTokenClaims(actualOID, expectedAppID, "https://api.loganalytics.io"))
	c, err := DecodeIdentity(token)
	if err != nil {
		t.Fatalf("DecodeIdentity: %v", err)
	}
	if c.OID != actualOID {
		t.Errorf("oid = %q, want %q", c.OID, actualOID)
	}
	if c.AppID != expectedAppID {
		t.Errorf("appid = %q, want %q", c.AppID, expectedAppID)
	}
	if c.TID != tenantID {
		t.Errorf("tid = %q, want %q", c.TID, tenantID)
	}
	if c.Audience != "https://api.loganalytics.io" {
		t.Errorf("aud = %q", c.Audience)
	}
	if !c.IsAppToken() {
		t.Error("idtyp=app must read as a service-principal token")
	}
	if c.Expiry.IsZero() || c.Expiry.Before(time.Now()) {
		t.Errorf("exp not decoded: %v", c.Expiry)
	}
}

// SECURITY: an error from DecodeIdentity must never carry any part of the
// token — it would put a live bearer credential into logs and into the
// DiagnosisReport the operator shares.
func TestDecodeIdentityErrorsNeverEchoTheToken(t *testing.T) {
	secretish := "eyJhbGciOiJSUzI1NiJ9.SUPERSECRETPAYLOAD.sig"
	cases := []string{
		"not-a-jwt",
		secretish + ".extra.segments",
		"a.!!!not-base64!!!.c",
		makeToken(t, map[string]any{"tid": tenantID}), // no oid
	}
	for _, tok := range cases {
		_, err := DecodeIdentity(tok)
		if err == nil {
			continue
		}
		for _, seg := range strings.Split(tok, ".") {
			// Single characters ("a", "c") occur in ordinary prose; only a
			// segment long enough to BE credential material is a leak.
			if len(seg) < 8 {
				continue
			}
			if strings.Contains(err.Error(), seg) {
				t.Errorf("error leaked a token segment %q: %v", seg, err)
			}
		}
	}
}

func TestDecodeIdentityRejectsTokenWithoutOID(t *testing.T) {
	token := makeToken(t, map[string]any{"tid": tenantID, "aud": "https://api.loganalytics.io"})
	_, err := DecodeIdentity(token)
	if err == nil {
		t.Fatal("a token with no oid claim must not be reported as a readable identity")
	}
}

func TestDecodeIdentityRejectsNonJWT(t *testing.T) {
	if _, err := DecodeIdentity("opaque-token"); err == nil {
		t.Fatal("an opaque (non-JWT) token must be reported as unreadable, not silently accepted")
	}
}

func TestAudienceMatchesScopeNormalizesDefaultSuffix(t *testing.T) {
	if !audienceMatchesScope("https://api.loganalytics.io", ScopeLogAnalytics) {
		t.Error("aud without /.default should match the /.default scope")
	}
	if !audienceMatchesScope("https://management.azure.com/", ScopeARM) {
		t.Error("trailing slash should not defeat the comparison")
	}
	if audienceMatchesScope("https://management.azure.com", ScopeLogAnalytics) {
		t.Error("an ARM token must not read as a Log Analytics token")
	}
}
