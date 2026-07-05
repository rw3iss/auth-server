package sso

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rw3iss/auth/internal/config"
)

// genTestP8 returns a fresh ES256 (P-256) private key as PKCS#8 PEM text.
func genTestP8(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func newTestAppleProvider(t *testing.T, pem string) *AppleProvider {
	t.Helper()
	p, err := NewAppleProvider(config.OAuthProviderConfig{
		Enabled:  true,
		ClientID: "com.rw3iss.svc",
		Scopes:   []string{"name", "email"},
	}, "TEAMID1234", "KEYID56789", pem)
	if err != nil {
		t.Fatalf("NewAppleProvider: %v", err)
	}
	return p
}

func TestParseApplePrivateKey_PEM(t *testing.T) {
	p := newTestAppleProvider(t, genTestP8(t))
	if p.privateKey == nil {
		t.Fatal("expected private key to parse from PEM")
	}
}

func TestParseApplePrivateKey_Base64(t *testing.T) {
	raw := genTestP8(t)
	b64 := base64.StdEncoding.EncodeToString([]byte(raw))
	p := newTestAppleProvider(t, b64)
	if p.privateKey == nil {
		t.Fatal("expected private key to parse from base64-wrapped PEM")
	}
}

func TestGenerateClientSecret(t *testing.T) {
	p := newTestAppleProvider(t, genTestP8(t))

	secret, err := p.generateClientSecret()
	if err != nil {
		t.Fatalf("generateClientSecret: %v", err)
	}

	// Verify it with the matching public key; assert the Apple-required claims.
	parsed, err := jwt.Parse(secret, func(tok *jwt.Token) (interface{}, error) {
		if _, ok := tok.Method.(*jwt.SigningMethodECDSA); !ok {
			t.Fatalf("expected ES256, got %v", tok.Header["alg"])
		}
		if tok.Header["kid"] != "KEYID56789" {
			t.Fatalf("kid = %v, want KEYID56789", tok.Header["kid"])
		}
		return &p.privateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("verify client secret: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["iss"] != "TEAMID1234" {
		t.Errorf("iss = %v, want TEAMID1234", claims["iss"])
	}
	if claims["sub"] != "com.rw3iss.svc" {
		t.Errorf("sub = %v, want com.rw3iss.svc", claims["sub"])
	}
	if claims["aud"] != appleIssuer {
		t.Errorf("aud = %v, want %s", claims["aud"], appleIssuer)
	}
	exp, _ := claims["exp"].(float64)
	if int64(exp) <= time.Now().Unix() {
		t.Error("exp must be in the future")
	}
}

func TestParseAppleUserName(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		wantFirst string
		wantLast  string
	}{
		{"first login", `{"name":{"firstName":"Jane","lastName":"Doe"},"email":"j@x.com"}`, "Jane", "Doe"},
		{"nth login (absent)", "", "", ""},
		{"malformed", "not json", "", ""},
		{"no name key", `{"email":"j@x.com"}`, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			first, last := ParseAppleUserName(c.in)
			if first != c.wantFirst || last != c.wantLast {
				t.Errorf("got (%q,%q), want (%q,%q)", first, last, c.wantFirst, c.wantLast)
			}
		})
	}
}

// TestValidateIDToken_RejectsUnsigned ensures the verifier no longer accepts an
// unverified token (the prior ParseUnverified hole). An RS256 token signed by a
// key Apple never published must fail.
func TestValidateIDToken_RejectsForgedToken(t *testing.T) {
	p := newTestAppleProvider(t, genTestP8(t))
	// HS256 token (wrong family entirely) — must be rejected by WithValidMethods.
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": appleIssuer,
		"aud": "com.rw3iss.svc",
		"sub": "001234.abcd",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signed, _ := tok.SignedString([]byte("attacker-secret"))
	if _, err := p.ValidateIDToken(t.Context(), signed); err == nil {
		t.Fatal("expected forged/unsigned id_token to be rejected")
	}
}
