// Package oidc implements the OpenID Connect provider surface: signing keys, discovery, JWKS,
// ID tokens, the authorization-code flow with PKCE, and userinfo.
//
// WHY A SEPARATE PACKAGE FROM internal/auth/jwt. The existing JWT service issues FOUR token types
// (access, refresh, password-reset, email-verify) signed with HMAC and purpose-derived secrets. Those are
// entirely internal: we mint them and we are the only party that validates them, so symmetric signing is
// correct and rotation is cheap.
//
// An OIDC ID token is the opposite: its whole purpose is to be verified by SOMEONE ELSE. That requires
// asymmetric signing — the relying party gets a PUBLIC key and can check the signature without ever
// holding anything that would let them mint a token. Mixing the two concerns in one service would have
// meant either weakening the internal tokens or handing out a secret that forges them.
package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
)

// KeyManager owns the RSA signing key and publishes its public half as a JWKS.
type KeyManager struct {
	mu      sync.RWMutex
	private *rsa.PrivateKey
	kid     string
}

// JWK is one key in a JSON Web Key Set (RFC 7517).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS is the document served at /.well-known/jwks.json.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// NewKeyManager resolves the signing key, in priority order:
//
//  1. OIDC_PRIVATE_KEY_PEM      — the PEM itself (how you would inject it from a secret manager).
//  2. OIDC_PRIVATE_KEY_FILE     — a path to a PEM file.
//  3. keyDir/oidc-signing-key.pem — generated on first boot and persisted.
//
// The generate-and-persist fallback is deliberate: a key that regenerates on restart would invalidate
// every outstanding ID token and break every relying party's cached JWKS, silently, on every deploy.
func NewKeyManager(keyDir string) (*KeyManager, error) {
	if pemStr := os.Getenv("OIDC_PRIVATE_KEY_PEM"); pemStr != "" {
		key, err := parsePrivateKeyPEM([]byte(pemStr))
		if err != nil {
			return nil, fmt.Errorf("OIDC_PRIVATE_KEY_PEM: %w", err)
		}
		return newFromKey(key)
	}

	path := os.Getenv("OIDC_PRIVATE_KEY_FILE")
	if path == "" {
		if keyDir == "" {
			keyDir = "."
		}
		path = filepath.Join(keyDir, "oidc-signing-key.pem")
	}

	if data, err := os.ReadFile(path); err == nil {
		key, err := parsePrivateKeyPEM(data)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		return newFromKey(key)
	}

	// First boot: generate and persist. 2048 is the RFC 7518 floor for RS256 and what every relying-party
	// library accepts; 4096 buys little here and costs signing time on every token.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating OIDC signing key: %w", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating key dir: %w", err)
	}
	// 0600: the private key is the one secret that, if leaked, lets an attacker impersonate ANY user to
	// EVERY relying party. It must never be group- or world-readable.
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return nil, fmt.Errorf("persisting signing key to %s: %w", path, err)
	}
	return newFromKey(key)
}

func newFromKey(key *rsa.PrivateKey) (*KeyManager, error) {
	km := &KeyManager{private: key}
	km.kid = thumbprint(&key.PublicKey)
	return km, nil
}

func parsePrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unsupported key format: %w", err)
	}
	k, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA")
	}
	return k, nil
}

// thumbprint derives a stable `kid` from the public key (RFC 7638 style).
//
// Deriving it rather than assigning a random id means the SAME key always advertises the SAME kid — so a
// relying party that cached the JWKS still matches after a restart, and a future second key gets a
// different kid automatically, which is exactly what makes rotation work.
func thumbprint(pub *rsa.PublicKey) string {
	canonical, _ := json.Marshal(map[string]string{
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
	})
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// PrivateKey returns the active signing key.
func (km *KeyManager) PrivateKey() *rsa.PrivateKey {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.private
}

// KID returns the active key id, written into every token header so a verifier knows which JWKS entry to use.
func (km *KeyManager) KID() string {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.kid
}

// JWKS returns the public key set. Public by design — this is what makes local verification possible.
func (km *KeyManager) JWKS() JWKS {
	km.mu.RLock()
	defer km.mu.RUnlock()
	pub := &km.private.PublicKey
	return JWKS{Keys: []JWK{{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: km.kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}
}
