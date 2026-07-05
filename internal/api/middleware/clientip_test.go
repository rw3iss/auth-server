package middleware

import (
	"net/http/httptest"
	"testing"
)

// AUDIT 1.15: without trusted-proxies configured, XFF is ignored entirely.
// Anything else is a spoofing vector.
func TestRealIPIgnoresXFFWithoutTrustedProxies(t *testing.T) {
	// Reset state to ensure the test is isolated.
	_ = ConfigureTrustedProxies(nil)

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.1:443"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")

	if got := RealIP(r); got != "192.0.2.1" {
		t.Fatalf("expected RemoteAddr ignored=192.0.2.1, got %q", got)
	}
}

// AUDIT 1.15: XFF from a trusted proxy IS honored — pick the right-most
// non-trusted entry.
func TestRealIPHonorsXFFFromTrustedProxy(t *testing.T) {
	if err := ConfigureTrustedProxies([]string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("configure: %v", err)
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:443"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")

	if got := RealIP(r); got != "203.0.113.7" {
		t.Fatalf("expected 203.0.113.7, got %q", got)
	}
}

// Chained proxies: walk right-to-left, skip trusted entries.
func TestRealIPChainedProxies(t *testing.T) {
	if err := ConfigureTrustedProxies([]string{"10.0.0.0/8", "172.16.0.0/12"}); err != nil {
		t.Fatalf("configure: %v", err)
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:443" // outermost proxy
	// XFF: client → P1 → P2 → us. P1 (172.16) appended client; P2 (10.0)
	// appended P1.
	r.Header.Set("X-Forwarded-For", "203.0.113.7, 172.16.5.5")

	if got := RealIP(r); got != "203.0.113.7" {
		t.Fatalf("expected 203.0.113.7, got %q", got)
	}
}

// Untrusted peer sending XFF: ignore the header, return the peer's IP.
func TestRealIPUntrustedPeerSpoofingXFF(t *testing.T) {
	if err := ConfigureTrustedProxies([]string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("configure: %v", err)
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.99:1234" // not in trusted set
	r.Header.Set("X-Forwarded-For", "1.2.3.4")

	if got := RealIP(r); got != "203.0.113.99" {
		t.Fatalf("expected peer IP 203.0.113.99, got %q", got)
	}
}

func TestConfigureTrustedProxiesRejectsBadCIDR(t *testing.T) {
	if err := ConfigureTrustedProxies([]string{"not-a-cidr"}); err == nil {
		t.Fatal("expected error on bad CIDR")
	}
}
