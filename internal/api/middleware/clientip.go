package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
)

// AUDIT 1.15: trust X-Forwarded-For only from proxies on a configured
// allowlist.
//
// Before, getClientIP took the first comma-separated value of XFF
// unconditionally. Any caller could spoof its source IP by sending
// `X-Forwarded-For: 1.2.3.4`, bypassing per-IP rate limits and poisoning
// IP-logged refresh-token rows.
//
// trustedProxies holds the parsed CIDR allowlist set once at boot via
// ConfigureTrustedProxies. We use atomic.Pointer so reads on the hot path
// (every request) don't need a mutex.

var trustedProxies atomic.Pointer[[]*net.IPNet]

// ConfigureTrustedProxies parses a list of CIDR strings (e.g.
// "10.0.0.0/8,fc00::/7") and installs them as the trusted-proxy set. Called
// once at server boot from main.go. Returns an error if any CIDR is malformed.
//
// An empty slice means "no trusted proxies" — XFF is ignored entirely and
// only the request's RemoteAddr is used. That's the safest default for
// servers that aren't behind a known reverse proxy.
func ConfigureTrustedProxies(cidrs []string) error {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, raw := range cidrs {
		c := strings.TrimSpace(raw)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return fmt.Errorf("invalid trusted proxy CIDR %q: %w", c, err)
		}
		nets = append(nets, n)
	}
	trustedProxies.Store(&nets)
	return nil
}

// RealIP returns the originating client IP for a request, honoring
// X-Forwarded-For only when it arrived through a trusted proxy.
//
// Algorithm (RFC 7239 §7.1 + standard practice):
//   - r.RemoteAddr is what the kernel saw — always trusted as the
//     immediate hop's address.
//   - If that immediate hop is in the trusted-proxies list, we can trust
//     the XFF header it appended. Walk XFF from right to left, skipping
//     entries that are also trusted-proxy IPs (chained proxies). The
//     first non-trusted entry is the real client.
//   - If the immediate hop is NOT trusted, ignore XFF entirely and use
//     RemoteAddr.
func RealIP(r *http.Request) string {
	remoteHost := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		remoteHost = host
	}

	nets := trustedProxies.Load()
	if nets == nil || len(*nets) == 0 {
		// No trusted proxies configured — never honor XFF.
		return remoteHost
	}

	remoteIP := net.ParseIP(remoteHost)
	if remoteIP == nil || !isInNets(remoteIP, *nets) {
		// The peer is not a trusted proxy. Ignore XFF.
		return remoteHost
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return remoteHost
	}

	// Walk right-to-left; first IP not in the trusted set is the client.
	entries := strings.Split(xff, ",")
	for i := len(entries) - 1; i >= 0; i-- {
		ipStr := strings.TrimSpace(entries[i])
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if !isInNets(ip, *nets) {
			return ipStr
		}
	}
	// Everything in XFF is a trusted proxy — fall back to remote.
	return remoteHost
}

func isInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
