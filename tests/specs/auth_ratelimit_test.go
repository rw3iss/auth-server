//go:build integration

package tests

import (
	"net/http"
	"testing"

	"github.com/rw3iss/auth/tests/specs/helpers"
)

func TestRateLimit_UnderLimit(t *testing.T) {
	env := helpers.NewTestEnvironment(t)

	// Make a few requests - should all succeed
	for i := 0; i < 5; i++ {
		resp := env.Client.Health(t)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Request %d failed with status %d", i+1, resp.StatusCode)
		}
	}
}

func TestRateLimit_ExceedsLimit(t *testing.T) {
	env := helpers.NewTestEnvironment(t)

	limit := env.Config.Security.RateLimitRequests
	if limit > 200 {
		t.Skip("Rate limit too high for test (>200)")
	}

	rateLimited := false
	for i := 0; i < limit+10; i++ {
		resp := env.Client.Health(t)
		if resp.StatusCode == http.StatusTooManyRequests {
			rateLimited = true
			break
		}
	}

	if !rateLimited {
		t.Error("Expected to be rate limited after exceeding the limit")
	}
}

func TestRateLimit_RetryAfterHeader(t *testing.T) {
	env := helpers.NewTestEnvironment(t)

	limit := env.Config.Security.RateLimitRequests
	if limit > 200 {
		t.Skip("Rate limit too high for test (>200)")
	}

	for i := 0; i < limit+10; i++ {
		resp := env.Client.Health(t)
		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfter := resp.Headers.Get("Retry-After")
			if retryAfter == "" {
				t.Error("Expected Retry-After header when rate limited")
			}
			return
		}
	}

	t.Error("Never hit rate limit")
}
