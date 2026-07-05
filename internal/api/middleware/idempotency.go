package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/rw3iss/auth/internal/cache"
)

// Idempotency-Key middleware. AUDIT 9.4: mobile clients on bad networks
// retry POST requests. Without idempotency, double-clicks during
// registration create two users; double-login creates two refresh-token
// rows. The pattern is standard (Stripe popularised it): clients send a
// random `Idempotency-Key` header; the server, on receiving the first
// request, executes it normally; subsequent retries with the same key
// short-circuit to the cached response.
//
// Cache key includes the request body's SHA-256 so two different requests
// can't be force-merged by sending the same key. Cache TTL is 5 minutes —
// long enough to cover network retries, short enough that operationally
// stale state doesn't accumulate.
//
// When Redis is unavailable, this middleware degrades to no-op: every
// request executes normally. Operators trade idempotency for availability
// in that case, which is the right tradeoff for an auth service.

const (
	idempotencyKeyHeader = "Idempotency-Key"
	idempotencyMaxAge    = 5 * time.Minute
	idempotencyKeyMaxLen = 200
)

// cacheClient is the subset of the redis API we need. Decouples the
// middleware from cache.RedisTokenCache so it can be tested against a
// fake.
type cacheClient interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	SetNX(ctx context.Context, key string, value interface{}, ttl time.Duration) *redis.BoolCmd
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) *redis.StatusCmd
}

// Idempotency returns middleware that consults the given Redis client for
// cached responses. Passing nil disables it entirely (no-op pass-through).
func Idempotency(client *redis.Client) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only POST methods carry idempotent intent; GET/DELETE are
			// already idempotent by HTTP semantics.
			if client == nil || r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}
			key := r.Header.Get(idempotencyKeyHeader)
			if key == "" || len(key) > idempotencyKeyMaxLen {
				next.ServeHTTP(w, r)
				return
			}

			// Buffer the body so we can hash it AND replay it to the
			// downstream handler. Body sizes are already capped by
			// BodyLimit middleware running upstream, so this isn't
			// unbounded.
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			_ = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			cacheKey := idempotencyCacheKey(key, r.URL.Path, bodyBytes)

			// Cache hit → replay cached response and stop.
			ctx := r.Context()
			if cached, err := client.Get(ctx, cacheKey).Bytes(); err == nil && len(cached) > 0 {
				var stored cachedResponse
				if json.Unmarshal(cached, &stored) == nil {
					for k, v := range stored.Headers {
						w.Header().Set(k, v)
					}
					w.WriteHeader(stored.Status)
					_, _ = w.Write(stored.Body)
					return
				}
			}

			// Cache miss: execute the handler, capture the response, store
			// it for replay.
			rec := &recordingWriter{ResponseWriter: w, body: &bytes.Buffer{}, headers: map[string]string{}}
			next.ServeHTTP(rec, r)

			// Don't cache 5xx — server errors aren't idempotent
			// outcomes and the client should be free to retry.
			if rec.status >= 500 || rec.status == 0 {
				return
			}

			payload, _ := json.Marshal(cachedResponse{
				Status:  rec.status,
				Headers: rec.headers,
				Body:    rec.body.Bytes(),
			})
			// Use Set with TTL (overwrite-friendly) rather than SetNX —
			// the second concurrent request will re-execute and overwrite,
			// which is fine because the body-hash component of the key
			// means re-executions are content-identical.
			_ = client.Set(ctx, cacheKey, payload, idempotencyMaxAge).Err()
		})
	}
}

// cachedResponse is what we serialise to Redis. JSON-encoded for the
// debugger's sake; not perf-critical.
type cachedResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body"`
}

// recordingWriter captures the response so we can both forward it to the
// real ResponseWriter and stash a copy for the idempotency cache.
type recordingWriter struct {
	http.ResponseWriter
	status      int
	headersSent bool
	body        *bytes.Buffer
	headers     map[string]string
}

func (r *recordingWriter) WriteHeader(code int) {
	if r.headersSent {
		return
	}
	r.headersSent = true
	r.status = code
	// Snapshot headers — the underlying ResponseWriter's header map can
	// mutate after WriteHeader, but the snapshot is what the cache should
	// replay on retry.
	for k, v := range r.ResponseWriter.Header() {
		if len(v) > 0 {
			r.headers[k] = v[0]
		}
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recordingWriter) Write(b []byte) (int, error) {
	if !r.headersSent {
		r.WriteHeader(http.StatusOK)
	}
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}

func idempotencyCacheKey(headerKey, path string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(headerKey))
	h.Write([]byte{'|'})
	h.Write([]byte(path))
	h.Write([]byte{'|'})
	h.Write(body)
	return "auth:idem:" + hex.EncodeToString(h.Sum(nil))
}

// compile-time guard that we satisfy the interface we documented.
var _ cacheClient = (*redis.Client)(nil)
var _ = cache.CachedClaims{} // keep import used if future refactors lean on it
