package middleware

import (
	"net/http"

	"github.com/ven/auth/pkg/shared/errors"
)

// BodyLimit returns middleware that caps the request body at maxBytes via
// http.MaxBytesReader. AUDIT 7.10: every handler today does
// json.NewDecoder(r.Body).Decode without bounding the read, so a multi-MB
// or multi-GB body allocates until OOM or the connection-level read timeout
// kicks in. The middleware wraps r.Body so the decoder errors cleanly at
// the limit instead.
//
// The default cap is 5 MB (DefaultBodyLimit). Upload-heavy routes (bulk
// CSV, image batches) opt into a larger cap with BodyLimitForRoute applied
// at registration time. Anything > MaxBodyLimit is rejected at config
// time — there's no legitimate auth request that big.
const (
	DefaultBodyLimit = int64(5 * 1024 * 1024)   // 5 MB platform default
	MaxBodyLimit     = int64(15 * 1024 * 1024)  // 15 MB hard ceiling — CSV uploads
)

// BodyLimit returns a middleware that enforces the given byte cap. If
// maxBytes ≤ 0 the default is used; if it exceeds MaxBodyLimit it's
// clamped down (loudly fail-shut rather than fail-open on misconfig).
func BodyLimit(maxBytes int64) func(http.Handler) http.Handler {
	if maxBytes <= 0 {
		maxBytes = DefaultBodyLimit
	}
	if maxBytes > MaxBodyLimit {
		maxBytes = MaxBodyLimit
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// PayloadTooLargeError surfaces the 413 response for handlers that bubble
// up MaxBytesError. Plumbing rather than logic — handlers typically don't
// need to call this directly because the JSON decoder error is mapped to
// 400 already.
func PayloadTooLargeError() *errors.AppError {
	return errors.New(errors.ErrCodeValidation, "Request body too large", http.StatusRequestEntityTooLarge)
}
