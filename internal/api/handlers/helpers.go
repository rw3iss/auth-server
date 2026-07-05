package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/rw3iss/auth/internal/api/middleware"
	"github.com/rw3iss/auth/pkg/shared/errors"
)

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

// writeError writes an error response
func writeError(w http.ResponseWriter, err *errors.AppError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.HTTPStatus)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]interface{}{
			"code":    err.Code,
			"message": err.Message,
			"details": err.Details,
		},
	})
}

// handleServiceError handles service layer errors.
//
// Typed AppErrors carry a client-safe code + message and pass through as-is.
// Anything else is an unexpected/internal error whose raw message can leak
// internals (SQL, driver text, file paths, etc.) — we log the real error
// server-side and return a single generic message to the client. This is the
// central place that obfuscates underlying errors for every portal.
func handleServiceError(w http.ResponseWriter, err error) {
	if appErr, ok := errors.AsAppError(err); ok {
		writeError(w, appErr)
		return
	}
	slog.Error("unhandled service error", "error", err.Error())
	writeError(w, errors.Internal("An unexpected error occurred. Please try again."))
}

// getClientIP delegates to middleware.RealIP — the trusted-proxy-aware
// extractor. Centralising the logic ensures handlers and rate-limiter agree
// on which IP they're talking about (AUDIT 1.15).
func getClientIP(r *http.Request) string {
	return middleware.RealIP(r)
}

// getQueryParam extracts a query parameter with a default value
func getQueryParam(r *http.Request, name, defaultValue string) string {
	value := r.URL.Query().Get(name)
	if value == "" {
		return defaultValue
	}
	return value
}

// getQueryParamInt extracts an integer query parameter with a default value
func getQueryParamInt(r *http.Request, name string, defaultValue int) int {
	value := r.URL.Query().Get(name)
	if value == "" {
		return defaultValue
	}
	var result int
	for _, c := range value {
		if c >= '0' && c <= '9' {
			result = result*10 + int(c-'0')
		} else {
			return defaultValue
		}
	}
	return result
}

// getQueryParamBool extracts a boolean query parameter
func getQueryParamBool(r *http.Request, name string) *bool {
	value := r.URL.Query().Get(name)
	if value == "" {
		return nil
	}
	result := value == "true" || value == "1"
	return &result
}
