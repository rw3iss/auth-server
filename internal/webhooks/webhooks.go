// Package webhooks dispatches platform events to operator-configured HTTP
// endpoints (AUDIT C6 — stub). Currently a documented scaffold: the
// Dispatcher interface + NoOp implementation are in place so consumers can
// take a Dispatcher without nil-checks, but no live network dispatch has
// been wired yet.
//
// # Why a stub rather than a full build
//
// The auth-server already has the audit log writer (internal/audit) which
// covers the audit-trail half of the requirement. Webhooks are the
// notify-third-parties half — useful for SOC integrations, Slack
// notifications, anti-fraud signals, etc. The shape of "what events
// matter, in what payload format, with what retry semantics" is best
// designed once a real consumer asks for it.
//
// # Intended design when this is built out
//
//   - Operators configure a list of endpoints via env (WEBHOOK_ENDPOINTS,
//     comma-separated) and a signing secret (WEBHOOK_SECRET).
//   - Every dispatch carries an HMAC-SHA256 signature in
//     X-rw3iss-Signature so the receiver can validate authenticity.
//   - Dispatcher runs out-of-band via a channel-buffered goroutine
//     (mirroring internal/audit's writer) so handlers never block on a
//     slow webhook receiver. Drop-on-overflow with a counter line so
//     silent loss is visible.
//   - At-least-once delivery via a small retry loop with exponential
//     backoff. A "permanent" failure (4xx that isn't 408/429) drops the
//     event with a structured slog line.
//   - Event taxonomy mirrors the audit log Action namespace:
//     login.success, login.failed, refresh.reuse_detected,
//     user.hard_deleted, user.impersonation_started, 2fa.enabled, etc.
//   - Recipients can subscribe per-event-prefix (login.*, user.*) via a
//     small admin endpoint that writes to a webhook_subscriptions table.
//
// # Wiring sketch (when ready)
//
// The natural integration point is internal/audit.Writer — every audit
// event is already going through a structured pipeline, so the same
// fanout produces both the postgres-sink record and the webhook
// dispatches. Adding a webhook sink to the audit.Writer would reuse all
// the buffering / drop-on-overflow primitives that exist there.
//
// For now: use NoOpDispatcher and document where the wiring would go.
package webhooks

import "context"

// Event is the wire-format struct dispatched to webhook endpoints. The
// shape mirrors internal/audit.Event so the same payloads can be reused.
type Event struct {
	// Action is the event type, e.g. "login.success" or
	// "refresh.reuse_detected". Mirror the audit Action namespace so
	// receivers can subscribe per-event-prefix.
	Action string `json:"action"`

	// ActorUserID is the user who performed the action (nil for
	// system-initiated events like background cleanup).
	ActorUserID *string `json:"actor_user_id,omitempty"`

	// SubjectUserID is the user the action was performed against, when
	// different from the actor (e.g. impersonation: actor=admin,
	// subject=target).
	SubjectUserID *string `json:"subject_user_id,omitempty"`

	// OrganizationID, when present, scopes the event to an org so a
	// webhook subscriber can filter to "events from my tenant only".
	OrganizationID *string `json:"organization_id,omitempty"`

	// Details mirrors audit.Event.Details — free-form JSONB payload.
	Details map[string]any `json:"details,omitempty"`

	// At is the server timestamp. RFC3339.
	At string `json:"at"`
}

// Dispatcher fans Events out to operator-configured webhook endpoints. The
// interface is defined to make a future live implementation drop-in:
// callers take a Dispatcher (not a concrete type) so the runtime can swap
// NoOp for a Real one at boot via main.go.
type Dispatcher interface {
	// Dispatch enqueues an event for delivery. Returns nil immediately —
	// actual network I/O happens in a background goroutine. Errors during
	// delivery are logged + counted, never propagated back to the caller.
	Dispatch(ctx context.Context, event Event) error
}

// NoOpDispatcher is the safe default: it accepts every dispatch and does
// nothing. Used until a real implementation is wired. Returns nil from
// every call so callers don't need to nil-check the Dispatcher field on
// services.
type NoOpDispatcher struct{}

// NewNoOpDispatcher returns a Dispatcher that silently drops every event.
// Suitable for environments where webhooks aren't configured (the default).
func NewNoOpDispatcher() Dispatcher { return NoOpDispatcher{} }

// Dispatch is a no-op.
func (NoOpDispatcher) Dispatch(_ context.Context, _ Event) error { return nil }
