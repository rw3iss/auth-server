// Package audit records security-relevant events to the audit_log table.
//
// Design goals (AUDIT roadmap "audit log writer" item):
//
//  1. Never block the request path. Auth must stay fast — Record() pushes
//     to a buffered channel and returns immediately. A background goroutine
//     drains and writes to the sink.
//  2. Configurable, drop-in. The Sink interface lets us swap Postgres for
//     a NoOp (dev/disabled) or future SIEM/Kafka exporters without
//     touching call sites.
//  3. Tolerant of overflow. If the channel fills (DB slow, sink down), we
//     drop events rather than block the producer. A periodic counter line
//     surfaces the drop rate so silent loss is visible.
//  4. Runtime-toggleable. AUDIT_ENABLED can be flipped without redeploy
//     by reloading config; the writer respects the current value.
//
// Call sites use a single line:
//
//	audit.Record(ctx, audit.Event{Action: "login.success", ActorID: u.ID})
//
// Required fields: Action, At. Everything else is contextual.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ven/auth/internal/logging"
	"github.com/ven/auth/pkg/shared/types"
)

// Event is one record's worth of audit data. JSON-encoded into the `details`
// column when fields don't map to dedicated columns.
type Event struct {
	ID             types.ID       `json:"id"`
	At             time.Time      `json:"at"`
	Action         string         `json:"action"`                      // e.g. "login.success", "refresh.reuse_detected"
	ActorUserID    *types.ID      `json:"actor_user_id,omitempty"`     // who did it; nil for unauthenticated events
	SubjectUserID  *types.ID      `json:"subject_user_id,omitempty"`   // who it was done TO; often == ActorUserID
	OrganizationID *types.ID      `json:"organization_id,omitempty"`
	ResourceType   string         `json:"resource_type,omitempty"`     // "user", "session", "refresh_token"
	ResourceID     *types.ID      `json:"resource_id,omitempty"`
	IP             string         `json:"ip,omitempty"`
	UserAgent      string         `json:"ua,omitempty"`
	Details        map[string]any `json:"details,omitempty"`           // arbitrary context
}

// Sink writes audit events to durable storage. Implementations must be safe
// for concurrent calls from the background drainer (Writer guarantees that
// today, but a parallel-write impl might want a real fan-out).
type Sink interface {
	Write(ctx context.Context, e *Event) error
}

// Writer holds the buffered channel and background drainer. Created via
// New(); the package-level default is installed via SetDefault and exposed
// via the package-level Record function for ergonomic call sites.
type Writer struct {
	enabled atomic.Bool
	sink    Sink
	queue   chan *Event

	// Counters surfaced periodically so silent loss is visible.
	dropped  atomic.Uint64
	written  atomic.Uint64

	// Shutdown plumbing — Stop() signals the drainer to flush and exit.
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

// Config configures a Writer.
type Config struct {
	Enabled    bool // AUDIT_ENABLED
	BufferSize int  // AUDIT_BUFFER_SIZE; default 1024
}

// New constructs a Writer. The drainer goroutine starts immediately; call
// Stop() at shutdown to flush remaining events.
func New(cfg Config, sink Sink) *Writer {
	if sink == nil {
		sink = NoopSink{}
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 1024
	}
	w := &Writer{
		sink:  sink,
		queue: make(chan *Event, cfg.BufferSize),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	w.enabled.Store(cfg.Enabled)
	go w.drain(context.Background())
	go w.reportDrops()
	return w
}

// SetEnabled toggles audit writes at runtime. When disabled, Record drops
// events silently (without incrementing the dropped counter — disabled is
// not the same as "dropping under load").
func (w *Writer) SetEnabled(v bool) {
	w.enabled.Store(v)
}

// Record queues an event for async write. Returns immediately. On overflow
// the event is dropped and the dropped counter increments — operators see
// this in the periodic report.
//
// At is filled in if zero; ID is generated if zero.
func (w *Writer) Record(ctx context.Context, e Event) {
	if !w.enabled.Load() {
		return
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	if e.ID == (types.ID{}) {
		e.ID = types.NewID()
	}
	select {
	case w.queue <- &e:
	default:
		w.dropped.Add(1)
	}
}

// Stop signals the drainer to finish remaining events and exit. Blocks until
// the queue is empty or a 5s grace period elapses.
func (w *Writer) Stop() {
	w.once.Do(func() {
		close(w.stop)
		select {
		case <-w.done:
		case <-time.After(5 * time.Second):
			logging.FromContext(context.Background()).Warn("audit drainer shutdown timed out; events may be lost")
		}
	})
}

func (w *Writer) drain(ctx context.Context) {
	defer close(w.done)
	for {
		select {
		case <-w.stop:
			// Drain remaining buffered events with a tight deadline.
			drainCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			for {
				select {
				case e := <-w.queue:
					_ = w.sink.Write(drainCtx, e)
				default:
					return
				}
			}
		case e := <-w.queue:
			writeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := w.sink.Write(writeCtx, e); err != nil {
				slog.Warn("audit write failed",
					"action", e.Action,
					"err", err,
				)
			} else {
				w.written.Add(1)
			}
			cancel()
		}
	}
}

// reportDrops emits a periodic INFO line summarising sink throughput +
// drops. Runs forever until process exit; cheap.
func (w *Writer) reportDrops() {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	var lastWritten, lastDropped uint64
	for {
		select {
		case <-w.stop:
			return
		case <-t.C:
			written := w.written.Load()
			dropped := w.dropped.Load()
			if written != lastWritten || dropped != lastDropped {
				slog.Info("audit stats",
					"written_total", written,
					"dropped_total", dropped,
					"written_60s", written-lastWritten,
					"dropped_60s", dropped-lastDropped,
				)
				lastWritten, lastDropped = written, dropped
			}
		}
	}
}

// --- Package-level convenience -------------------------------------------

// defaultWriter is installed via SetDefault and used by the bare Record()
// function. Call sites in services use Record() so they don't need to
// thread a writer through every service constructor.
var defaultWriter atomic.Pointer[Writer]

// SetDefault installs w as the package-level writer. Called once at server
// boot from main.go.
func SetDefault(w *Writer) { defaultWriter.Store(w) }

// Default returns the installed writer or nil if none is set.
func Default() *Writer { return defaultWriter.Load() }

// Record is the package-level convenience entry point. No-op if no writer
// has been installed (e.g. in unit tests that don't care).
func Record(ctx context.Context, e Event) {
	w := defaultWriter.Load()
	if w == nil {
		return
	}
	w.Record(ctx, e)
}

// --- Sink implementations -------------------------------------------------

// NoopSink discards every event. Used when AUDIT_ENABLED=false or when an
// operator wants the writer ready-to-toggle but inert.
type NoopSink struct{}

func (NoopSink) Write(_ context.Context, _ *Event) error { return nil }

// --- Detail helpers -------------------------------------------------------

// MarshalDetails turns a map into a JSON-encoded string. Used by sinks that
// store details in a TEXT column or want a stable representation in logs.
func MarshalDetails(d map[string]any) string {
	if len(d) == 0 {
		return ""
	}
	b, err := json.Marshal(d)
	if err != nil {
		return ""
	}
	return string(b)
}
