// Package background provides a small job registry + scheduler for
// recurring maintenance work (expired-token cleanup, audit drainage, etc.).
//
// Design — AUDIT roadmap §10.2 M16 + the project plan's "expose in admin
// dashboard" requirement:
//
//   - Job is the unit of work: a Name, an Interval, and a Run(ctx).
//   - Scheduler owns N registered jobs. Each runs on its own ticker.
//   - Jobs are individually pausable / triggerable from the admin API,
//     so operators can poke at them without bouncing the process.
//   - Scheduler holds runtime status (LastRunAt, LastDuration, LastError,
//     CurrentlyRunning) so the admin dashboard has something to render.
//   - Shutdown is coordinated via context: the parent passes a context;
//     when it cancels, every job's ticker shuts down and any in-flight
//     Run is given a chance to finish via the provided context.
//
// The interface is deliberately small: nothing here knows about Postgres,
// Redis, or any specific cleanup task. The cleanup_jobs.go file in this
// package wires concrete jobs against the repository.
package background

import (
	"context"
	"fmt"
	"sync"
	"time"

	"log/slog"
)

// Job is one piece of recurring work. Implementations should be idempotent
// and tolerant of being called manually via Trigger.
type Job interface {
	// Name is a stable identifier (e.g. "cleanup.refresh_tokens"). Shown
	// in /admin/jobs responses and used as the lookup key for Trigger /
	// Pause / Resume.
	Name() string
	// Interval is the recurring period. Returning 0 disables auto-runs;
	// the job can still be Triggered manually.
	Interval() time.Duration
	// Run executes once. The context carries a deadline (Scheduler injects
	// one based on the configured per-job timeout). Returns any error so
	// the Scheduler can record it as LastError.
	Run(ctx context.Context) error
}

// Status is the runtime snapshot exposed via /admin/jobs.
type Status struct {
	Name             string        `json:"name"`
	Interval         time.Duration `json:"interval"`
	Paused           bool          `json:"paused"`
	CurrentlyRunning bool          `json:"currently_running"`
	LastRunAt        *time.Time    `json:"last_run_at,omitempty"`
	LastDuration    time.Duration  `json:"last_duration_ns,omitempty"`
	LastError       string        `json:"last_error,omitempty"`
	RunCount        uint64        `json:"run_count"`
	ErrorCount      uint64        `json:"error_count"`
}

// jobState is the Scheduler's per-job bookkeeping. Mutex protects every
// field — runs from the ticker goroutine read and write all of them.
type jobState struct {
	job      Job
	mu       sync.Mutex
	paused   bool
	running  bool
	lastAt   *time.Time
	lastDur  time.Duration
	lastErr  string
	runs     uint64
	errors   uint64
	stopCh   chan struct{} // closed to terminate this job's loop
	triggerCh chan struct{} // unbuffered; manual triggers send here
}

// Scheduler holds the registered jobs and supervises their loops.
type Scheduler struct {
	mu      sync.RWMutex
	jobs    map[string]*jobState
	timeout time.Duration // per-run timeout; default 30s
	logger  *slog.Logger
	stopped bool
}

// NewScheduler returns an idle scheduler. Register jobs via Register;
// Start launches every registered job's loop.
func NewScheduler(perJobTimeout time.Duration, logger *slog.Logger) *Scheduler {
	if perJobTimeout <= 0 {
		perJobTimeout = 30 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Scheduler{
		jobs:    make(map[string]*jobState),
		timeout: perJobTimeout,
		logger:  logger,
	}
}

// Register adds a job. Must be called before Start. Duplicate names panic
// — they're a programmer error, not a runtime condition.
func (s *Scheduler) Register(j Job) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.jobs[j.Name()]; exists {
		panic(fmt.Sprintf("background: duplicate job %q", j.Name()))
	}
	s.jobs[j.Name()] = &jobState{
		job:       j,
		stopCh:    make(chan struct{}),
		triggerCh: make(chan struct{}, 1),
	}
}

// Start launches every registered job's loop. Each loop runs until ctx
// cancels or Stop() is called.
func (s *Scheduler) Start(ctx context.Context) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, st := range s.jobs {
		go s.runLoop(ctx, st)
	}
}

// Stop terminates every job's loop. Blocks until each loop's goroutine
// exits or the deadline elapses. Safe to call multiple times.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	s.stopped = true
	for _, st := range s.jobs {
		close(st.stopCh)
	}
}

// Trigger requests an immediate run of the named job. Returns
// ErrJobNotFound if the job isn't registered.
func (s *Scheduler) Trigger(name string) error {
	s.mu.RLock()
	st, ok := s.jobs[name]
	s.mu.RUnlock()
	if !ok {
		return ErrJobNotFound
	}
	select {
	case st.triggerCh <- struct{}{}:
	default:
		// A trigger is already pending. Idempotent: collapse into the
		// existing one. Operators clicking twice don't queue duplicate
		// runs.
	}
	return nil
}

// Pause stops the named job's auto-runs. Triggers still work.
func (s *Scheduler) Pause(name string) error {
	return s.setPaused(name, true)
}

// Resume re-enables auto-runs.
func (s *Scheduler) Resume(name string) error {
	return s.setPaused(name, false)
}

func (s *Scheduler) setPaused(name string, v bool) error {
	s.mu.RLock()
	st, ok := s.jobs[name]
	s.mu.RUnlock()
	if !ok {
		return ErrJobNotFound
	}
	st.mu.Lock()
	st.paused = v
	st.mu.Unlock()
	return nil
}

// StatusFor returns the runtime snapshot for one job.
func (s *Scheduler) StatusFor(name string) (Status, error) {
	s.mu.RLock()
	st, ok := s.jobs[name]
	s.mu.RUnlock()
	if !ok {
		return Status{}, ErrJobNotFound
	}
	return st.snapshot(), nil
}

// All returns snapshots for every registered job. Ordering is not
// guaranteed; callers sort if they care.
func (s *Scheduler) All() []Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Status, 0, len(s.jobs))
	for _, st := range s.jobs {
		out = append(out, st.snapshot())
	}
	return out
}

func (st *jobState) snapshot() Status {
	st.mu.Lock()
	defer st.mu.Unlock()
	return Status{
		Name:             st.job.Name(),
		Interval:         st.job.Interval(),
		Paused:           st.paused,
		CurrentlyRunning: st.running,
		LastRunAt:        st.lastAt,
		LastDuration:     st.lastDur,
		LastError:        st.lastErr,
		RunCount:         st.runs,
		ErrorCount:       st.errors,
	}
}

func (s *Scheduler) runLoop(parentCtx context.Context, st *jobState) {
	interval := st.job.Interval()
	var tick <-chan time.Time
	if interval > 0 {
		t := time.NewTicker(interval)
		defer t.Stop()
		tick = t.C
	}

	for {
		select {
		case <-parentCtx.Done():
			return
		case <-st.stopCh:
			return
		case <-tick:
			st.mu.Lock()
			paused := st.paused
			st.mu.Unlock()
			if paused {
				continue
			}
			s.runOnce(parentCtx, st, "scheduled")
		case <-st.triggerCh:
			s.runOnce(parentCtx, st, "manual")
		}
	}
}

func (s *Scheduler) runOnce(parentCtx context.Context, st *jobState, source string) {
	st.mu.Lock()
	if st.running {
		// Re-entry guard: a slow job shouldn't pile up runs. Treat the
		// trigger as if it had been collapsed.
		st.mu.Unlock()
		return
	}
	st.running = true
	st.mu.Unlock()

	ctx, cancel := context.WithTimeout(parentCtx, s.timeout)
	defer cancel()

	start := time.Now()
	err := st.job.Run(ctx)
	dur := time.Since(start)

	st.mu.Lock()
	st.running = false
	st.runs++
	now := time.Now()
	st.lastAt = &now
	st.lastDur = dur
	if err != nil {
		st.errors++
		st.lastErr = err.Error()
	} else {
		st.lastErr = ""
	}
	st.mu.Unlock()

	if err != nil {
		s.logger.Warn("job run failed",
			"job", st.job.Name(),
			"source", source,
			"dur_ms", dur.Milliseconds(),
			"err", err,
		)
	} else {
		s.logger.Info("job run ok",
			"job", st.job.Name(),
			"source", source,
			"dur_ms", dur.Milliseconds(),
		)
	}
}

// ErrJobNotFound is returned by Trigger/Pause/Resume/StatusFor when the
// named job isn't registered. Callers should surface this as a 404.
var ErrJobNotFound = errBoundary("job not found")

type errBoundary string

func (e errBoundary) Error() string { return string(e) }
