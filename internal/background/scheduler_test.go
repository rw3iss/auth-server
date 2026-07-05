package background

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type fakeJob struct {
	name     string
	every    time.Duration
	calls    atomic.Uint64
	fail     atomic.Bool
	failOnce atomic.Bool
}

func (f *fakeJob) Name() string             { return f.name }
func (f *fakeJob) Interval() time.Duration  { return f.every }
func (f *fakeJob) Run(_ context.Context) error {
	f.calls.Add(1)
	if f.failOnce.CompareAndSwap(true, false) {
		return errors.New("boom-once")
	}
	if f.fail.Load() {
		return errors.New("boom")
	}
	return nil
}

// Triggers run synchronously through the loop's manual channel; verify they
// arrive at the job and bump the status counters.
func TestSchedulerManualTrigger(t *testing.T) {
	s := NewScheduler(time.Second, nil)
	j := &fakeJob{name: "x", every: 0} // interval=0 → no auto-runs
	s.Register(j)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	defer s.Stop()

	if err := s.Trigger("x"); err != nil {
		t.Fatalf("trigger: %v", err)
	}

	// Wait up to 500ms for the run to land.
	for deadline := time.Now().Add(500 * time.Millisecond); time.Now().Before(deadline); {
		if j.calls.Load() >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if j.calls.Load() != 1 {
		t.Fatalf("expected 1 run after trigger, got %d", j.calls.Load())
	}

	st, _ := s.StatusFor("x")
	if st.RunCount != 1 {
		t.Fatalf("expected RunCount=1, got %d", st.RunCount)
	}
	if st.LastError != "" {
		t.Fatalf("expected no LastError, got %q", st.LastError)
	}
}

// A paused job ignores ticks but still honors manual triggers.
func TestSchedulerPauseAllowsTrigger(t *testing.T) {
	s := NewScheduler(time.Second, nil)
	j := &fakeJob{name: "y", every: 0}
	s.Register(j)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	defer s.Stop()

	if err := s.Pause("y"); err != nil {
		t.Fatalf("pause: %v", err)
	}
	if err := s.Trigger("y"); err != nil {
		t.Fatalf("trigger: %v", err)
	}
	for deadline := time.Now().Add(500 * time.Millisecond); time.Now().Before(deadline); {
		if j.calls.Load() >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if j.calls.Load() != 1 {
		t.Fatalf("trigger should run even when paused; got %d", j.calls.Load())
	}
}

// LastError is populated when a run fails, then cleared by the next success.
func TestSchedulerLastError(t *testing.T) {
	s := NewScheduler(time.Second, nil)
	j := &fakeJob{name: "z", every: 0}
	j.failOnce.Store(true)
	s.Register(j)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	defer s.Stop()

	_ = s.Trigger("z") // first run, fails
	waitForRuns(t, j, 1)
	st, _ := s.StatusFor("z")
	if st.LastError != "boom-once" {
		t.Fatalf("expected LastError=boom-once, got %q", st.LastError)
	}
	if st.ErrorCount != 1 {
		t.Fatalf("expected ErrorCount=1, got %d", st.ErrorCount)
	}

	_ = s.Trigger("z") // second run, succeeds
	waitForRuns(t, j, 2)
	st, _ = s.StatusFor("z")
	if st.LastError != "" {
		t.Fatalf("LastError should clear on success, got %q", st.LastError)
	}
}

// Unknown jobs surface a typed error.
func TestSchedulerJobNotFound(t *testing.T) {
	s := NewScheduler(time.Second, nil)
	if err := s.Trigger("nope"); !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("expected ErrJobNotFound, got %v", err)
	}
}

func waitForRuns(t *testing.T, j *fakeJob, n uint64) {
	t.Helper()
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		if j.calls.Load() >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("waited for %d runs, got %d", n, j.calls.Load())
}
