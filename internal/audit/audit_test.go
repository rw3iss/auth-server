package audit

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// captureSink records every event written and tracks calls, for assertions.
type captureSink struct {
	mu     sync.Mutex
	events []*Event
	delay  time.Duration // optional artificial delay to test overflow
	fail   atomic.Bool
}

func (c *captureSink) Write(ctx context.Context, e *Event) error {
	if c.delay > 0 {
		select {
		case <-time.After(c.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
	return nil
}

func (c *captureSink) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

func TestRecordWhenDisabledIsNoop(t *testing.T) {
	sink := &captureSink{}
	w := New(Config{Enabled: false, BufferSize: 4}, sink)
	defer w.Stop()
	w.Record(context.Background(), Event{Action: "test"})
	time.Sleep(20 * time.Millisecond)
	if got := sink.count(); got != 0 {
		t.Fatalf("expected no events when disabled, got %d", got)
	}
}

func TestRecordWritesEvent(t *testing.T) {
	sink := &captureSink{}
	w := New(Config{Enabled: true, BufferSize: 4}, sink)
	defer w.Stop()

	w.Record(context.Background(), Event{Action: "login.success"})

	// Drainer is async — wait until written.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if sink.count() == 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("event never landed in sink (count=%d)", sink.count())
}

func TestRecordOverflowDropsNotBlocks(t *testing.T) {
	// Tiny buffer + slow sink → overflow path. Producer must not block.
	sink := &captureSink{delay: 100 * time.Millisecond}
	w := New(Config{Enabled: true, BufferSize: 1}, sink)
	defer w.Stop()

	// Fire many events fast.
	for i := 0; i < 50; i++ {
		w.Record(context.Background(), Event{Action: "noise"})
	}
	dropped := w.dropped.Load()
	if dropped == 0 {
		t.Fatal("expected some events to be dropped under overflow")
	}
}

func TestRecordFillsTimestampAndID(t *testing.T) {
	sink := &captureSink{}
	w := New(Config{Enabled: true, BufferSize: 4}, sink)
	defer w.Stop()
	before := time.Now().UTC().Add(-time.Second)

	w.Record(context.Background(), Event{Action: "x"})

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && sink.count() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if sink.count() != 1 {
		t.Fatal("event never landed")
	}
	got := sink.events[0]
	if got.At.Before(before) {
		t.Fatalf("expected At to be auto-filled, got %v", got.At)
	}
	if got.ID.String() == "" || got.ID.String() == "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("expected ID auto-filled, got %v", got.ID)
	}
}

func TestSetEnabledRuntimeToggle(t *testing.T) {
	sink := &captureSink{}
	w := New(Config{Enabled: false, BufferSize: 4}, sink)
	defer w.Stop()

	w.Record(context.Background(), Event{Action: "first"})
	w.SetEnabled(true)
	w.Record(context.Background(), Event{Action: "second"})

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && sink.count() < 1 {
		time.Sleep(5 * time.Millisecond)
	}
	if sink.count() != 1 {
		t.Fatalf("expected exactly 1 event after toggle, got %d", sink.count())
	}
	if sink.events[0].Action != "second" {
		t.Fatalf("expected 'second' written, got %q", sink.events[0].Action)
	}
}
