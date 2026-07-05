package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestNewJSONHandlerInProduction(t *testing.T) {
	var buf bytes.Buffer
	logger := New("production", "info", &buf)
	logger.Info("hello", "k", "v")
	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("expected JSON in production: %v\n%s", err, buf.String())
	}
	if record["msg"] != "hello" || record["k"] != "v" {
		t.Fatalf("unexpected payload: %v", record)
	}
}

func TestNewTextHandlerInDev(t *testing.T) {
	var buf bytes.Buffer
	logger := New("development", "debug", &buf)
	logger.Debug("dev-msg")
	// Text handler emits key=value pairs, not JSON.
	if !strings.Contains(buf.String(), "msg=dev-msg") {
		t.Fatalf("expected text key=value, got: %s", buf.String())
	}
}

func TestFromContextStampsRequestIDAndUserID(t *testing.T) {
	var buf bytes.Buffer
	logger := New("production", "info", &buf)
	SetDefault(logger)

	ctx := context.Background()
	ctx = WithRequestID(ctx, "req-123")
	ctx = WithUserID(ctx, "user-abc")

	FromContext(ctx).Info("ping")
	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("decode: %v\n%s", err, buf.String())
	}
	if record["request_id"] != "req-123" {
		t.Fatalf("expected request_id=req-123, got %v", record["request_id"])
	}
	if record["user_id"] != "user-abc" {
		t.Fatalf("expected user_id=user-abc, got %v", record["user_id"])
	}
}

func TestFromContextDefaultsWithoutFields(t *testing.T) {
	var buf bytes.Buffer
	logger := New("production", "info", &buf)
	SetDefault(logger)

	FromContext(context.Background()).Info("bare")
	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Should NOT have request_id / user_id keys when context is empty.
	if _, present := record["request_id"]; present {
		t.Fatal("expected no request_id when none in context")
	}
}

// AUDIT 1.25-relevant: the level-parser must be tolerant of casing.
func TestParseLevelTolerantOfCase(t *testing.T) {
	for _, in := range []string{"DEBUG", "Debug", "debug", " debug "} {
		if got := parseLevel(in); got.String() != "DEBUG" {
			t.Fatalf("parseLevel(%q)=%v want DEBUG", in, got)
		}
	}
	// Unknown falls back to INFO.
	if got := parseLevel("nonsense"); got.String() != "INFO" {
		t.Fatalf("parseLevel(nonsense)=%v want INFO", got)
	}
}
