package handlers

import (
	"net/http"

	"github.com/ven/auth/internal/background"
	"github.com/ven/auth/pkg/shared/errors"
)

// JobHandler exposes the background.Scheduler as a system_admin admin API.
// The admin dashboard (not yet built) will render these endpoints; humans
// also call them with curl during incidents to trigger or pause jobs.
//
// All routes are mounted under /admin/jobs and gated to system_admin.
type JobHandler struct {
	scheduler *background.Scheduler
}

// NewJobHandler returns a handler for the given scheduler. Passing nil
// is allowed (the routes will 404 because nothing is registered) but
// main.go should always pass a real instance.
func NewJobHandler(s *background.Scheduler) *JobHandler {
	return &JobHandler{scheduler: s}
}

// List returns the runtime status of every registered job.
//
//	GET /admin/jobs
//
// Response: { jobs: [...statuses] }
func (h *JobHandler) List(w http.ResponseWriter, r *http.Request) {
	if !h.requireSysAdmin(w, r) {
		return
	}
	if h.scheduler == nil {
		writeJSON(w, http.StatusOK, map[string]any{"jobs": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": h.scheduler.All()})
}

// Get returns the status for one job.
//
//	GET /admin/jobs/{name}
func (h *JobHandler) Get(w http.ResponseWriter, r *http.Request) {
	if !h.requireSysAdmin(w, r) {
		return
	}
	name := r.PathValue("name")
	st, err := h.scheduler.StatusFor(name)
	if err != nil {
		writeError(w, errors.NotFound("job"))
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// Trigger requests an immediate run.
//
//	POST /admin/jobs/{name}/trigger
func (h *JobHandler) Trigger(w http.ResponseWriter, r *http.Request) {
	if !h.requireSysAdmin(w, r) {
		return
	}
	name := r.PathValue("name")
	if err := h.scheduler.Trigger(name); err != nil {
		writeError(w, errors.NotFound("job"))
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"triggered": name})
}

// Pause stops the named job's auto-runs. Triggers still work.
//
//	POST /admin/jobs/{name}/pause
func (h *JobHandler) Pause(w http.ResponseWriter, r *http.Request) {
	if !h.requireSysAdmin(w, r) {
		return
	}
	name := r.PathValue("name")
	if err := h.scheduler.Pause(name); err != nil {
		writeError(w, errors.NotFound("job"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"paused": name})
}

// Resume restores auto-runs.
//
//	POST /admin/jobs/{name}/resume
func (h *JobHandler) Resume(w http.ResponseWriter, r *http.Request) {
	if !h.requireSysAdmin(w, r) {
		return
	}
	name := r.PathValue("name")
	if err := h.scheduler.Resume(name); err != nil {
		writeError(w, errors.NotFound("job"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"resumed": name})
}

func (h *JobHandler) requireSysAdmin(w http.ResponseWriter, r *http.Request) bool {
	// Reuse the package-level requireSystemAdmin helper (user_handler.go)
	// so the gate stays uniform across admin handlers. Phase-B item B4
	// later collapses these into a single route-level middleware.
	return requireSystemAdmin(w, r)
}

// Suppress unused-import lint when errors goes unused after a refactor.
var _ = errors.NotFound
