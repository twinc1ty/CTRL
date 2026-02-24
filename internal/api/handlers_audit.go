package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/org/secretvault/internal/storage"
)

// AuditLogHandler handles GET /v1/sys/audit-log
func (s *Server) AuditLogHandler(w http.ResponseWriter, r *http.Request) {
	token := tokenFromCtx(r.Context())
	if token == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Requires sudo capability
	if !s.policy.IsAllowed(r.Context(), token.Policies, "sudo", "sys/audit-log") {
		writeError(w, http.StatusForbidden, "permission denied")
		return
	}

	q := r.URL.Query()
	filter := storage.AuditFilter{
		Path:  q.Get("path"),
		Limit: 100,
	}

	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			filter.Limit = n
		}
	}
	if o := q.Get("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil {
			filter.Offset = n
		}
	}
	if since := q.Get("since"); since != "" {
		t, err := time.Parse(time.RFC3339, since)
		if err == nil {
			filter.Since = &t
		}
	}

	entries, err := s.auditor.Query(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"data": entries})
}
