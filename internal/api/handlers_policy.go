package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/org/secretvault/pkg/models"
)

// PolicyWriteHandler handles POST /v1/sys/policy/:name
func (s *Server) PolicyWriteHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	var req struct {
		Rules map[string]models.PathRule `json:"path"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	policy := &models.Policy{
		Name:  name,
		Rules: req.Rules,
	}
	if err := s.store.WritePolicy(r.Context(), policy); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// PolicyReadHandler handles GET /v1/sys/policy/:name
func (s *Server) PolicyReadHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	pol, err := s.store.GetPolicy(r.Context(), name)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "policy not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": pol.Name, "rules": pol.Rules})
}

// PolicyDeleteHandler handles DELETE /v1/sys/policy/:name
func (s *Server) PolicyDeleteHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := s.store.DeletePolicy(r.Context(), name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// PolicyListHandler handles GET /v1/sys/policy
func (s *Server) PolicyListHandler(w http.ResponseWriter, r *http.Request) {
	names, err := s.store.ListPolicies(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": names})
}
