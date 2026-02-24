package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
)

// KVGetHandler handles GET /v1/secret/data/*path
func (s *Server) KVGetHandler(w http.ResponseWriter, r *http.Request) {
	token := tokenFromCtx(r.Context())
	if token == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	path := chi.URLParam(r, "*")
	version := 0
	if v := r.URL.Query().Get("version"); v != "" {
		var err error
		version, err = strconv.Atoi(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid version")
			return
		}
	}

	data, meta, err := s.kv.Get(r.Context(), token, path, version)
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{
			"data":     data,
			"metadata": meta,
		},
	})
}

// KVPutHandler handles POST /v1/secret/data/*path
func (s *Server) KVPutHandler(w http.ResponseWriter, r *http.Request) {
	token := tokenFromCtx(r.Context())
	if token == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	path := chi.URLParam(r, "*")

	var req struct {
		Data map[string]any `json:"data"`
		Type string         `json:"type"` // optional; defaults to "kv"
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Type == "" {
		req.Type = "kv"
	}

	version, err := s.kv.Put(r.Context(), token, path, req.Type, req.Data)
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{
			"version":    version.Version,
			"created_at": version.CreatedAt,
		},
	})
}

// KVDeleteHandler handles DELETE /v1/secret/data/*path
func (s *Server) KVDeleteHandler(w http.ResponseWriter, r *http.Request) {
	token := tokenFromCtx(r.Context())
	if token == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	path := chi.URLParam(r, "*")

	var req struct {
		Versions []int `json:"versions"`
	}
	decodeJSON(r, &req) //nolint:errcheck

	if len(req.Versions) == 0 {
		// Delete latest version
		meta, err := s.store.GetSecretMetadata(r.Context(), path)
		if err == nil && meta.CurrentVersion > 0 {
			req.Versions = []int{meta.CurrentVersion}
		}
	}

	if err := s.kv.Delete(r.Context(), token, path, req.Versions); err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// KVListHandler handles LIST /v1/secret/metadata/*path
func (s *Server) KVListHandler(w http.ResponseWriter, r *http.Request) {
	token := tokenFromCtx(r.Context())
	if token == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	prefix := chi.URLParam(r, "*")
	keys, err := s.kv.List(r.Context(), token, prefix)
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{"keys": keys},
	})
}

// KVMetadataHandler handles GET /v1/secret/metadata/*path
func (s *Server) KVMetadataHandler(w http.ResponseWriter, r *http.Request) {
	token := tokenFromCtx(r.Context())
	if token == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	path := chi.URLParam(r, "*")
	meta, err := s.kv.GetMetadata(r.Context(), token, path)
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"data": meta})
}

// KVDestroyHandler handles DELETE /v1/secret/destroy/*path
func (s *Server) KVDestroyHandler(w http.ResponseWriter, r *http.Request) {
	token := tokenFromCtx(r.Context())
	if token == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	path := chi.URLParam(r, "*")

	var req struct {
		Versions []int `json:"versions"`
	}
	if err := decodeJSON(r, &req); err != nil || len(req.Versions) == 0 {
		writeError(w, http.StatusBadRequest, "versions required")
		return
	}

	if err := s.kv.Destroy(r.Context(), token, path, req.Versions); err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
