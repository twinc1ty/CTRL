package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/org/secretvault/internal/auth"
)

// TokenCreateHandler handles POST /v1/auth/token/create
func (s *Server) TokenCreateHandler(w http.ResponseWriter, r *http.Request) {
	token := tokenFromCtx(r.Context())
	if token == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		DisplayName string   `json:"display_name"`
		Policies    []string `json:"policies"`
		TTL         string   `json:"ttl"`
		Renewable   bool     `json:"renewable"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var ttl time.Duration
	if req.TTL != "" {
		var err error
		ttl, err = time.ParseDuration(req.TTL)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid ttl format")
			return
		}
	}

	if len(req.Policies) == 0 {
		req.Policies = []string{"default"}
	}

	newToken, plaintext, err := s.tokens.CreateToken(r.Context(), req.DisplayName, req.Policies, ttl, req.Renewable, &token.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"auth": map[string]any{
			"client_token": plaintext,
			"policies":     newToken.Policies,
			"lease_duration": int(newToken.TTL.Seconds()),
			"renewable":    newToken.Renewable,
		},
	})
}

// TokenRevokeHandler handles POST /v1/auth/token/revoke
func (s *Server) TokenRevokeHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate the token to get its ID
	tok, err := s.tokens.ValidateToken(r.Context(), req.Token)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.tokens.RevokeToken(r.Context(), tok.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// TokenLookupSelfHandler handles GET /v1/auth/token/lookup-self
func (s *Server) TokenLookupSelfHandler(w http.ResponseWriter, r *http.Request) {
	token := tokenFromCtx(r.Context())
	if token == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{
			"id":              token.ID,
			"display_name":    token.DisplayName,
			"policies":        token.Policies,
			"ttl":             int(token.TTL.Seconds()),
			"renewable":       token.Renewable,
			"creation_time":   token.CreatedAt.Unix(),
			"expire_time":     token.ExpiresAt.Unix(),
		},
	})
}

// TokenRenewHandler handles POST /v1/auth/token/renew-self
func (s *Server) TokenRenewHandler(w http.ResponseWriter, r *http.Request) {
	token := tokenFromCtx(r.Context())
	if token == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if !token.Renewable {
		writeError(w, http.StatusBadRequest, "token is not renewable")
		return
	}

	var req struct {
		Increment string `json:"increment"`
	}
	decodeJSON(r, &req) //nolint:errcheck

	ttl := token.TTL
	if req.Increment != "" {
		var err error
		ttl, err = time.ParseDuration(req.Increment)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid increment")
			return
		}
	}

	if err := s.tokens.RenewToken(r.Context(), token.ID, ttl); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"auth": map[string]any{
			"lease_duration": int(ttl.Seconds()),
			"renewable":      true,
		},
	})
}

// AppRoleCreateHandler handles POST /v1/auth/approle/role
func (s *Server) AppRoleCreateHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string   `json:"name"`
		Policies    []string `json:"token_policies"`
		SecretIDTTL string   `json:"secret_id_ttl"`
		TokenTTL    string   `json:"token_ttl"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var sidTTL, tokTTL time.Duration
	if req.SecretIDTTL != "" {
		sidTTL, _ = time.ParseDuration(req.SecretIDTTL)
	}
	if req.TokenTTL != "" {
		tokTTL, _ = time.ParseDuration(req.TokenTTL)
	}
	if tokTTL == 0 {
		tokTTL = time.Hour
	}

	role, err := s.approle.CreateRole(r.Context(), req.Name, req.Policies, sidTTL, tokTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"role_id": role.ID, "name": role.Name})
}

// AppRoleGetRoleIDHandler handles GET /v1/auth/approle/role/:name/role-id
func (s *Server) AppRoleGetRoleIDHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	role, err := s.approle.GetRole(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, "role not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"role_id": role.ID}})
}

// AppRoleGenSecretIDHandler handles POST /v1/auth/approle/role/:name/secret-id
func (s *Server) AppRoleGenSecretIDHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	secretID, err := s.approle.GenerateSecretID(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"secret_id": secretID}})
}

// AppRoleLoginHandler handles POST /v1/auth/approle/login
func (s *Server) AppRoleLoginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RoleID   string `json:"role_id"`
		SecretID string `json:"secret_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	token, plaintext, err := s.approle.Login(r.Context(), req.RoleID, req.SecretID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"auth": map[string]any{
			"client_token":   plaintext,
			"policies":       token.Policies,
			"lease_duration": int(token.TTL.Seconds()),
			"renewable":      token.Renewable,
		},
	})
}

// ensure auth import is used
var _ = auth.HashToken
