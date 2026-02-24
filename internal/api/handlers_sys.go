package api

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/org/secretvault/internal/crypto"
	"github.com/org/secretvault/pkg/models"
)

// InitHandler handles POST /v1/sys/init
func (s *Server) InitHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check if already initialized
	initialized, err := s.store.IsInitialized(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if initialized {
		writeError(w, http.StatusBadRequest, "vault is already initialized")
		return
	}

	var req struct {
		SecretShares    int `json:"secret_shares"`
		SecretThreshold int `json:"secret_threshold"`
	}
	req.SecretShares = 5
	req.SecretThreshold = 3
	if err := decodeJSON(r, &req); err == nil {
		// use provided values if decoding succeeds
	}

	if req.SecretThreshold > req.SecretShares {
		writeError(w, http.StatusBadRequest, "threshold cannot exceed shares")
		return
	}

	// Generate root key
	rootKey, err := crypto.GenerateRootKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate root key")
		return
	}

	// Split root key via Shamir's SS
	shards, err := crypto.SplitRootKey(rootKey, req.SecretShares, req.SecretThreshold)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to split root key")
		return
	}

	// Persist init data (shards stored as-is — in production these would be further encrypted)
	initData := &models.InitData{
		EncryptedRootKeyShares: shards,
		KEKContext:             "vault-kek-v1",
		InitializedAt:          time.Now().UTC(),
	}
	if err := s.store.InitVault(ctx, initData); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to persist init data")
		return
	}

	// Auto-unseal using the root key (operator would normally unseal manually with shards)
	if err := s.seal.UnsealWithRootKey(rootKey); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to unseal after init")
		return
	}

	// Zero root key from stack
	for i := range rootKey {
		rootKey[i] = 0
	}

	// Return shards (base64-encoded) to operator — show once
	shardsB64 := make([]string, len(shards))
	for i, s := range shards {
		shardsB64[i] = base64.StdEncoding.EncodeToString(s)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"keys":              shardsB64,
		"keys_base64":       shardsB64,
		"root_token":        s.rootToken,
		"initialized":       true,
	})
}

// SealStatusHandler handles GET /v1/sys/seal-status
func (s *Server) SealStatusHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"sealed":    s.seal.IsSealed(),
		"threshold": s.seal.Threshold(),
		"progress":  s.seal.ShardsProvided(),
	})
}

// UnsealHandler handles POST /v1/sys/unseal
func (s *Server) UnsealHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key   string `json:"key"`
		Reset bool   `json:"reset"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Reset {
		s.seal.Seal()
		writeJSON(w, http.StatusOK, map[string]any{"sealed": true, "progress": 0})
		return
	}

	shardBytes, err := base64.StdEncoding.DecodeString(req.Key)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid key encoding (must be base64)")
		return
	}

	unsealed, err := s.seal.Unseal(shardBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"sealed":    !unsealed,
		"progress":  s.seal.ShardsProvided(),
		"threshold": s.seal.Threshold(),
	})
}

// SealHandler handles PUT /v1/sys/seal
func (s *Server) SealHandler(w http.ResponseWriter, r *http.Request) {
	s.seal.Seal()
	writeJSON(w, http.StatusOK, map[string]any{"sealed": true})
}

// HealthHandler handles GET /v1/sys/health
func (s *Server) HealthHandler(w http.ResponseWriter, r *http.Request) {
	code := http.StatusOK
	if s.seal.IsSealed() {
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{
		"initialized": true,
		"sealed":      s.seal.IsSealed(),
		"version":     "1.0.0",
	})
}
