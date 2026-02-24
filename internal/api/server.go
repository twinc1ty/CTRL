package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/org/secretvault/internal/audit"
	"github.com/org/secretvault/internal/auth"
	"github.com/org/secretvault/internal/core"
	"github.com/org/secretvault/internal/policy"
	"github.com/org/secretvault/internal/secret"
	"github.com/org/secretvault/internal/storage"
	"github.com/org/secretvault/pkg/models"
	"github.com/rs/zerolog/log"
)

// Config holds server configuration.
type Config struct {
	ListenAddr       string
	TLSCertFile      string
	TLSKeyFile       string
	DBUrl            string
	UnsealThreshold  int
	MigrationsDir    string
}

// AuditLogger is the interface the server needs from an audit logger.
type AuditLogger interface {
	LogRequest(ctx context.Context, entry *models.AuditEntry)
	Query(ctx context.Context, filter storage.AuditFilter) ([]*models.AuditEntry, error)
}

// Server is the API server.
type Server struct {
	store     storage.StorageBackend
	seal      *core.SealManager
	tokens    *auth.TokenService
	approle   *auth.AppRoleService
	policy    *policy.Engine
	kv        *secret.KVEngine
	auditor   AuditLogger
	rootToken string
	cfg       Config
	httpSrv   *http.Server
}

// NewServer creates a fully wired Server.
func NewServer(store storage.StorageBackend, cfg Config) *Server {
	sealMgr := core.NewSealManager(cfg.UnsealThreshold)
	tokenSvc := auth.NewTokenService(store)
	approleAuth := auth.NewAppRoleService(store, tokenSvc)
	policyEng := policy.NewEngine(store)
	kvEng := secret.NewKVEngine(store, sealMgr, policyEng)
	auditor := audit.NewLogger(store) // implements AuditLogger

	return &Server{
		store:   store,
		seal:    sealMgr,
		tokens:  tokenSvc,
		approle: approleAuth,
		policy:  policyEng,
		kv:      kvEng,
		auditor: auditor,
		cfg:     cfg,
	}
}

// SetRootToken sets the root token (generated at init time).
func (s *Server) SetRootToken(token string) {
	s.rootToken = token
}

// SealManager exposes the seal manager (for init flow).
func (s *Server) SealManager() *core.SealManager {
	return s.seal
}

// BuildRouter wires up all routes and returns a chi router.
func (s *Server) BuildRouter() http.Handler {
	r := chi.NewRouter()

	// Global middleware
	r.Use(chimiddleware.Recoverer)
	r.Use(requestIDMiddleware)
	r.Use(metricsMiddleware)
	r.Use(newRateLimiter(100, 200).middleware)
	r.Use(auditMiddleware(s.auditor))

	// Prometheus metrics (unauthenticated)
	r.Handle("/metrics", MetricsHandler())

	// Public routes (no auth required)
	r.Group(func(r chi.Router) {
		r.Get("/v1/sys/health", s.HealthHandler)
		r.Get("/v1/sys/seal-status", s.SealStatusHandler)
		r.Post("/v1/sys/init", s.InitHandler)
		r.Post("/v1/sys/unseal", s.UnsealHandler)
		r.Post("/v1/auth/approle/login", s.AppRoleLoginHandler)
	})

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(authMiddleware(s.tokens))

		// Sys
		r.Put("/v1/sys/seal", s.SealHandler)
		r.Get("/v1/sys/audit-log", s.AuditLogHandler)

		// Policy
		r.Post("/v1/sys/policy/{name}", s.PolicyWriteHandler)
		r.Get("/v1/sys/policy/{name}", s.PolicyReadHandler)
		r.Delete("/v1/sys/policy/{name}", s.PolicyDeleteHandler)
		r.Get("/v1/sys/policy", s.PolicyListHandler)

		// Token auth
		r.Post("/v1/auth/token/create", s.TokenCreateHandler)
		r.Post("/v1/auth/token/revoke", s.TokenRevokeHandler)
		r.Get("/v1/auth/token/lookup-self", s.TokenLookupSelfHandler)
		r.Post("/v1/auth/token/renew-self", s.TokenRenewHandler)

		// AppRole management (requires auth)
		r.Post("/v1/auth/approle/role", s.AppRoleCreateHandler)
		r.Get("/v1/auth/approle/role/{name}/role-id", s.AppRoleGetRoleIDHandler)
		r.Post("/v1/auth/approle/role/{name}/secret-id", s.AppRoleGenSecretIDHandler)

		// KV secrets
		r.Get("/v1/secret/data/*", s.KVGetHandler)
		r.Post("/v1/secret/data/*", s.KVPutHandler)
		r.Delete("/v1/secret/data/*", s.KVDeleteHandler)
		// GET /v1/secret/metadata/*?list=true → list; without → metadata
		r.Get("/v1/secret/metadata/*", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("list") == "true" {
				s.KVListHandler(w, r)
			} else {
				s.KVMetadataHandler(w, r)
			}
		})
		r.Delete("/v1/secret/destroy/*", s.KVDestroyHandler)
	})

	return r
}

// Start begins listening on the configured address.
func (s *Server) Start() error {
	handler := s.BuildRouter()

	s.httpSrv = &http.Server{
		Addr:         s.cfg.ListenAddr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if s.cfg.TLSCertFile != "" && s.cfg.TLSKeyFile != "" {
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
		}
		s.httpSrv.TLSConfig = tlsCfg
		log.Info().Str("addr", s.cfg.ListenAddr).Msg("starting HTTPS server")
		return s.httpSrv.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
	}

	log.Info().Str("addr", s.cfg.ListenAddr).Msg("starting HTTP server")
	return s.httpSrv.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpSrv == nil {
		return nil
	}
	return s.httpSrv.Shutdown(ctx)
}

// InitializeRootToken creates the root token during first initialization.
// Should only be called once at vault init.
func (s *Server) InitializeRootToken(ctx context.Context) (string, error) {
	tok, plaintext, err := s.tokens.CreateToken(ctx, "root", []string{"root"}, 0, false, nil)
	if err != nil {
		return "", fmt.Errorf("creating root token: %w", err)
	}
	_ = tok
	s.rootToken = plaintext
	return plaintext, nil
}
