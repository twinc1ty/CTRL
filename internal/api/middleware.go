package api

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/org/secretvault/internal/auth"
	"github.com/org/secretvault/pkg/models"
	"github.com/rs/zerolog/log"
)

// requestIDMiddleware attaches a UUID request ID to each request.
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := newRequestID()
		w.Header().Set("X-Request-ID", id)
		ctx := withRequestID(r.Context(), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func newRequestID() string {
	return newUUID()
}

// authMiddleware validates the X-Vault-Token header and attaches the token to context.
// Routes registered before auth (sys/health, sys/init, sys/unseal) skip this.
func authMiddleware(tokens *auth.TokenService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			plaintext := r.Header.Get("X-Vault-Token")
			if plaintext == "" {
				writeError(w, http.StatusUnauthorized, "missing X-Vault-Token header")
				return
			}
			token, err := tokens.ValidateToken(r.Context(), plaintext)
			if err != nil {
				writeError(w, http.StatusForbidden, err.Error())
				return
			}
			ctx := withToken(r.Context(), token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// auditMiddleware records every request + response code to the audit log.
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rr *responseRecorder) WriteHeader(code int) {
	rr.statusCode = code
	rr.ResponseWriter.WriteHeader(code)
}

func auditMiddleware(auditor AuditLogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rr := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(rr, r)

			token := tokenFromCtx(r.Context())
			tokenHash := ""
			if token != nil {
				tokenHash = auth.HashToken(r.Header.Get("X-Vault-Token"))
			}

			entry := &models.AuditEntry{
				RequestID:      requestIDFromCtx(r.Context()),
				TokenHash:      tokenHash,
				Operation:      r.Method,
				Path:           r.URL.Path,
				Status:         http.StatusText(rr.statusCode),
				ResponseCode:   rr.statusCode,
				ResponseTimeMs: time.Since(start).Milliseconds(),
				ClientIP:       r.RemoteAddr,
			}
			auditor.LogRequest(r.Context(), entry)
		})
	}
}

// rateLimiter is a simple per-IP token bucket rate limiter.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    int // requests per second
	burst   int
}

type bucket struct {
	tokens    float64
	lastCheck time.Time
}

func newRateLimiter(rps, burst int) *rateLimiter {
	return &rateLimiter{
		buckets: make(map[string]*bucket),
		rate:    rps,
		burst:   burst,
	}
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b, ok := rl.buckets[ip]
	if !ok {
		b = &bucket{tokens: float64(rl.burst), lastCheck: time.Now()}
		rl.buckets[ip] = b
	}
	now := time.Now()
	elapsed := now.Sub(b.lastCheck).Seconds()
	b.tokens += elapsed * float64(rl.rate)
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.lastCheck = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (rl *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !rl.allow(ip) {
			log.Warn().Str("ip", ip).Msg("rate limit exceeded")
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	return r.RemoteAddr
}

// helpers

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"errors":[%q]}`, msg)
}

func newUUID() string {
	return newUUIDImpl()
}
