# SecretVault — Implementation Plan

## Context
In February, 2026 there occurred an incident at my workplace which eventually caused the compromise of all env files, tokens and secrets in general. We had no secrets Manager in place, and most of them were shared over Slack. After that incident the need for a Secrets Manager inspired me to study for such a project and build CTRL. This project implements a Vault-inspired system with envelope encryption, access policies, audit logging, and auth — giving the team a secure, auditable, self-hosted secrets lifecycle manager.

**Stack:** Go · PostgreSQL · AES-256-GCM · REST API + CLI

---

## Architecture Overview

```
CLI Client (vault)
      │
      ▼ HTTPS / REST
  API Server
      │
  ┌───┴────────────────────────────┐
  │  Auth Layer (token / AppRole)  │
  │  Policy Engine (path ACL)      │
  │  Secret Engine (KV v2)         │
  │  Crypto Layer (DEK/KEK/Root)   │
  │  Audit Log                     │
  └───┬────────────────────────────┘
      │
  PostgreSQL
```

### Envelope Encryption (HashiCorp-style)
```
Root Key (32 bytes, split via Shamir's SS)
   └── derives → KEK (HKDF-SHA256)
                    └── encrypts → DEK (per-secret, AES-256-GCM)
                                      └── encrypts → Secret Plaintext
```
Compromising one secret's DEK never compromises the whole keystore.

---

## Directory Structure
```
SecretVault/
├── cmd/
│   ├── server/main.go          # API server entrypoint
│   └── vault/main.go           # CLI client entrypoint
├── internal/
│   ├── crypto/                 # envelope encryption primitives
│   ├── storage/                # storage interface + pg backend
│   ├── auth/                   # token + AppRole auth
│   ├── policy/                 # path-glob ACL policy engine
│   ├── secret/                 # KV v2 engine, secret types
│   ├── api/                    # HTTP handlers + middleware
│   └── audit/                  # structured audit logger
├── pkg/
│   └── models/                 # shared structs (Secret, Token, Policy…)
├── migrations/                 # SQL migration files
├── Docs/                       # Project documentation
└── config.yaml.example
```

---

## Phase 1 — Project Scaffolding & Crypto Foundation

**Goal:** Working Go project with a battle-tested, unit-tested encryption layer.

### Steps
1. **Init Go module**
   - `go mod init github.com/org/secretvault`
   - Add deps: `chi` (HTTP router), `cobra` (CLI), `pgx` (Postgres driver), `golang-migrate`, `zerolog`, `crypto` stdlib
2. **Create directory skeleton** — all packages with stub files
3. **Implement `internal/crypto` package**
   - `GenerateRootKey() []byte` — 32-byte CSPRNG key
   - `SplitRootKey(key, shares, threshold) [][]byte` — Shamir's Secret Sharing (implement or use `hashicorp/vault/helper/shamir`)
   - `CombineShards(shards [][]byte) ([]byte, error)` — reconstruct root key from threshold shards
   - `DeriveKEK(rootKey []byte, context string) []byte` — HKDF-SHA256 derivation
   - `GenerateDEK() []byte` — 32-byte random DEK per secret
   - `EncryptAESGCM(plaintext, key []byte) (ciphertext, nonce []byte, err error)`
   - `DecryptAESGCM(ciphertext, nonce, key []byte) ([]byte, error)`
   - `EncryptDEK(dek, kek []byte) ([]byte, error)` — wraps DEK with KEK
   - `DecryptDEK(encryptedDEK, kek []byte) ([]byte, error)`
4. **Write unit tests** for every crypto function (`crypto_test.go`)
5. **Seal/Unseal state machine** — `internal/core/seal.go`
   - In-memory KEK only after unseal; vault is "sealed" on start
   - `Unseal(shard)` — accumulates shards until threshold met, derives KEK, stores in memory
   - `Seal()` — wipes KEK from memory

**Verification:** `go test ./internal/crypto/...` all green; encrypt→decrypt round-trip test passes.

---

## Phase 2 — Storage Layer

**Goal:** Pluggable storage interface backed by PostgreSQL with versioned secret storage.

### Steps
1. **Define `StorageBackend` interface** (`internal/storage/interface.go`)
   ```go
   type StorageBackend interface {
     InitVault(ctx, initData) error
     GetInitData(ctx) (*InitData, error)
     WriteSecretVersion(ctx, path string, version *SecretVersion) error
     ReadSecretVersion(ctx, path string, version int) (*SecretVersion, error)
     ListSecrets(ctx, prefix string) ([]string, error)
     DeleteSecretVersions(ctx, path string, versions []int) error
     GetSecretMetadata(ctx, path string) (*SecretMetadata, error)
     WriteToken(ctx, *Token) error
     GetToken(ctx, tokenID string) (*Token, error)
     RevokeToken(ctx, tokenID string) error
     WritePolicy(ctx, *Policy) error
     GetPolicy(ctx, name string) (*Policy, error)
     ListPolicies(ctx) ([]string, error)
     WriteAuditEntry(ctx, *AuditEntry) error
   }
   ```
2. **Design PostgreSQL schema** (`migrations/001_init.sql`)
   ```sql
   vault_init        (id, encrypted_root_key_shares jsonb, kek_context text, initialized_at)
   secrets           (id, path text UNIQUE, type text, created_at, updated_at, deleted_at)
   secret_versions   (id, secret_id FK, version int, encrypted_dek bytea, ciphertext bytea,
                      nonce bytea, created_at, deleted_at, destroyed bool)
   tokens            (id, token_hash text, display_name, policies text[], ttl, renewable,
                      created_at, expires_at, revoked_at, parent_id FK)
   approle_roles     (id, name text UNIQUE, policies text[], secret_id_ttl, token_ttl)
   approle_secrets   (id, role_id FK, secret_id_hash text, uses_remaining, expires_at, used_at)
   policies          (id, name text UNIQUE, rules jsonb, created_at, updated_at)
   audit_log         (id BIGSERIAL, request_id uuid, timestamp, token_hash text,
                      operation text, path text, status text, response_code int, metadata jsonb)
   ```
3. **Implement PostgreSQL backend** (`internal/storage/postgres.go`)
   - Connection pool via `pgx/pgxpool`
   - All queries use parameterized statements
4. **Write migration runner** using `golang-migrate`
5. **Seed default policies** (root policy, default policy) in initial migration

**Verification:** Run migrations against a local Postgres instance; assert all tables created; write integration test for round-trip secret write/read.

---

## Phase 3 — Authentication & Authorization

**Goal:** Token-based auth and AppRole auth with a policy ACL engine.

### Steps
1. **Token auth** (`internal/auth/token.go`)
   - `CreateToken(policies, ttl, renewable, parent) (*Token, plaintext)` — generates opaque token, stores SHA-256 hash
   - `ValidateToken(plaintext) (*Token, error)` — hash and lookup
   - `RevokeToken(tokenID)` + cascade revoke child tokens
   - `RenewToken(tokenID)` — extend TTL if renewable
2. **AppRole auth** (`internal/auth/approle.go`)
   - `CreateRole(name, policies, secretIDTTL, tokenTTL)`
   - `GenerateSecretID(roleName) (secretID string)` — one-time or limited-use
   - `Login(roleID, secretID) (*Token, error)` — validates both, issues token with role's policies
3. **Policy engine** (`internal/policy/engine.go`)
   - Policy rules format (JSON):
     ```json
     { "path": { "secret/data/*": { "capabilities": ["read","write","list"] } } }
     ```
   - Capabilities: `read`, `write`, `list`, `delete`, `sudo`
   - `IsAllowed(token, operation, path) bool` — evaluates all attached policies, glob path matching
   - Built-in policies: `root` (all access), `default` (basic token self-management)
4. **Auth middleware** for HTTP server — extracts `X-Vault-Token` header, validates, attaches to request context

**Verification:** Unit test policy engine with wildcard paths; integration test AppRole login flow issuing a scoped token.

---

## Phase 4 — Secret Engines

**Goal:** Versioned KV store with dedicated types for PEM certs and env bundles.

### Steps
1. **KV v2 engine** (`internal/secret/kv.go`)
   - `Put(ctx, token, path string, data map[string]any) (*SecretVersion, error)`
     - Policy check → generate DEK → AES-GCM encrypt JSON(data) → store encrypted DEK + ciphertext
   - `Get(ctx, token, path string, version int) (map[string]any, *SecretMetadata, error)`
     - Policy check → fetch version → decrypt DEK with KEK → decrypt ciphertext
   - `List(ctx, token, prefix string) ([]string, error)`
   - `Delete(ctx, token, path string, versions []int) error` — soft delete (sets deleted_at, preserves ciphertext)
   - `Destroy(ctx, token, path string, versions []int) error` — wipe ciphertext + DEK from storage
   - `Undelete(ctx, token, path string, versions []int) error`
   - `GetMetadata(ctx, token, path string) (*SecretMetadata, error)` — version list, created/updated
2. **PEM secret type** — structured KV with fields: `certificate`, `private_key`, `ca_chain`, `expires_at`
   - Helper to parse expiry from PEM cert automatically
3. **Env bundle type** — structured KV with field `env_vars: map[string]string`
   - Export helper: render as `.env` file format
4. **Rotation helper** (`internal/secret/rotation.go`)
   - `Rotate(ctx, token, path string, newData map[string]any)` — write new version, preserve history

**Verification:** Integration test: put → get (latest), get (version 1), delete version 2, undelete version 2, destroy version 1.

---

## Phase 5 — REST API Server

**Goal:** HTTP API server with all Vault-compatible routes, TLS, and middleware.

### Steps
1. **Server setup** (`internal/api/server.go`) using `chi` router
2. **Middleware stack**
   - `requestID` — attach UUID to every request
   - `authMiddleware` — validate token, attach to ctx
   - `auditMiddleware` — record request + response to audit log
   - `rateLimiter` — per-IP token bucket
3. **Route groups**
   ```
   POST   /v1/sys/init                        → InitHandler
   GET    /v1/sys/seal-status                 → SealStatusHandler
   POST   /v1/sys/unseal                      → UnsealHandler
   PUT    /v1/sys/seal                        → SealHandler
   GET    /v1/sys/health                      → HealthHandler

   POST   /v1/auth/token/create               → TokenCreateHandler
   POST   /v1/auth/token/revoke               → TokenRevokeHandler
   GET    /v1/auth/token/lookup-self          → TokenLookupSelfHandler
   POST   /v1/auth/token/renew-self           → TokenRenewHandler

   POST   /v1/auth/approle/role               → AppRoleCreateHandler
   GET    /v1/auth/approle/role/:name/role-id → AppRoleGetRoleIDHandler
   POST   /v1/auth/approle/role/:name/secret-id → AppRoleGenSecretIDHandler
   POST   /v1/auth/approle/login              → AppRoleLoginHandler

   GET    /v1/secret/data/*path               → KVGetHandler
   POST   /v1/secret/data/*path               → KVPutHandler
   DELETE /v1/secret/data/*path               → KVDeleteHandler
   LIST   /v1/secret/metadata/*path           → KVListHandler
   GET    /v1/secret/metadata/*path           → KVMetadataHandler
   DELETE /v1/secret/destroy/*path            → KVDestroyHandler

   POST   /v1/sys/policy/:name                → PolicyWriteHandler
   GET    /v1/sys/policy/:name                → PolicyReadHandler
   DELETE /v1/sys/policy/:name                → PolicyDeleteHandler
   GET    /v1/sys/policy                      → PolicyListHandler
   ```
4. **TLS config** — load cert/key from config; enforce TLS 1.2+
5. **Server config** (`config.yaml`): `listen_addr`, `tls_cert`, `tls_key`, `db_url`, `unseal_threshold`

**Verification:** `go test ./internal/api/...` with httptest; end-to-end: init → unseal → write secret → read secret via curl.

---

## Phase 6 — CLI Client

**Goal:** Developer-friendly CLI that mirrors HashiCorp Vault's UX.

### Steps
1. **Cobra CLI root** (`cmd/vault/main.go`)
2. **Commands**
   ```
   vault operator init [--shares 5] [--threshold 3]
   vault operator unseal
   vault operator seal

   vault kv put   secret/myapp/db password=hunter2
   vault kv get   secret/myapp/db
   vault kv list  secret/myapp/
   vault kv delete secret/myapp/db
   vault kv metadata get secret/myapp/db
   vault kv rotate secret/myapp/db password=newpass

   vault policy write  mypolicy policy.json
   vault policy read   mypolicy
   vault policy delete mypolicy
   vault policy list

   vault auth approle role create myrole --policies=mypolicy
   vault auth approle login --role-id=... --secret-id=...

   vault token create [--policy=...] [--ttl=24h]
   vault token revoke <token>
   vault token lookup
   ```
3. **Config** (`~/.secretvault/config.yaml`): `address`, `token`, `tls_ca_cert`
4. **Env var overrides**: `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_CACERT`
5. **Output formats**: table (default), JSON (`-format=json`), raw (`-field=key`)

**Verification:** Shell script integration test covering full workflow: init → unseal → kv put → kv get → verify decrypted value matches.

---

## Phase 7 — Audit & Observability

**Goal:** Tamper-evident audit trail and operational metrics.

### Steps
1. **Audit log writer** (`internal/audit/logger.go`)
   - Every request logged: `request_id`, `timestamp`, `token_hash` (never plaintext), `operation`, `path`, `http_status`, `response_time_ms`, `client_ip`
   - Secret values are **never** written to audit log (only metadata)
   - Append-only: no UPDATE/DELETE on `audit_log` table (Postgres trigger to enforce)
2. **Audit query API**
   - `GET /v1/sys/audit-log?path=secret/&since=2024-01-01` — paginated audit entries (requires `sudo` capability)
3. **Prometheus metrics** (`/metrics`)
   - `secretvault_requests_total{method, path, status}`
   - `secretvault_request_duration_seconds`
   - `secretvault_secrets_total` (count by type)
   - `secretvault_active_tokens_total`
   - `secretvault_seal_status` (0=sealed, 1=unsealed)
4. **Structured server logging** via `zerolog` — JSON lines to stdout

**Verification:** Make 10 requests; query audit log and confirm all 10 appear with correct paths and token hashes.

---

## Key Data Structures (Go)

```go
// pkg/models/secret.go
type SecretVersion struct {
    ID           int64
    SecretID     int64
    Version      int
    EncryptedDEK []byte
    Ciphertext   []byte
    Nonce        []byte
    CreatedAt    time.Time
    DeletedAt    *time.Time
    Destroyed    bool
}

type SecretMetadata struct {
    Path          string
    Type          string  // "kv", "pem", "env"
    CurrentVersion int
    Versions      []VersionInfo
    CreatedAt     time.Time
    UpdatedAt     time.Time
}

// pkg/models/auth.go
type Token struct {
    ID          string
    DisplayName string
    Policies    []string
    TTL         time.Duration
    Renewable   bool
    CreatedAt   time.Time
    ExpiresAt   time.Time
    RevokedAt   *time.Time
    ParentID    *string
}

// pkg/models/policy.go
type Policy struct {
    Name  string
    Rules map[string]PathRule  // path glob → capabilities
}
type PathRule struct {
    Capabilities []string  // read, write, list, delete, sudo
}
```

---

## Dependency Summary
| Package | Purpose |
|---|---|
| `github.com/go-chi/chi/v5` | HTTP router |
| `github.com/spf13/cobra` | CLI framework |
| `github.com/jackc/pgx/v5` | PostgreSQL driver + pool |
| `github.com/golang-migrate/migrate/v4` | DB migrations |
| `github.com/rs/zerolog` | Structured logging |
| `golang.org/x/crypto` | HKDF, bcrypt, Shamir |
| `github.com/prometheus/client_golang` | Metrics |
