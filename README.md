<div align="center">

```
 ██████╗████████╗██████╗ ██╗
██╔════╝╚══██╔══╝██╔══██╗██║
██║        ██║   ██████╔╝██║
██║        ██║   ██╔══██╗██║
╚██████╗   ██║   ██║  ██║███████╗
 ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝
```

**Self-hosted secrets lifecycle manager with envelope encryption, policy-driven access, and a tamper-evident audit trail.**

[![Build](https://img.shields.io/badge/build-passing-00fff7?style=flat-square&logo=go&logoColor=black)](https://github.com/twinc1ty/CTRL)
[![Tests](https://img.shields.io/badge/tests-20%2F20-00fff7?style=flat-square)](https://github.com/twinc1ty/CTRL)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-4169E1?style=flat-square&logo=postgresql&logoColor=white)](https://postgresql.org)
[![License](https://img.shields.io/badge/license-MIT-ff00a0?style=flat-square)](LICENSE)

[Landing Page](https://twinc1ty.github.io/CTRL) · [Overview Doc](Docs/OVERVIEW.md) · [Implementation Plan](Docs/PLAN.md)

</div>

---

## What is CTRL?

A workplace security incident — requiring full rotation of every API key, TLS certificate, and environment variable the team owned — made one thing clear: scattered secrets with no audit trail are a liability waiting to detonate.

**CTRL** is a self-hosted, auditable secrets manager built from scratch in Go. It gives teams complete ownership of their credentials with:

- **Envelope encryption** (AES-256-GCM + HKDF-SHA256 + per-secret DEKs) so a database breach yields only ciphertext
- **Shamir's Secret Sharing** so no single person can unlock the vault
- **Versioned KV store** for full history, soft-delete, and permanent destruction
- **Policy-driven access control** with path-glob ACL rules
- **Token + AppRole auth** for humans and CI/CD pipelines
- **Tamper-evident audit log** enforced by a Postgres trigger
- **REST API + CLI** that mirrors HashiCorp Vault's UX

---

## Table of Contents

- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [API Reference](#api-reference)
- [Security Model](#security-model)
- [Configuration](#configuration)
- [Development](#development)
- [Project Structure](#project-structure)

---

## Architecture

```
CLI (vault)
    │
    ▼  HTTPS / REST
┌──────────────────────────────────────────┐
│               API Server                 │
│  requestID · auth · audit · rateLimit    │
│  ┌──────────┐  ┌────────┐  ┌──────────┐ │
│  │   Auth   │  │ Policy │  │  Secret  │ │
│  │ Token    │  │ Engine │  │  Engine  │ │
│  │ AppRole  │  │ (ACL)  │  │ KV/PEM   │ │
│  └──────────┘  └────────┘  └──────────┘ │
│  ┌──────────────────────────────────┐   │
│  │          Crypto Layer            │   │
│  │  Root Key → KEK (HKDF) → DEK    │   │
│  │  Shamir SS · Seal/Unseal FSM    │   │
│  └──────────────────────────────────┘   │
└────────────────────┬─────────────────────┘
                     │
              ┌──────┴──────┐
              │  PostgreSQL │
              │  secrets    │
              │  tokens     │
              │  policies   │
              │  audit_log  │
              └─────────────┘
```

### Envelope Encryption

```
Root Key  (32 bytes, CSPRNG)
  └─ Shamir's SS → N shards (K required to unseal)
  └─ HKDF-SHA256 → KEK  (in RAM only, wiped on seal)
                     └─ AES-256-GCM → wrapped DEK  (per secret, stored in DB)
                                          └─ AES-256-GCM → Secret Plaintext
```

Compromising one secret's DEK — or the entire database — never exposes other secrets or the KEK.

---

## Quick Start

### Prerequisites

- Go 1.22+
- PostgreSQL 14+

### 1. Clone and build

```bash
git clone https://github.com/twinc1ty/CTRL.git
cd CTRL
go build -o bin/vault-server ./cmd/server
go build -o bin/vault        ./cmd/vault
```

### 2. Configure

```bash
cp config.yaml.example config.yaml
# Edit db_url, listen_addr, etc.
```

Or use environment variables:

```bash
export DATABASE_URL="postgres://user:pass@localhost:5432/ctrl?sslmode=disable"
export VAULT_LISTEN_ADDR=":8200"
```

### 3. Start the server

```bash
./bin/vault-server
# Migrations run automatically on first start
```

### 4. Initialize the vault

```bash
# Generates 5 unseal shards — any 3 required to unseal
./bin/vault operator init --shares 5 --threshold 3

# Output:
# Key 1: <base64-shard-1>
# Key 2: <base64-shard-2>
# ...
# Root Token: svt_...
```

> Save the shards separately — once shown, they cannot be retrieved. The vault auto-unseals after init.

### 5. Set your token and write a secret

```bash
export VAULT_TOKEN="svt_..."

./bin/vault kv put secret/myapp/db \
  password=hunter2 \
  user=admin \
  host=db.internal

./bin/vault kv get secret/myapp/db
# password    hunter2
# user        admin
# host        db.internal
```

---

## CLI Reference

### Operator

```bash
vault operator init   [--shares N] [--threshold K]   # Initialize vault, generate shards
vault operator unseal [shard]                         # Provide one unseal shard
vault operator seal                                   # Seal the vault (wipes KEK from RAM)
```

### KV Secrets

```bash
vault kv put    <path> [key=value ...]    # Write a secret (creates new version)
vault kv get    <path> [--version N]     # Read a secret (default: latest)
vault kv list   <prefix>                 # List secrets under a prefix
vault kv delete <path>                   # Soft-delete latest version
vault kv rotate <path> [key=value ...]   # Write new version (rotation)
vault kv metadata get <path>             # Get version history and metadata
```

### Tokens

```bash
vault token create [--policy p1,p2] [--ttl 24h] [--renewable]
vault token revoke <token>
vault token lookup                       # Look up the current token
```

### Policies

```bash
vault policy write  <name> <policy.json>
vault policy read   <name>
vault policy delete <name>
vault policy list
```

**Policy file format (`policy.json`):**

```json
{
  "path": {
    "secret/data/myapp/*": {
      "capabilities": ["read", "write"]
    },
    "secret/data/shared/**": {
      "capabilities": ["read"]
    }
  }
}
```

Capabilities: `read` · `write` · `list` · `delete` · `sudo`

### AppRole Auth

```bash
# Create a role (for CI/CD pipelines)
vault auth approle role create ci-runner \
  --policies=deploy \
  --token-ttl=1h

# Get the role ID (safe to commit)
vault auth approle role get-id ci-runner

# Generate a secret ID (short-lived, single-use capable)
vault auth approle role create-secret-id ci-runner

# Login and get a scoped token
vault auth approle login \
  --role-id=<role-id> \
  --secret-id=<secret-id>
```

### Output Formats

```bash
vault kv get secret/myapp/db               # table (default)
vault kv get secret/myapp/db --format=json # JSON
vault kv get secret/myapp/db --field=password --format=raw  # raw value
```

### Environment Variables

| Variable       | Description                      | Default                  |
|----------------|----------------------------------|--------------------------|
| `VAULT_ADDR`   | Server address                   | `http://127.0.0.1:8200`  |
| `VAULT_TOKEN`  | Auth token                       | from `~/.secretvault/config.yaml` |
| `VAULT_CACERT` | Path to CA certificate (TLS)     | —                        |

---

## API Reference

All routes are under `/v1/`. Authenticated routes require `X-Vault-Token: <token>`.

### System

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/sys/init` | Initialize vault, generate unseal shards |
| `GET` | `/v1/sys/seal-status` | Check sealed/unsealed state |
| `POST` | `/v1/sys/unseal` | Submit one unseal shard |
| `PUT` | `/v1/sys/seal` | Seal the vault |
| `GET` | `/v1/sys/health` | Health check |
| `GET` | `/v1/sys/audit-log` | Query audit log (requires `sudo`) |
| `GET` | `/metrics` | Prometheus metrics |

### Auth

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/auth/token/create` | Create a child token |
| `POST` | `/v1/auth/token/revoke` | Revoke a token (cascades to children) |
| `GET`  | `/v1/auth/token/lookup-self` | Look up current token |
| `POST` | `/v1/auth/token/renew-self` | Renew a renewable token |
| `POST` | `/v1/auth/approle/role` | Create/update an AppRole |
| `GET`  | `/v1/auth/approle/role/:name/role-id` | Get role ID |
| `POST` | `/v1/auth/approle/role/:name/secret-id` | Generate secret ID |
| `POST` | `/v1/auth/approle/login` | Login with role ID + secret ID |

### Secrets

| Method | Path | Description |
|--------|------|-------------|
| `POST`   | `/v1/secret/data/*path` | Write a secret |
| `GET`    | `/v1/secret/data/*path?version=N` | Read a secret |
| `DELETE` | `/v1/secret/data/*path` | Soft-delete versions |
| `GET`    | `/v1/secret/metadata/*path?list=true` | List secrets |
| `GET`    | `/v1/secret/metadata/*path` | Get version metadata |
| `DELETE` | `/v1/secret/destroy/*path` | Permanently destroy versions |

### Policies

| Method | Path | Description |
|--------|------|-------------|
| `POST`   | `/v1/sys/policy/:name` | Create/update policy |
| `GET`    | `/v1/sys/policy/:name` | Read policy |
| `DELETE` | `/v1/sys/policy/:name` | Delete policy |
| `GET`    | `/v1/sys/policy` | List all policies |

---

## Security Model

| Property | Implementation |
|----------|---------------|
| **Secrets unreadable at rest** | AES-256-GCM with per-secret DEKs; KEK held in RAM only |
| **No single point of key compromise** | Shamir's SS: threshold of operators required to unseal |
| **Token leaks can't raid the DB** | SHA-256 hashes only; plaintext shown once at creation |
| **Tamper-evident audit trail** | Postgres `BEFORE UPDATE/DELETE` trigger on `audit_log` rejects all mutations |
| **Least-privilege access** | Path-glob policies; tokens limited to declared capabilities |
| **Short-lived machine credentials** | AppRole secret IDs expire by TTL or use count |
| **Rotation without downtime** | Versioned secrets: new version atomic; old versions preserved |
| **Secret values never leave encrypted** | Audit log records only token hash, path, and status — never values |

### Seal / Unseal

```
Server starts → SEALED (no KEK in memory, all secret ops rejected)
  ↓  (operator submits K of N shards)
UNSEALED (KEK derived + cached in RAM, full operation)
  ↓  (operator seals, or server restarts)
SEALED again
```

---

## Configuration

**`config.yaml`:**

```yaml
listen_addr:      ":8200"
db_url:           "postgres://user:pass@localhost:5432/ctrl?sslmode=disable"
unseal_threshold: 3
migrations_dir:   "migrations"
log_level:        "info"

# TLS (recommended for production)
# tls_cert: "/path/to/cert.pem"
# tls_key:  "/path/to/key.pem"
```

**CLI config (`~/.secretvault/config.yaml`):**

```yaml
address:    "https://vault.internal:8200"
token:      "svt_..."
tls_ca_cert: "/path/to/ca.pem"
```

---

## Development

### Run tests

```bash
# Unit tests (no database required)
go test ./internal/crypto/ ./internal/policy/ ./internal/api/

# All packages
go test ./...
```

### Run locally (no TLS)

```bash
# Start postgres
docker run -d \
  -e POSTGRES_DB=ctrl \
  -e POSTGRES_USER=ctrl \
  -e POSTGRES_PASSWORD=ctrl \
  -p 5432:5432 postgres:16

# Start server
DATABASE_URL="postgres://ctrl:ctrl@localhost:5432/ctrl?sslmode=disable" \
  go run ./cmd/server/

# In another terminal
export VAULT_ADDR="http://127.0.0.1:8200"

go run ./cmd/vault/ operator init --shares 3 --threshold 2
export VAULT_TOKEN="<root-token-from-above>"
go run ./cmd/vault/ kv put secret/test hello=world
go run ./cmd/vault/ kv get secret/test
```

### Build binaries

```bash
go build -o bin/vault-server ./cmd/server
go build -o bin/vault        ./cmd/vault
```

---

## Project Structure

```
CTRL/
├── cmd/
│   ├── server/main.go       # API server binary
│   └── vault/main.go        # CLI binary
├── internal/
│   ├── crypto/              # AES-GCM, HKDF-SHA256, Shamir's SS
│   ├── core/seal.go         # Seal/unseal state machine
│   ├── storage/             # StorageBackend interface + PostgreSQL backend
│   ├── auth/                # TokenService + AppRoleService
│   ├── policy/              # Path-glob ACL engine
│   ├── secret/              # KV v2, PEM, env bundle engines + rotation
│   ├── api/                 # chi HTTP server, handlers, middleware, metrics
│   └── audit/               # AuditLogger interface + structured logger
├── pkg/models/              # Shared data structures
├── migrations/
│   ├── 001_init.up.sql      # Full schema + built-in policies
│   └── 001_init.down.sql
├── Docs/
│   ├── OVERVIEW.md          # Architecture narrative + design decisions
│   └── PLAN.md              # Full implementation plan
├── index.html               # GitHub Pages landing page
├── config.yaml.example      # Server config template
└── go.mod
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `go stdlib crypto` | AES-GCM · HKDF · SHA-256 — no third-party crypto |
| `github.com/go-chi/chi/v5` | HTTP router |
| `github.com/spf13/cobra` | CLI framework |
| `github.com/jackc/pgx/v5` | PostgreSQL driver + connection pool |
| `github.com/golang-migrate/migrate/v4` | SQL migration runner |
| `github.com/rs/zerolog` | Zero-allocation structured logging |
| `github.com/prometheus/client_golang` | Prometheus metrics |
| `gopkg.in/yaml.v3` | YAML config parsing |

---

<div align="center">

**CTRL** — Built with Go · PostgreSQL · AES-256-GCM

[github.com/twinc1ty/CTRL](https://github.com/twinc1ty/CTRL)

</div>
