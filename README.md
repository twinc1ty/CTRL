<div align="center">

```
 ██████╗████████╗██████╗ ██╗
██╔════╝╚══██╔══╝██╔══██╗██║
██║        ██║   ██████╔╝██║
██║        ██║   ██╔══██╗██║
╚██████╗   ██║   ██║  ██║███████╗
 ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝
```

**Self-hosted secrets lifecycle manager — envelope encryption, policy-driven access, tamper-evident audit trail.**

[![CI](https://github.com/twinc1ty/CTRL/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/twinc1ty/CTRL/actions/workflows/ci.yml)
[![Release](https://github.com/twinc1ty/CTRL/actions/workflows/release.yml/badge.svg)](https://github.com/twinc1ty/CTRL/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/twinc1ty/CTRL?style=flat-square&color=00fff7)](https://github.com/twinc1ty/CTRL/releases/latest)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-ff00a0?style=flat-square)](LICENSE)

[Landing Page](https://twinc1ty.github.io/CTRL) · [Releases](https://github.com/twinc1ty/CTRL/releases)

</div>

---

## What is CTRL?

A workplace security incident — requiring full rotation of every API key, TLS certificate, and environment variable the team owned — made one thing clear: scattered secrets with no audit trail are a liability waiting to detonate.

**CTRL** is a self-hosted, auditable secrets manager built in Go, giving teams complete ownership of their credentials with:

- **Envelope encryption** (AES-256-GCM + HKDF-SHA256 + per-secret DEKs) so a database breach yields only ciphertext
- **Shamir's Secret Sharing** so no single person can unlock the vault
- **Versioned KV store** with full history, soft-delete, and permanent destruction
- **Path-glob ACL policies** for fine-grained access control
- **Token + AppRole auth** for humans and CI/CD pipelines
- **Tamper-evident audit log** enforced by a Postgres trigger
- **REST API + Cobra CLI** that mirrors HashiCorp Vault's UX

---

## Table of Contents

- [Architecture](#architecture)
- [Install](#install)
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
│  │  Token   │  │ Engine │  │  Engine  │ │
│  │ AppRole  │  │  (ACL) │  │ KV / PEM │ │
│  └──────────┘  └────────┘  └──────────┘ │
│  ┌──────────────────────────────────┐   │
│  │          Crypto Layer            │   │
│  │  Root Key → KEK (HKDF) → DEK    │   │
│  │  Shamir SS · Seal/Unseal FSM    │   │
│  └──────────────────────────────────┘   │
└────────────────────┬─────────────────────┘
                     │
              ┌──────┴──────┐
              │  PostgreSQL  │
              │  secrets     │
              │  tokens      │
              │  policies    │
              │  audit_log   │
              └─────────────┘
```

### Envelope encryption

```
Root Key  (32 bytes, CSPRNG)
  └─ Shamir's SS → N shards  (K required to unseal)
  └─ HKDF-SHA256 → KEK       (in RAM only, wiped on seal)
                     └─ AES-256-GCM → wrapped DEK  (per secret, stored in DB)
                                          └─ AES-256-GCM → Secret Plaintext
```

Compromising one DEK — or the entire database — never exposes the KEK or any other secret.

---

## Install

### Download a binary (recommended)

Grab the latest release for your platform from the [Releases page](https://github.com/twinc1ty/CTRL/releases/latest).

```bash
# Linux / macOS
VERSION=$(curl -s https://api.github.com/repos/twinc1ty/CTRL/releases/latest | grep tag_name | cut -d'"' -f4)
curl -LO "https://github.com/twinc1ty/CTRL/releases/download/${VERSION}/ctrl-${VERSION}-linux-amd64.tar.gz"
tar -xzf ctrl-${VERSION}-linux-amd64.tar.gz
chmod +x vault vault-server
sudo mv vault vault-server /usr/local/bin/

# Verify checksum
sha256sum -c ctrl-${VERSION}-linux-amd64.tar.gz.sha256
```

### Build from source

```bash
git clone https://github.com/twinc1ty/CTRL.git
cd CTRL
go build -o bin/vault-server ./cmd/server
go build -o bin/vault        ./cmd/vault
```

---

## Quick Start

### 1. Configure

```bash
cp config.yaml.example config.yaml
# Edit db_url to point at your PostgreSQL instance
```

Or use env vars:

```bash
export DATABASE_URL="postgres://user:pass@localhost:5432/ctrl?sslmode=disable"
```

### 2. Start the server

```bash
vault-server
# Migrations run automatically on first start
# → listening on :8200
```

### 3. Initialize and unseal

```bash
# Generate 5 shards, require any 3 to unseal
vault operator init --shares 5 --threshold 3

# Output:
#   Key 1: <base64-shard>  ← distribute these to 5 different operators
#   ...
#   Root Token: svt_...    ← shown once, save it
```

> The vault auto-unseals after init. On subsequent restarts, provide threshold shards via `vault operator unseal`.

### 4. Write and read a secret

```bash
export VAULT_TOKEN="svt_..."

vault kv put secret/prod/db \
  password=hunter2 user=admin host=db.internal

vault kv get secret/prod/db
#   host      db.internal
#   password  hunter2
#   user      admin
```

---

## CLI Reference

### Operator

```bash
vault operator init   [--shares N] [--threshold K]
vault operator unseal [shard]
vault operator seal
```

### KV Secrets

```bash
vault kv put    <path> [key=value ...]
vault kv get    <path> [--version N]
vault kv list   <prefix>
vault kv delete <path>
vault kv rotate <path> [key=value ...]
vault kv metadata get <path>
```

### Tokens

```bash
vault token create [--policy p1,p2] [--ttl 24h] [--renewable]
vault token revoke <token>
vault token lookup
```

### Policies

```bash
vault policy write  <name> <policy.json>
vault policy read   <name>
vault policy delete <name>
vault policy list
```

**Policy file format:**

```json
{
  "path": {
    "secret/data/myapp/*":   { "capabilities": ["read","write"] },
    "secret/data/shared/**": { "capabilities": ["read"] }
  }
}
```

Capabilities: `read` · `write` · `list` · `delete` · `sudo`

### AppRole

```bash
# Create a role for CI/CD
vault auth approle role create ci-runner \
  --policies=deploy --token-ttl=1h

# Get the static role ID (safe to commit)
vault auth approle role get-id ci-runner

# Generate a short-lived secret ID
vault auth approle role create-secret-id ci-runner

# Login → scoped token
vault auth approle login \
  --role-id=<role-id> \
  --secret-id=<secret-id>
```

### Output formats

```bash
vault kv get secret/db                  # table (default)
vault kv get secret/db --format=json    # JSON
vault kv get secret/db --field=password --format=raw  # raw value
```

### Environment variables

| Variable       | Default                        |
|----------------|-------------------------------|
| `VAULT_ADDR`   | `http://127.0.0.1:8200`       |
| `VAULT_TOKEN`  | `~/.secretvault/config.yaml`  |
| `VAULT_CACERT` | —                             |

---

## API Reference

All routes are under `/v1/`. Authenticated routes require `X-Vault-Token`.

### System

| Method   | Path                   | Auth | Description                          |
|----------|------------------------|------|--------------------------------------|
| `POST`   | `/v1/sys/init`         | —    | Initialize vault, generate shards    |
| `GET`    | `/v1/sys/seal-status`  | —    | Sealed/unsealed state                |
| `POST`   | `/v1/sys/unseal`       | —    | Submit one unseal shard              |
| `PUT`    | `/v1/sys/seal`         | ✓    | Seal the vault                       |
| `GET`    | `/v1/sys/health`       | —    | Health check                         |
| `GET`    | `/v1/sys/audit-log`    | ✓    | Query audit log (requires `sudo`)    |
| `GET`    | `/metrics`             | —    | Prometheus metrics                   |

### Auth

| Method   | Path                                       | Description                        |
|----------|--------------------------------------------|------------------------------------|
| `POST`   | `/v1/auth/token/create`                    | Create a child token               |
| `POST`   | `/v1/auth/token/revoke`                    | Revoke a token (cascades)          |
| `GET`    | `/v1/auth/token/lookup-self`               | Look up current token              |
| `POST`   | `/v1/auth/token/renew-self`                | Renew a renewable token            |
| `POST`   | `/v1/auth/approle/role`                    | Create/update an AppRole           |
| `GET`    | `/v1/auth/approle/role/:name/role-id`      | Get role ID                        |
| `POST`   | `/v1/auth/approle/role/:name/secret-id`    | Generate secret ID                 |
| `POST`   | `/v1/auth/approle/login`                   | Login with role ID + secret ID     |

### Secrets

| Method   | Path                                  | Description                        |
|----------|---------------------------------------|------------------------------------|
| `POST`   | `/v1/secret/data/*path`               | Write a secret                     |
| `GET`    | `/v1/secret/data/*path?version=N`     | Read a secret                      |
| `DELETE` | `/v1/secret/data/*path`               | Soft-delete versions               |
| `GET`    | `/v1/secret/metadata/*path?list=true` | List secrets under prefix          |
| `GET`    | `/v1/secret/metadata/*path`           | Get version metadata               |
| `DELETE` | `/v1/secret/destroy/*path`            | Permanently destroy versions       |

### Policies

| Method   | Path                  | Description              |
|----------|-----------------------|--------------------------|
| `POST`   | `/v1/sys/policy/:name`| Create/update policy     |
| `GET`    | `/v1/sys/policy/:name`| Read policy              |
| `DELETE` | `/v1/sys/policy/:name`| Delete policy            |
| `GET`    | `/v1/sys/policy`      | List all policies        |

---

## Security Model

| Property | Implementation |
|----------|---------------|
| Secrets unreadable at rest | AES-256-GCM with per-secret DEKs; KEK in RAM only |
| No single point of key compromise | Shamir's SS: threshold operators required to unseal |
| Token leaks don't expose the DB | SHA-256 hashes only; plaintext shown once at creation |
| Tamper-evident audit | Postgres trigger rejects all `UPDATE`/`DELETE` on `audit_log` |
| Least-privilege access | Path-glob policies; tokens limited to declared capabilities |
| Short-lived machine credentials | AppRole secret IDs expire by TTL or use count |
| Rotation without downtime | Versioned secrets: new version atomic; old versions preserved |
| Audit never contains secret values | Only token hash, path, and status logged |

### Seal / Unseal lifecycle

```
Server starts  →  SEALED   (KEK not in memory; secret ops rejected)
  ↓  operator submits K of N shards
               →  UNSEALED (KEK derived from root key, cached in RAM)
  ↓  seal command OR server restart
               →  SEALED   (KEK zeroed from memory)
```

---

## Configuration

**`config.yaml` (server):**

```yaml
listen_addr:      ":8200"
db_url:           "postgres://user:pass@localhost:5432/ctrl?sslmode=disable"
unseal_threshold: 3
migrations_dir:   "migrations"
log_level:        "info"

# TLS (strongly recommended for production)
# tls_cert: "/etc/ctrl/cert.pem"
# tls_key:  "/etc/ctrl/key.pem"
```

**`~/.secretvault/config.yaml` (CLI):**

```yaml
address:    "https://vault.internal:8200"
token:      "svt_..."
tls_ca_cert: "/path/to/ca.pem"
```

---

## Development

### Prerequisites

- Go 1.22+
- PostgreSQL 14+ (or Docker)

### Run tests

```bash
# Core unit tests — no database needed
go test ./internal/crypto/ ./internal/policy/ ./internal/api/ -v -count=1
```

### Run locally

```bash
# Spin up Postgres
docker run -d \
  -e POSTGRES_DB=ctrl \
  -e POSTGRES_USER=ctrl \
  -e POSTGRES_PASSWORD=ctrl \
  -p 5432:5432 postgres:16

# Start server
DATABASE_URL="postgres://ctrl:ctrl@localhost:5432/ctrl?sslmode=disable" \
  go run ./cmd/server/

# Init, write, read
export VAULT_ADDR="http://127.0.0.1:8200"
go run ./cmd/vault/ operator init --shares 3 --threshold 2
export VAULT_TOKEN="<root-token>"
go run ./cmd/vault/ kv put secret/test hello=world
go run ./cmd/vault/ kv get secret/test
```

### Release a new version

```bash
git tag v1.0.0
git push origin v1.0.0
# The release workflow builds all platform binaries and creates a GitHub Release automatically.
```

---

## Project Structure

```
CTRL/
├── .github/workflows/
│   ├── ci.yml          # Tests + build on every push to master
│   └── release.yml     # Multi-platform binaries + GitHub Release on tag
├── cmd/
│   ├── server/main.go  # API server binary
│   └── vault/main.go   # CLI binary
├── internal/
│   ├── crypto/         # AES-GCM, HKDF-SHA256, Shamir's SS
│   ├── core/seal.go    # Seal/unseal state machine
│   ├── storage/        # StorageBackend interface + PostgreSQL backend
│   ├── auth/           # TokenService + AppRoleService
│   ├── policy/         # Path-glob ACL engine
│   ├── secret/         # KV v2, PEM, env bundle engines + rotation
│   ├── api/            # HTTP server, handlers, middleware, metrics
│   └── audit/          # Audit logger
├── pkg/models/         # Shared data structures
├── migrations/         # SQL migration files (auto-applied on startup)
├── status.json         # Live CI status (written by ci.yml on every push)
├── index.html          # GitHub Pages landing page
└── config.yaml.example
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `stdlib crypto` | AES-GCM · HKDF · SHA-256 — no third-party crypto |
| `github.com/go-chi/chi/v5` | HTTP router |
| `github.com/spf13/cobra` | CLI framework |
| `github.com/jackc/pgx/v5` | PostgreSQL driver + connection pool |
| `github.com/golang-migrate/migrate/v4` | SQL migration runner |
| `github.com/rs/zerolog` | Zero-allocation structured logging |
| `github.com/prometheus/client_golang` | Prometheus metrics |
| `gopkg.in/yaml.v3` | YAML config parsing |

---

<div align="center">

Built with Go · PostgreSQL · AES-256-GCM

[github.com/twinc1ty/CTRL](https://github.com/twinc1ty/CTRL)

</div>
