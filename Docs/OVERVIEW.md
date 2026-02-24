# CTRL — Project Overview

## Why This Exists

A workplace security incident required full rotation of every secret the team managed — API keys, TLS certificates, environment variables, database credentials. The process was painful: secrets were scattered across `.env` files, spreadsheets, and password managers, with no audit trail of who accessed what or when, no versioning, and no way to know if a leaked credential had already been used.

Rather than bolt onto an existing hosted solution (with its own trust and compliance surface), we built **CTRL** — a self-hosted, auditable secrets lifecycle manager inspired by HashiCorp Vault, designed to be owned entirely by the team.

---

## What Was Built

CTRL is a full-stack secrets management system. It covers the entire lifecycle of a secret: creation, storage, access control, rotation, and destruction — with a cryptographic audit trail at every step.

### The Seven Layers

#### 1. Cryptographic Foundation
The most critical piece. Everything else rests on this.

We implemented **envelope encryption**: each secret is encrypted with its own randomly-generated **Data Encryption Key (DEK)**. That DEK is then wrapped by a **Key Encryption Key (KEK)**, which is derived from a **Root Key** using HKDF-SHA256. This means compromising one secret's DEK never exposes any other secret.

The Root Key itself never lives on disk. On first setup, it is split into multiple shards using **Shamir's Secret Sharing** — a threshold scheme where, for example, any 3 of 5 shards can reconstruct the key. No single person holds the full key.

> *Why this matters:* If an attacker exfiltrates the entire database, they get only ciphertext. Without the KEK (held only in RAM while the vault is unsealed), the data is unreadable.

#### 2. Seal / Unseal State Machine
The vault starts **sealed** — the KEK is not in memory. The server will accept requests but refuse to read or write secrets until a quorum of key-holders each submit their shard. Once the threshold is met, the Root Key is reconstructed, the KEK is derived and cached in memory, and the vault becomes **unsealed**.

Calling `seal` wipes the KEK from memory, returning the vault to a locked state. This means a server restart or a deliberate seal operation makes all secret data unreadable, even to someone with full disk access.

#### 3. Storage Layer
A clean interface (`StorageBackend`) decouples the rest of the system from PostgreSQL. This means the backend could be swapped for another store without changing any business logic.

The PostgreSQL schema stores:
- **Versioned secrets** — every write creates a new version; old versions are preserved and recoverable
- **Tokens** — hashed (SHA-256), never in plaintext
- **AppRole credentials** — for machine-to-machine auth
- **Policies** — the ACL ruleset
- **Audit log** — append-only, enforced by a Postgres trigger that rejects any `UPDATE` or `DELETE`

#### 4. Authentication
Two methods are supported:

**Token Auth** — The primary method. Tokens are opaque random strings. Only the SHA-256 hash is stored in the database, so even a full DB dump does not expose valid tokens. Tokens can have TTLs, be renewable, and form parent-child trees (revoking a parent cascades to all children).

**AppRole Auth** — For automated systems and CI/CD pipelines. A Role ID (static, safe to commit) is paired with a Secret ID (short-lived, generated on demand). Presenting both issues a scoped token. This avoids storing long-lived credentials in pipelines.

#### 5. Policy Engine
Access control uses a path-glob model matching HashiCorp Vault's design. Each policy is a JSON document mapping path patterns to capability sets:

```json
{
  "secret/data/myapp/*": { "capabilities": ["read", "write"] },
  "secret/data/shared/**": { "capabilities": ["read"] }
}
```

Capabilities: `read`, `write`, `list`, `delete`, `sudo`. The engine supports exact paths, single-segment wildcards (`*`), and multi-segment wildcards (`**`). A token holds multiple policies; access is granted if *any* attached policy allows the operation.

#### 6. Secret Engines
Three secret types are supported:

- **KV v2** — Generic key-value store. Every `put` creates a new version. Old versions can be soft-deleted (data preserved but inaccessible), undeleted, or permanently destroyed (ciphertext and DEK wiped). This gives full control over the secret lifecycle.
- **PEM** — Structured storage for TLS certificates. Automatically parses the `NotAfter` field from the certificate, so you always know when a cert expires without decrypting it.
- **Env Bundle** — Stores a map of environment variables. Can be exported directly to `.env` file format for local development or CI injection.

#### 7. REST API + CLI
The HTTP API follows Vault's URL conventions (`/v1/secret/data/*`, `/v1/auth/token/*`, etc.), making it familiar to anyone who has used Vault. TLS 1.2+ is enforced when cert/key files are configured.

The CLI (`vault`) mirrors Vault's command structure: `vault kv put`, `vault kv get`, `vault operator init`, etc. It reads from `~/.secretvault/config.yaml` and respects `VAULT_ADDR`, `VAULT_TOKEN`, and `VAULT_CACERT` environment variables for easy scripting.

---

## Audit & Observability

Every API request — successful or not — is written to an append-only audit log. The log records:
- A unique request ID
- Timestamp
- Token hash (never the plaintext token)
- Operation and path
- HTTP response code and latency
- Client IP

**Secret values are never written to the audit log** — only paths and metadata.

A Postgres trigger prevents any `UPDATE` or `DELETE` on the audit table, making the log tamper-evident.

Prometheus metrics are exposed at `/metrics`:
- Request counts and latency histograms
- Active token count
- Secret count by type
- Seal status gauge

---

## Technology Choices

| Choice | Rationale |
|---|---|
| **Go** | Single binary, strong standard crypto library, excellent concurrency for a server handling concurrent secret reads |
| **PostgreSQL** | Battle-tested, ACID guarantees, `JSONB` for flexible policy storage, native support for append-only triggers |
| **AES-256-GCM** | Authenticated encryption — provides both confidentiality and integrity in one primitive |
| **HKDF-SHA256** | Standard key derivation; deterministic and collision-resistant |
| **Shamir's Secret Sharing** | Avoids a single point of compromise for the root key; no single operator can unlock the vault alone |
| **chi** | Lightweight, idiomatic Go HTTP router with no magic |
| **cobra** | Industry-standard Go CLI framework; clean subcommand structure |
| **zerolog** | Structured JSON logging with zero allocations on the hot path |

---

## Security Properties

| Property | How It's Achieved |
|---|---|
| **Secret data unreadable at rest** | AES-256-GCM with per-secret DEKs; DEKs wrapped by KEK held only in RAM |
| **No single point of key compromise** | Shamir's SS: threshold of operators required to unseal |
| **Token leaks don't expose DB** | Only SHA-256 hashes of tokens stored; plaintext shown once at creation |
| **Tamper-evident audit trail** | Postgres trigger rejects all mutations to `audit_log` |
| **Least-privilege access** | Fine-grained path-glob policies; tokens limited to declared capabilities |
| **Automated system safety** | AppRole: role ID safe to commit; secret ID short-lived and single-use capable |
| **Rotation without downtime** | Versioned secrets: new version written atomically; old versions preserved |

---

## Project Structure

```
SecretVault/
├── cmd/
│   ├── server/main.go       # API server binary
│   └── vault/main.go        # CLI binary
├── internal/
│   ├── crypto/              # AES-GCM, HKDF, Shamir's SS
│   ├── core/seal.go         # Seal/unseal state machine
│   ├── storage/             # StorageBackend interface + PostgreSQL
│   ├── auth/                # Token + AppRole services
│   ├── policy/              # Path-glob ACL engine
│   ├── secret/              # KV v2, PEM, env engines
│   ├── api/                 # HTTP handlers + middleware
│   └── audit/               # Audit logger
├── pkg/models/              # Shared data structures
├── migrations/              # SQL migration files
└── Docs/                    # Project documentation
```
