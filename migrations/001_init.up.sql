-- SecretVault initial schema

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Vault initialization record (one row)
CREATE TABLE IF NOT EXISTS vault_init (
    id              SERIAL PRIMARY KEY,
    key_shares      JSONB NOT NULL,          -- base64-encoded encrypted shards
    kek_context     TEXT NOT NULL,
    initialized_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Secret paths
CREATE TABLE IF NOT EXISTS secrets (
    id          BIGSERIAL PRIMARY KEY,
    path        TEXT NOT NULL UNIQUE,
    type        TEXT NOT NULL DEFAULT 'kv',  -- kv, pem, env
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS secrets_path_prefix_idx ON secrets (path text_pattern_ops);

-- Secret versions (append-only except for soft-delete and destroy)
CREATE TABLE IF NOT EXISTS secret_versions (
    id            BIGSERIAL PRIMARY KEY,
    secret_id     BIGINT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version       INT NOT NULL,
    encrypted_dek BYTEA,                   -- NULL when destroyed
    ciphertext    BYTEA,                   -- NULL when destroyed
    nonce         BYTEA,                   -- NULL when destroyed
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at    TIMESTAMPTZ,
    destroyed     BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (secret_id, version)
);

-- Auth tokens
CREATE TABLE IF NOT EXISTS tokens (
    id           TEXT PRIMARY KEY,          -- UUID
    token_hash   TEXT NOT NULL UNIQUE,      -- SHA-256 of plaintext token
    display_name TEXT NOT NULL DEFAULT '',
    policies     TEXT[] NOT NULL DEFAULT '{}',
    ttl_seconds  BIGINT NOT NULL DEFAULT 0, -- 0 = no expiry
    renewable    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    parent_id    TEXT REFERENCES tokens(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS tokens_hash_idx ON tokens (token_hash);
CREATE INDEX IF NOT EXISTS tokens_parent_idx ON tokens (parent_id);

-- AppRole roles
CREATE TABLE IF NOT EXISTS approle_roles (
    id               TEXT PRIMARY KEY,      -- UUID
    name             TEXT NOT NULL UNIQUE,
    policies         TEXT[] NOT NULL DEFAULT '{}',
    secret_id_ttl_s  BIGINT NOT NULL DEFAULT 0,
    token_ttl_s      BIGINT NOT NULL DEFAULT 3600,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- AppRole secret IDs
CREATE TABLE IF NOT EXISTS approle_secrets (
    id               TEXT PRIMARY KEY,      -- UUID
    role_id          TEXT NOT NULL REFERENCES approle_roles(id) ON DELETE CASCADE,
    secret_id_hash   TEXT NOT NULL UNIQUE,  -- SHA-256 of plaintext secret ID
    uses_remaining   INT,                   -- NULL = unlimited
    expires_at       TIMESTAMPTZ,
    used_at          TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS approle_secrets_hash_idx ON approle_secrets (secret_id_hash);

-- Policies
CREATE TABLE IF NOT EXISTS policies (
    id         SERIAL PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    rules      JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit log (append-only)
CREATE TABLE IF NOT EXISTS audit_log (
    id               BIGSERIAL PRIMARY KEY,
    request_id       UUID NOT NULL,
    timestamp        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    token_hash       TEXT NOT NULL DEFAULT '',
    operation        TEXT NOT NULL,
    path             TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT '',
    response_code    INT NOT NULL DEFAULT 0,
    response_time_ms BIGINT NOT NULL DEFAULT 0,
    client_ip        TEXT NOT NULL DEFAULT '',
    metadata         JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS audit_log_timestamp_idx ON audit_log (timestamp);
CREATE INDEX IF NOT EXISTS audit_log_path_idx ON audit_log (path);

-- Prevent UPDATE and DELETE on audit_log (append-only enforcement)
CREATE OR REPLACE FUNCTION audit_log_immutable()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update
    BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

CREATE TRIGGER audit_log_no_delete
    BEFORE DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

-- Seed built-in policies
INSERT INTO policies (name, rules) VALUES
    ('root', '{"path": {"*": {"capabilities": ["read","write","list","delete","sudo"]}}}'),
    ('default', '{"path": {
        "auth/token/lookup-self":  {"capabilities": ["read"]},
        "auth/token/renew-self":   {"capabilities": ["write"]},
        "auth/token/revoke-self":  {"capabilities": ["write"]},
        "sys/health":              {"capabilities": ["read"]}
    }}')
ON CONFLICT (name) DO NOTHING;
