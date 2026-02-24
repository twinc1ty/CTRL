package storage

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/org/secretvault/pkg/models"
)

// PostgresBackend is a StorageBackend backed by PostgreSQL.
type PostgresBackend struct {
	pool *pgxpool.Pool
}

// NewPostgresBackend opens a pgxpool connection and returns a ready backend.
func NewPostgresBackend(ctx context.Context, connStr string) (*PostgresBackend, error) {
	cfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("parsing postgres config: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connecting to postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("pinging postgres: %w", err)
	}
	return &PostgresBackend{pool: pool}, nil
}

func (p *PostgresBackend) Close() {
	p.pool.Close()
}

// --- Vault init ---

func (p *PostgresBackend) InitVault(ctx context.Context, data *models.InitData) error {
	// Encode shards as base64 JSON array
	encoded := make([]string, len(data.EncryptedRootKeyShares))
	for i, s := range data.EncryptedRootKeyShares {
		encoded[i] = base64.StdEncoding.EncodeToString(s)
	}
	sharesJSON, err := json.Marshal(encoded)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx,
		`INSERT INTO vault_init (key_shares, kek_context, initialized_at) VALUES ($1, $2, $3)`,
		sharesJSON, data.KEKContext, data.InitializedAt,
	)
	return err
}

func (p *PostgresBackend) GetInitData(ctx context.Context) (*models.InitData, error) {
	row := p.pool.QueryRow(ctx,
		`SELECT key_shares, kek_context, initialized_at FROM vault_init ORDER BY id LIMIT 1`,
	)
	var sharesJSON []byte
	var kekCtx string
	var initAt time.Time
	if err := row.Scan(&sharesJSON, &kekCtx, &initAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var encoded []string
	if err := json.Unmarshal(sharesJSON, &encoded); err != nil {
		return nil, err
	}
	shards := make([][]byte, len(encoded))
	for i, s := range encoded {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
		shards[i] = b
	}
	return &models.InitData{
		EncryptedRootKeyShares: shards,
		KEKContext:             kekCtx,
		InitializedAt:          initAt,
	}, nil
}

func (p *PostgresBackend) IsInitialized(ctx context.Context) (bool, error) {
	var count int
	err := p.pool.QueryRow(ctx, `SELECT COUNT(*) FROM vault_init`).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// --- Secrets ---

func (p *PostgresBackend) WriteSecretVersion(ctx context.Context, path, secretType string, v *models.SecretVersion) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Upsert secret path
	var secretID int64
	err = tx.QueryRow(ctx,
		`INSERT INTO secrets (path, type, updated_at)
		 VALUES ($1, $2, NOW())
		 ON CONFLICT (path) DO UPDATE SET updated_at = NOW(), type = EXCLUDED.type
		 RETURNING id`,
		path, secretType,
	).Scan(&secretID)
	if err != nil {
		return fmt.Errorf("upserting secret path: %w", err)
	}

	// Determine next version number
	var maxVer int
	err = tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM secret_versions WHERE secret_id = $1`,
		secretID,
	).Scan(&maxVer)
	if err != nil {
		return fmt.Errorf("fetching max version: %w", err)
	}
	v.Version = maxVer + 1
	v.SecretID = secretID

	_, err = tx.Exec(ctx,
		`INSERT INTO secret_versions (secret_id, version, encrypted_dek, ciphertext, nonce, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		secretID, v.Version, v.EncryptedDEK, v.Ciphertext, v.Nonce, v.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("inserting secret version: %w", err)
	}
	return tx.Commit(ctx)
}

func (p *PostgresBackend) ReadSecretVersion(ctx context.Context, path string, version int) (*models.SecretVersion, error) {
	row := p.pool.QueryRow(ctx,
		`SELECT sv.id, sv.secret_id, sv.version, sv.encrypted_dek, sv.ciphertext, sv.nonce,
		        sv.created_at, sv.deleted_at, sv.destroyed
		 FROM secret_versions sv
		 JOIN secrets s ON s.id = sv.secret_id
		 WHERE s.path = $1 AND sv.version = $2`,
		path, version,
	)
	return scanSecretVersion(row)
}

func (p *PostgresBackend) ReadLatestSecretVersion(ctx context.Context, path string) (*models.SecretVersion, error) {
	row := p.pool.QueryRow(ctx,
		`SELECT sv.id, sv.secret_id, sv.version, sv.encrypted_dek, sv.ciphertext, sv.nonce,
		        sv.created_at, sv.deleted_at, sv.destroyed
		 FROM secret_versions sv
		 JOIN secrets s ON s.id = sv.secret_id
		 WHERE s.path = $1
		 ORDER BY sv.version DESC
		 LIMIT 1`,
		path,
	)
	return scanSecretVersion(row)
}

func scanSecretVersion(row pgx.Row) (*models.SecretVersion, error) {
	var v models.SecretVersion
	err := row.Scan(&v.ID, &v.SecretID, &v.Version, &v.EncryptedDEK, &v.Ciphertext, &v.Nonce,
		&v.CreatedAt, &v.DeletedAt, &v.Destroyed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &v, nil
}

func (p *PostgresBackend) ListSecrets(ctx context.Context, prefix string) ([]string, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT path FROM secrets WHERE path LIKE $1 AND deleted_at IS NULL ORDER BY path`,
		prefix+"%",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var paths []string
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	return paths, rows.Err()
}

func (p *PostgresBackend) DeleteSecretVersions(ctx context.Context, path string, versions []int) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE secret_versions sv
		 SET deleted_at = NOW()
		 FROM secrets s
		 WHERE s.id = sv.secret_id AND s.path = $1
		   AND sv.version = ANY($2::int[])
		   AND sv.destroyed = FALSE`,
		path, versions,
	)
	return err
}

func (p *PostgresBackend) UndeleteSecretVersions(ctx context.Context, path string, versions []int) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE secret_versions sv
		 SET deleted_at = NULL
		 FROM secrets s
		 WHERE s.id = sv.secret_id AND s.path = $1
		   AND sv.version = ANY($2::int[])
		   AND sv.destroyed = FALSE`,
		path, versions,
	)
	return err
}

func (p *PostgresBackend) DestroySecretVersions(ctx context.Context, path string, versions []int) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE secret_versions sv
		 SET encrypted_dek = NULL, ciphertext = NULL, nonce = NULL, destroyed = TRUE, deleted_at = NOW()
		 FROM secrets s
		 WHERE s.id = sv.secret_id AND s.path = $1
		   AND sv.version = ANY($2::int[])`,
		path, versions,
	)
	return err
}

func (p *PostgresBackend) GetSecretMetadata(ctx context.Context, path string) (*models.SecretMetadata, error) {
	// Get secret row
	var secretID int64
	var secretType string
	var createdAt, updatedAt time.Time
	err := p.pool.QueryRow(ctx,
		`SELECT id, type, created_at, updated_at FROM secrets WHERE path = $1`,
		path,
	).Scan(&secretID, &secretType, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Get versions
	rows, err := p.pool.Query(ctx,
		`SELECT version, created_at, deleted_at, destroyed
		 FROM secret_versions WHERE secret_id = $1 ORDER BY version`,
		secretID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var versionInfos []models.VersionInfo
	maxVersion := 0
	for rows.Next() {
		var vi models.VersionInfo
		if err := rows.Scan(&vi.Version, &vi.CreatedAt, &vi.DeletedAt, &vi.Destroyed); err != nil {
			return nil, err
		}
		versionInfos = append(versionInfos, vi)
		if vi.Version > maxVersion {
			maxVersion = vi.Version
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &models.SecretMetadata{
		Path:           path,
		Type:           secretType,
		CurrentVersion: maxVersion,
		Versions:       versionInfos,
		CreatedAt:      createdAt,
		UpdatedAt:      updatedAt,
	}, nil
}

// --- Tokens ---

func (p *PostgresBackend) WriteToken(ctx context.Context, token *models.Token) error {
	// When called via WriteToken, token_hash == token.ID (test/simple usage).
	return p.WriteTokenWithHash(ctx, token, token.ID)
}

// WriteTokenWithHash persists a token with an explicit hash (SHA-256 of plaintext).
func (p *PostgresBackend) WriteTokenWithHash(ctx context.Context, token *models.Token, tokenHash string) error {
	ttlSec := int64(token.TTL.Seconds())
	_, err := p.pool.Exec(ctx,
		`INSERT INTO tokens (id, token_hash, display_name, policies, ttl_seconds, renewable, created_at, expires_at, parent_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (id) DO UPDATE
		 SET display_name = EXCLUDED.display_name,
		     policies = EXCLUDED.policies,
		     ttl_seconds = EXCLUDED.ttl_seconds,
		     renewable = EXCLUDED.renewable,
		     expires_at = EXCLUDED.expires_at`,
		token.ID, tokenHash, token.DisplayName, token.Policies,
		ttlSec, token.Renewable, token.CreatedAt, nullableTime(token.ExpiresAt), token.ParentID,
	)
	return err
}

func nullableTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func (p *PostgresBackend) GetToken(ctx context.Context, tokenHash string) (*models.Token, error) {
	row := p.pool.QueryRow(ctx,
		`SELECT id, display_name, policies, ttl_seconds, renewable, created_at, expires_at, revoked_at, parent_id
		 FROM tokens WHERE token_hash = $1`,
		tokenHash,
	)
	return scanToken(row)
}

func scanToken(row pgx.Row) (*models.Token, error) {
	var t models.Token
	var ttlSec int64
	var expiresAt *time.Time
	err := row.Scan(&t.ID, &t.DisplayName, &t.Policies, &ttlSec, &t.Renewable,
		&t.CreatedAt, &expiresAt, &t.RevokedAt, &t.ParentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	t.TTL = time.Duration(ttlSec) * time.Second
	if expiresAt != nil {
		t.ExpiresAt = *expiresAt
	}
	return &t, nil
}

func (p *PostgresBackend) RevokeToken(ctx context.Context, tokenID string) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE tokens SET revoked_at = NOW() WHERE id = $1`,
		tokenID,
	)
	return err
}

func (p *PostgresBackend) RevokeTokenChildren(ctx context.Context, parentID string) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE tokens SET revoked_at = NOW() WHERE parent_id = $1 AND revoked_at IS NULL`,
		parentID,
	)
	return err
}

func (p *PostgresBackend) RenewToken(ctx context.Context, tokenID string, newExpiresAt interface{}) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE tokens SET expires_at = $1 WHERE id = $2`,
		newExpiresAt, tokenID,
	)
	return err
}

// --- AppRole ---

func (p *PostgresBackend) WriteAppRole(ctx context.Context, role *models.AppRole) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO approle_roles (id, name, policies, secret_id_ttl_s, token_ttl_s, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (name) DO UPDATE
		 SET policies = EXCLUDED.policies,
		     secret_id_ttl_s = EXCLUDED.secret_id_ttl_s,
		     token_ttl_s = EXCLUDED.token_ttl_s`,
		role.ID, role.Name, role.Policies,
		int64(role.SecretIDTTL.Seconds()), int64(role.TokenTTL.Seconds()), role.CreatedAt,
	)
	return err
}

func (p *PostgresBackend) GetAppRole(ctx context.Context, name string) (*models.AppRole, error) {
	row := p.pool.QueryRow(ctx,
		`SELECT id, name, policies, secret_id_ttl_s, token_ttl_s, created_at
		 FROM approle_roles WHERE name = $1`,
		name,
	)
	return scanAppRole(row)
}

func (p *PostgresBackend) GetAppRoleByID(ctx context.Context, roleID string) (*models.AppRole, error) {
	row := p.pool.QueryRow(ctx,
		`SELECT id, name, policies, secret_id_ttl_s, token_ttl_s, created_at
		 FROM approle_roles WHERE id = $1`,
		roleID,
	)
	return scanAppRole(row)
}

func scanAppRole(row pgx.Row) (*models.AppRole, error) {
	var r models.AppRole
	var sidTTL, tokTTL int64
	err := row.Scan(&r.ID, &r.Name, &r.Policies, &sidTTL, &tokTTL, &r.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	r.SecretIDTTL = time.Duration(sidTTL) * time.Second
	r.TokenTTL = time.Duration(tokTTL) * time.Second
	return &r, nil
}

func (p *PostgresBackend) WriteAppRoleSecret(ctx context.Context, secret *models.AppRoleSecret) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO approle_secrets (id, role_id, secret_id_hash, uses_remaining, expires_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		secret.ID, secret.RoleID, secret.SecretIDHash, secret.UsesRemaining, secret.ExpiresAt,
	)
	return err
}

func (p *PostgresBackend) GetAppRoleSecret(ctx context.Context, secretIDHash string) (*models.AppRoleSecret, error) {
	row := p.pool.QueryRow(ctx,
		`SELECT id, role_id, secret_id_hash, uses_remaining, expires_at, used_at
		 FROM approle_secrets WHERE secret_id_hash = $1`,
		secretIDHash,
	)
	var s models.AppRoleSecret
	err := row.Scan(&s.ID, &s.RoleID, &s.SecretIDHash, &s.UsesRemaining, &s.ExpiresAt, &s.UsedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &s, nil
}

func (p *PostgresBackend) ConsumeAppRoleSecret(ctx context.Context, secretIDHash string) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE approle_secrets
		 SET uses_remaining = CASE WHEN uses_remaining IS NOT NULL THEN uses_remaining - 1 ELSE NULL END,
		     used_at = NOW()
		 WHERE secret_id_hash = $1`,
		secretIDHash,
	)
	return err
}

// --- Policies ---

func (p *PostgresBackend) WritePolicy(ctx context.Context, policy *models.Policy) error {
	rulesJSON, err := json.Marshal(policy.Rules)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx,
		`INSERT INTO policies (name, rules, created_at, updated_at)
		 VALUES ($1, $2, NOW(), NOW())
		 ON CONFLICT (name) DO UPDATE SET rules = EXCLUDED.rules, updated_at = NOW()`,
		policy.Name, rulesJSON,
	)
	return err
}

func (p *PostgresBackend) GetPolicy(ctx context.Context, name string) (*models.Policy, error) {
	row := p.pool.QueryRow(ctx,
		`SELECT name, rules, created_at, updated_at FROM policies WHERE name = $1`,
		name,
	)
	var pol models.Policy
	var rulesJSON []byte
	err := row.Scan(&pol.Name, &rulesJSON, &pol.CreatedAt, &pol.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal(rulesJSON, &pol.Rules); err != nil {
		return nil, err
	}
	return &pol, nil
}

func (p *PostgresBackend) DeletePolicy(ctx context.Context, name string) error {
	if name == "root" || name == "default" {
		return errors.New("cannot delete built-in policy")
	}
	_, err := p.pool.Exec(ctx, `DELETE FROM policies WHERE name = $1`, name)
	return err
}

func (p *PostgresBackend) ListPolicies(ctx context.Context) ([]string, error) {
	rows, err := p.pool.Query(ctx, `SELECT name FROM policies ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// --- Audit ---

func (p *PostgresBackend) WriteAuditEntry(ctx context.Context, entry *models.AuditEntry) error {
	metaJSON, err := json.Marshal(entry.Metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}
	_, err = p.pool.Exec(ctx,
		`INSERT INTO audit_log (request_id, timestamp, token_hash, operation, path, status, response_code, response_time_ms, client_ip, metadata)
		 VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		entry.RequestID, entry.Timestamp, entry.TokenHash, entry.Operation, entry.Path,
		entry.Status, entry.ResponseCode, entry.ResponseTimeMs, entry.ClientIP, metaJSON,
	)
	return err
}

func (p *PostgresBackend) QueryAuditLog(ctx context.Context, filter AuditFilter) ([]*models.AuditEntry, error) {
	query := strings.Builder{}
	query.WriteString(`SELECT id, request_id, timestamp, token_hash, operation, path, status, response_code, response_time_ms, client_ip, metadata FROM audit_log WHERE 1=1`)
	args := []any{}
	n := 1
	if filter.Path != "" {
		fmt.Fprintf(&query, ` AND path LIKE $%d`, n)
		args = append(args, filter.Path+"%")
		n++
	}
	if filter.Since != nil {
		fmt.Fprintf(&query, ` AND timestamp >= $%d`, n)
		args = append(args, filter.Since)
		n++
	}
	query.WriteString(` ORDER BY timestamp DESC`)
	if filter.Limit > 0 {
		fmt.Fprintf(&query, ` LIMIT $%d`, n)
		args = append(args, filter.Limit)
		n++
	}
	if filter.Offset > 0 {
		fmt.Fprintf(&query, ` OFFSET $%d`, n)
		args = append(args, filter.Offset)
	}

	rows, err := p.pool.Query(ctx, query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*models.AuditEntry
	for rows.Next() {
		var e models.AuditEntry
		var metaJSON []byte
		var reqID string
		if err := rows.Scan(&e.ID, &reqID, &e.Timestamp, &e.TokenHash, &e.Operation,
			&e.Path, &e.Status, &e.ResponseCode, &e.ResponseTimeMs, &e.ClientIP, &metaJSON); err != nil {
			return nil, err
		}
		e.RequestID = reqID
		json.Unmarshal(metaJSON, &e.Metadata) //nolint:errcheck
		entries = append(entries, &e)
	}
	return entries, rows.Err()
}

// --- Metrics ---

func (p *PostgresBackend) CountSecrets(ctx context.Context) (int64, error) {
	var count int64
	err := p.pool.QueryRow(ctx, `SELECT COUNT(*) FROM secrets WHERE deleted_at IS NULL`).Scan(&count)
	return count, err
}

func (p *PostgresBackend) CountActiveTokens(ctx context.Context) (int64, error) {
	var count int64
	err := p.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM tokens WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())`,
	).Scan(&count)
	return count, err
}
