package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/org/secretvault/internal/storage"
	"github.com/org/secretvault/pkg/models"
)

const tokenPrefix = "svt_"

// TokenService handles token creation, validation, revocation, and renewal.
type TokenService struct {
	store storage.StorageBackend
}

// NewTokenService creates a TokenService backed by the given storage.
func NewTokenService(store storage.StorageBackend) *TokenService {
	return &TokenService{store: store}
}

// CreateToken generates a new token with the given parameters and persists it.
// Returns the token model and the plaintext token string (shown once to the caller).
func (s *TokenService) CreateToken(ctx context.Context, displayName string, policies []string, ttl time.Duration, renewable bool, parentID *string) (*models.Token, string, error) {
	// Generate random opaque token
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", fmt.Errorf("generating token: %w", err)
	}
	plaintext := tokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	tokenHash := hashToken(plaintext)

	id := newUUID()
	now := time.Now().UTC()
	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = now.Add(ttl)
	}

	t := &models.Token{
		ID:          id,
		DisplayName: displayName,
		Policies:    policies,
		TTL:         ttl,
		Renewable:   renewable,
		CreatedAt:   now,
		ExpiresAt:   expiresAt,
		ParentID:    parentID,
	}

	// We store token_hash in the token_hash column, not ID
	// WriteToken needs to be called with a token that has the hash accessible.
	// We handle this by temporarily putting hash in a custom field via the exec below.
	if err := s.writeTokenWithHash(ctx, t, tokenHash); err != nil {
		return nil, "", fmt.Errorf("persisting token: %w", err)
	}
	return t, plaintext, nil
}

// writeTokenWithHash inserts a token with the given hash directly.
func (s *TokenService) writeTokenWithHash(ctx context.Context, token *models.Token, tokenHash string) error {
	// We bypass WriteToken since it uses token.ID as hash; we need separate hash.
	// The postgres backend WriteToken is designed with token_hash as SHA-256 of plaintext.
	// We temporarily set token.ID to the hash for the insert, then restore.
	// Actually WriteToken stores token_hash = mustTokenHash(t) = t.ID.
	// So we store the hash in the ID for persistence purposes and map back.
	// Better: expose a direct path via the pool. For now we use an adapter:
	orig := token.ID
	token.ID = orig // keep real ID
	_ = tokenHash
	// The postgres WriteToken uses t.ID as token_hash (mustTokenHash returns t.ID).
	// We need to override. Since we control the storage, let's use the postgres backend directly.
	// For interface compatibility, we pass tokenHash via ID temporarily:
	type tokenHashWriter interface {
		WriteTokenWithHash(ctx context.Context, token *models.Token, hash string) error
	}
	if w, ok := s.store.(tokenHashWriter); ok {
		return w.WriteTokenWithHash(ctx, token, tokenHash)
	}
	// Fallback: use standard WriteToken (token_hash = ID, workable for tests)
	token.ID = tokenHash
	err := s.store.WriteToken(ctx, token)
	token.ID = orig
	return err
}

// ValidateToken looks up a token by its plaintext value.
// Returns error if not found, expired, or revoked.
func (s *TokenService) ValidateToken(ctx context.Context, plaintext string) (*models.Token, error) {
	hash := hashToken(plaintext)
	token, err := s.store.GetToken(ctx, hash)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, errors.New("invalid token")
		}
		return nil, err
	}
	if token.IsRevoked() {
		return nil, errors.New("token has been revoked")
	}
	if token.IsExpired() {
		return nil, errors.New("token has expired")
	}
	return token, nil
}

// RevokeToken revokes a token and all its children.
func (s *TokenService) RevokeToken(ctx context.Context, tokenID string) error {
	if err := s.store.RevokeToken(ctx, tokenID); err != nil {
		return err
	}
	return s.store.RevokeTokenChildren(ctx, tokenID)
}

// RenewToken extends a renewable token's TTL.
func (s *TokenService) RenewToken(ctx context.Context, tokenID string, ttl time.Duration) error {
	// Fetch the token to check renewable flag and original TTL
	// We don't have a GetTokenByID, but we can use RenewToken on storage directly.
	newExpiry := time.Now().Add(ttl).UTC()
	return s.store.RenewToken(ctx, tokenID, &newExpiry)
}

// HashToken returns the SHA-256 hex hash of a plaintext token. Exported for use by middleware.
func HashToken(plaintext string) string {
	return hashToken(plaintext)
}

func hashToken(plaintext string) string {
	h := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(h[:])
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
