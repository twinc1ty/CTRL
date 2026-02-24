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

// AppRoleService manages AppRole auth lifecycle.
type AppRoleService struct {
	store  storage.StorageBackend
	tokens *TokenService
}

// NewAppRoleService creates an AppRoleService.
func NewAppRoleService(store storage.StorageBackend, tokens *TokenService) *AppRoleService {
	return &AppRoleService{store: store, tokens: tokens}
}

// CreateRole creates or updates an AppRole.
func (s *AppRoleService) CreateRole(ctx context.Context, name string, policies []string, secretIDTTL, tokenTTL time.Duration) (*models.AppRole, error) {
	role := &models.AppRole{
		ID:          newUUID(),
		Name:        name,
		Policies:    policies,
		SecretIDTTL: secretIDTTL,
		TokenTTL:    tokenTTL,
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.store.WriteAppRole(ctx, role); err != nil {
		return nil, fmt.Errorf("creating approle: %w", err)
	}
	return role, nil
}

// GetRole returns an AppRole by name.
func (s *AppRoleService) GetRole(ctx context.Context, name string) (*models.AppRole, error) {
	return s.store.GetAppRole(ctx, name)
}

// GenerateSecretID creates a new secret ID for the named role.
func (s *AppRoleService) GenerateSecretID(ctx context.Context, roleName string) (string, error) {
	role, err := s.store.GetAppRole(ctx, roleName)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return "", errors.New("role not found")
		}
		return "", err
	}

	// Generate random secret ID
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating secret ID: %w", err)
	}
	secretID := base64.RawURLEncoding.EncodeToString(raw)
	secretIDHash := hashSecretID(secretID)

	var expiresAt *time.Time
	if role.SecretIDTTL > 0 {
		t := time.Now().Add(role.SecretIDTTL).UTC()
		expiresAt = &t
	}

	secret := &models.AppRoleSecret{
		ID:           newUUID(),
		RoleID:       role.ID,
		SecretIDHash: secretIDHash,
		UsesRemaining: 0, // 0 = unlimited
		ExpiresAt:    expiresAt,
	}

	if err := s.store.WriteAppRoleSecret(ctx, secret); err != nil {
		return "", fmt.Errorf("persisting secret ID: %w", err)
	}
	return secretID, nil
}

// Login validates roleID + secretID and issues a token scoped to the role's policies.
func (s *AppRoleService) Login(ctx context.Context, roleID, secretID string) (*models.Token, string, error) {
	// Look up the role
	role, err := s.store.GetAppRoleByID(ctx, roleID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, "", errors.New("invalid role ID or secret ID")
		}
		return nil, "", err
	}

	// Validate secret ID
	hash := hashSecretID(secretID)
	appSecret, err := s.store.GetAppRoleSecret(ctx, hash)
	if err != nil {
		return nil, "", errors.New("invalid role ID or secret ID")
	}

	// Check expiry
	if appSecret.ExpiresAt != nil && time.Now().After(*appSecret.ExpiresAt) {
		return nil, "", errors.New("secret ID has expired")
	}

	// Check uses
	if appSecret.UsesRemaining > 0 {
		// Will consume below
	} else if appSecret.UsesRemaining < 0 {
		return nil, "", errors.New("secret ID has been exhausted")
	}

	// Ensure the secret belongs to this role
	if appSecret.RoleID != role.ID {
		return nil, "", errors.New("invalid role ID or secret ID")
	}

	// Consume the secret ID
	if err := s.store.ConsumeAppRoleSecret(ctx, hash); err != nil {
		return nil, "", fmt.Errorf("consuming secret ID: %w", err)
	}

	// Issue token
	token, plaintext, err := s.tokens.CreateToken(ctx, "approle:"+role.Name, role.Policies, role.TokenTTL, false, nil)
	if err != nil {
		return nil, "", fmt.Errorf("issuing token: %w", err)
	}
	return token, plaintext, nil
}

func hashSecretID(secretID string) string {
	h := sha256.Sum256([]byte(secretID))
	return hex.EncodeToString(h[:])
}
