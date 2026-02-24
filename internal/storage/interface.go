package storage

import (
	"context"
	"errors"

	"github.com/org/secretvault/pkg/models"
)

// ErrNotFound is returned when a requested resource does not exist.
var ErrNotFound = errors.New("not found")

// ErrAlreadyExists is returned when trying to create a resource that already exists.
var ErrAlreadyExists = errors.New("already exists")

// StorageBackend defines the persistence interface for SecretVault.
type StorageBackend interface {
	// Vault initialization
	InitVault(ctx context.Context, data *models.InitData) error
	GetInitData(ctx context.Context) (*models.InitData, error)
	IsInitialized(ctx context.Context) (bool, error)

	// Secrets
	WriteSecretVersion(ctx context.Context, path string, secretType string, version *models.SecretVersion) error
	ReadSecretVersion(ctx context.Context, path string, version int) (*models.SecretVersion, error)
	ReadLatestSecretVersion(ctx context.Context, path string) (*models.SecretVersion, error)
	ListSecrets(ctx context.Context, prefix string) ([]string, error)
	DeleteSecretVersions(ctx context.Context, path string, versions []int) error
	UndeleteSecretVersions(ctx context.Context, path string, versions []int) error
	DestroySecretVersions(ctx context.Context, path string, versions []int) error
	GetSecretMetadata(ctx context.Context, path string) (*models.SecretMetadata, error)

	// Tokens
	WriteToken(ctx context.Context, token *models.Token) error
	GetToken(ctx context.Context, tokenHash string) (*models.Token, error)
	RevokeToken(ctx context.Context, tokenID string) error
	RevokeTokenChildren(ctx context.Context, parentID string) error
	RenewToken(ctx context.Context, tokenID string, newExpiresAt interface{}) error

	// AppRole
	WriteAppRole(ctx context.Context, role *models.AppRole) error
	GetAppRole(ctx context.Context, name string) (*models.AppRole, error)
	GetAppRoleByID(ctx context.Context, roleID string) (*models.AppRole, error)
	WriteAppRoleSecret(ctx context.Context, secret *models.AppRoleSecret) error
	GetAppRoleSecret(ctx context.Context, secretIDHash string) (*models.AppRoleSecret, error)
	ConsumeAppRoleSecret(ctx context.Context, secretIDHash string) error

	// Policies
	WritePolicy(ctx context.Context, policy *models.Policy) error
	GetPolicy(ctx context.Context, name string) (*models.Policy, error)
	DeletePolicy(ctx context.Context, name string) error
	ListPolicies(ctx context.Context) ([]string, error)

	// Audit
	WriteAuditEntry(ctx context.Context, entry *models.AuditEntry) error
	QueryAuditLog(ctx context.Context, filter AuditFilter) ([]*models.AuditEntry, error)

	// Metrics helpers
	CountSecrets(ctx context.Context) (int64, error)
	CountActiveTokens(ctx context.Context) (int64, error)

	// Lifecycle
	Close()
}

// AuditFilter specifies query parameters for audit log retrieval.
type AuditFilter struct {
	Path     string
	Since    interface{} // *time.Time
	Limit    int
	Offset   int
}
