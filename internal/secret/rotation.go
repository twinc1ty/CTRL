package secret

import (
	"context"
	"fmt"

	"github.com/org/secretvault/pkg/models"
)

// Rotate writes a new version of a secret, preserving its history.
// It is equivalent to a Put — the KV engine's versioning handles history automatically.
func (e *KVEngine) Rotate(ctx context.Context, token *models.Token, path string, newData map[string]any) (*models.SecretVersion, error) {
	// Fetch existing metadata to determine current type
	meta, err := e.store.GetSecretMetadata(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("fetching secret metadata for rotation: %w", err)
	}
	return e.Put(ctx, token, path, meta.Type, newData)
}

// RotateWithType writes a new version with an explicit type override.
func (e *KVEngine) RotateWithType(ctx context.Context, token *models.Token, path, secretType string, newData map[string]any) (*models.SecretVersion, error) {
	return e.Put(ctx, token, path, secretType, newData)
}

// LatestVersion returns the current version number for a path.
func (e *KVEngine) LatestVersion(ctx context.Context, token *models.Token, path string) (int, error) {
	meta, err := e.GetMetadata(ctx, token, path)
	if err != nil {
		return 0, err
	}
	return meta.CurrentVersion, nil
}

// PreviousVersionData reads the data from version n-1 of a secret.
func (e *KVEngine) PreviousVersionData(ctx context.Context, token *models.Token, path string) (map[string]any, *models.SecretMetadata, error) {
	meta, err := e.store.GetSecretMetadata(ctx, path)
	if err != nil {
		return nil, nil, err
	}
	if meta.CurrentVersion < 2 {
		return nil, nil, fmt.Errorf("no previous version for %s", path)
	}
	return e.Get(ctx, token, path, meta.CurrentVersion-1)
}
