package secret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/org/secretvault/internal/core"
	"github.com/org/secretvault/internal/crypto"
	"github.com/org/secretvault/internal/policy"
	"github.com/org/secretvault/internal/storage"
	"github.com/org/secretvault/pkg/models"
)

// KVEngine implements a versioned KV secret store.
type KVEngine struct {
	store  storage.StorageBackend
	seal   *core.SealManager
	policy *policy.Engine
}

// NewKVEngine creates a KVEngine.
func NewKVEngine(store storage.StorageBackend, seal *core.SealManager, pol *policy.Engine) *KVEngine {
	return &KVEngine{store: store, seal: seal, policy: pol}
}

// Put stores a new version of a secret at path.
func (e *KVEngine) Put(ctx context.Context, token *models.Token, path, secretType string, data map[string]any) (*models.SecretVersion, error) {
	if err := e.checkPolicy(ctx, token, models.CapWrite, "secret/data/"+path); err != nil {
		return nil, err
	}
	if e.seal.IsSealed() {
		return nil, errors.New("vault is sealed")
	}

	kek, err := e.seal.KEK()
	if err != nil {
		return nil, err
	}
	defer zeroBytes(kek)

	// Serialize data
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshaling secret data: %w", err)
	}

	// Generate DEK
	dek, err := crypto.GenerateDEK()
	if err != nil {
		return nil, err
	}
	defer zeroBytes(dek)

	// Encrypt data with DEK
	ciphertext, nonce, err := crypto.EncryptAESGCM(plaintext, dek)
	if err != nil {
		return nil, fmt.Errorf("encrypting secret: %w", err)
	}

	// Wrap DEK with KEK
	encDEK, err := crypto.EncryptDEK(dek, kek)
	if err != nil {
		return nil, fmt.Errorf("wrapping DEK: %w", err)
	}

	v := &models.SecretVersion{
		EncryptedDEK: encDEK,
		Ciphertext:   ciphertext,
		Nonce:        nonce,
		CreatedAt:    time.Now().UTC(),
	}

	if err := e.store.WriteSecretVersion(ctx, path, secretType, v); err != nil {
		return nil, fmt.Errorf("storing secret version: %w", err)
	}
	return v, nil
}

// Get retrieves a secret version. version=0 means latest.
func (e *KVEngine) Get(ctx context.Context, token *models.Token, path string, version int) (map[string]any, *models.SecretMetadata, error) {
	if err := e.checkPolicy(ctx, token, models.CapRead, "secret/data/"+path); err != nil {
		return nil, nil, err
	}
	if e.seal.IsSealed() {
		return nil, nil, errors.New("vault is sealed")
	}

	kek, err := e.seal.KEK()
	if err != nil {
		return nil, nil, err
	}
	defer zeroBytes(kek)

	var sv *models.SecretVersion
	if version == 0 {
		sv, err = e.store.ReadLatestSecretVersion(ctx, path)
	} else {
		sv, err = e.store.ReadSecretVersion(ctx, path, version)
	}
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, nil, fmt.Errorf("secret not found: %s", path)
		}
		return nil, nil, err
	}

	if sv.Destroyed {
		return nil, nil, errors.New("secret version has been destroyed")
	}
	if sv.DeletedAt != nil {
		return nil, nil, errors.New("secret version has been deleted")
	}

	// Unwrap DEK
	dek, err := crypto.DecryptDEK(sv.EncryptedDEK, kek)
	if err != nil {
		return nil, nil, fmt.Errorf("unwrapping DEK: %w", err)
	}
	defer zeroBytes(dek)

	// Decrypt data
	plaintext, err := crypto.DecryptAESGCM(sv.Ciphertext, sv.Nonce, dek)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypting secret: %w", err)
	}

	var data map[string]any
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, nil, fmt.Errorf("deserializing secret: %w", err)
	}

	meta, err := e.store.GetSecretMetadata(ctx, path)
	if err != nil {
		meta = &models.SecretMetadata{Path: path}
	}
	return data, meta, nil
}

// List lists secrets under a prefix.
func (e *KVEngine) List(ctx context.Context, token *models.Token, prefix string) ([]string, error) {
	if err := e.checkPolicy(ctx, token, models.CapList, "secret/metadata/"+prefix); err != nil {
		return nil, err
	}
	return e.store.ListSecrets(ctx, prefix)
}

// Delete soft-deletes specific versions of a secret.
func (e *KVEngine) Delete(ctx context.Context, token *models.Token, path string, versions []int) error {
	if err := e.checkPolicy(ctx, token, models.CapDelete, "secret/data/"+path); err != nil {
		return err
	}
	return e.store.DeleteSecretVersions(ctx, path, versions)
}

// Undelete restores soft-deleted versions.
func (e *KVEngine) Undelete(ctx context.Context, token *models.Token, path string, versions []int) error {
	if err := e.checkPolicy(ctx, token, models.CapWrite, "secret/data/"+path); err != nil {
		return err
	}
	return e.store.UndeleteSecretVersions(ctx, path, versions)
}

// Destroy permanently wipes a secret version (DEK + ciphertext).
func (e *KVEngine) Destroy(ctx context.Context, token *models.Token, path string, versions []int) error {
	if err := e.checkPolicy(ctx, token, models.CapDelete, "secret/destroy/"+path); err != nil {
		return err
	}
	return e.store.DestroySecretVersions(ctx, path, versions)
}

// GetMetadata returns secret metadata without decrypting.
func (e *KVEngine) GetMetadata(ctx context.Context, token *models.Token, path string) (*models.SecretMetadata, error) {
	if err := e.checkPolicy(ctx, token, models.CapRead, "secret/metadata/"+path); err != nil {
		return nil, err
	}
	return e.store.GetSecretMetadata(ctx, path)
}

func (e *KVEngine) checkPolicy(ctx context.Context, token *models.Token, capability, path string) error {
	if !e.policy.IsAllowed(ctx, token.Policies, capability, path) {
		return fmt.Errorf("permission denied: %s on %s", capability, path)
	}
	return nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
