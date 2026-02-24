package core

import (
	"errors"
	"sync"

	"github.com/org/secretvault/internal/crypto"
)

const kekContext = "vault-kek-v1"

// SealManager manages the vault's seal/unseal state.
// The KEK is held in memory only while the vault is unsealed.
type SealManager struct {
	mu            sync.RWMutex
	kek           []byte
	sealed        bool
	threshold     int
	collectedShards [][]byte
}

// NewSealManager creates a new SealManager in sealed state.
func NewSealManager(threshold int) *SealManager {
	return &SealManager{
		sealed:    true,
		threshold: threshold,
	}
}

// IsSealed returns whether the vault is currently sealed.
func (s *SealManager) IsSealed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sealed
}

// ShardsProvided returns how many unseal shards have been provided so far.
func (s *SealManager) ShardsProvided() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.collectedShards)
}

// Threshold returns the unseal threshold.
func (s *SealManager) Threshold() int {
	return s.threshold
}

// Unseal provides one shard toward unsealing. Returns true when the vault is unsealed.
func (s *SealManager) Unseal(shard []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.sealed {
		return true, nil // already unsealed
	}

	// Deduplicate: don't add same shard twice (simple byte equality check)
	for _, existing := range s.collectedShards {
		if string(existing) == string(shard) {
			return false, errors.New("duplicate shard")
		}
	}

	s.collectedShards = append(s.collectedShards, shard)

	if len(s.collectedShards) < s.threshold {
		return false, nil // still need more shards
	}

	// Reconstruct root key
	rootKey, err := crypto.CombineShards(s.collectedShards)
	if err != nil {
		s.collectedShards = nil
		return false, errors.New("failed to reconstruct root key from shards")
	}

	// Derive KEK
	kek, err := crypto.DeriveKEK(rootKey, kekContext)
	if err != nil {
		s.collectedShards = nil
		return false, errors.New("failed to derive KEK")
	}

	s.kek = kek
	s.sealed = false
	s.collectedShards = nil // clear shards from memory
	return true, nil
}

// Seal wipes the KEK from memory, sealing the vault.
func (s *SealManager) Seal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Zero out KEK
	for i := range s.kek {
		s.kek[i] = 0
	}
	s.kek = nil
	s.sealed = true
	s.collectedShards = nil
}

// KEK returns the current KEK. Returns an error if sealed.
func (s *SealManager) KEK() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.sealed {
		return nil, errors.New("vault is sealed")
	}
	kekCopy := make([]byte, len(s.kek))
	copy(kekCopy, s.kek)
	return kekCopy, nil
}

// UnsealWithRootKey directly unseals using the raw root key (used during init).
func (s *SealManager) UnsealWithRootKey(rootKey []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	kek, err := crypto.DeriveKEK(rootKey, kekContext)
	if err != nil {
		return err
	}
	s.kek = kek
	s.sealed = false
	s.collectedShards = nil
	return nil
}
