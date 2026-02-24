package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateRootKey(t *testing.T) {
	key, err := GenerateRootKey()
	if err != nil {
		t.Fatalf("GenerateRootKey failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(key))
	}
	// Keys should be random
	key2, _ := GenerateRootKey()
	if bytes.Equal(key, key2) {
		t.Error("two root keys should not be equal")
	}
}

func TestDeriveKEK(t *testing.T) {
	root, _ := GenerateRootKey()
	kek, err := DeriveKEK(root, "vault-kek-v1")
	if err != nil {
		t.Fatalf("DeriveKEK failed: %v", err)
	}
	if len(kek) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(kek))
	}
	// Same inputs → same KEK (deterministic)
	kek2, _ := DeriveKEK(root, "vault-kek-v1")
	if !bytes.Equal(kek, kek2) {
		t.Error("KEK derivation should be deterministic")
	}
	// Different context → different KEK
	kek3, _ := DeriveKEK(root, "vault-kek-v2")
	if bytes.Equal(kek, kek3) {
		t.Error("different contexts should yield different KEKs")
	}
}

func TestGenerateDEK(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK failed: %v", err)
	}
	if len(dek) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(dek))
	}
}

func TestAESGCMRoundTrip(t *testing.T) {
	key, _ := GenerateRootKey()
	plaintext := []byte("super secret value 12345")

	ciphertext, nonce, err := EncryptAESGCM(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptAESGCM failed: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted, err := DecryptAESGCM(ciphertext, nonce, key)
	if err != nil {
		t.Fatalf("DecryptAESGCM failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted %q != original %q", decrypted, plaintext)
	}
}

func TestAESGCMWrongKey(t *testing.T) {
	key, _ := GenerateRootKey()
	wrongKey, _ := GenerateRootKey()
	plaintext := []byte("secret data")

	ciphertext, nonce, _ := EncryptAESGCM(plaintext, key)
	_, err := DecryptAESGCM(ciphertext, nonce, wrongKey)
	if err == nil {
		t.Error("expected error decrypting with wrong key")
	}
}

func TestDEKWrapping(t *testing.T) {
	kek, _ := DeriveKEK([]byte("rootkey_rootkey_rootkey_rootkey_!"), "kek")
	dek, _ := GenerateDEK()

	encDEK, err := EncryptDEK(dek, kek)
	if err != nil {
		t.Fatalf("EncryptDEK failed: %v", err)
	}

	decDEK, err := DecryptDEK(encDEK, kek)
	if err != nil {
		t.Fatalf("DecryptDEK failed: %v", err)
	}
	if !bytes.Equal(dek, decDEK) {
		t.Error("decrypted DEK should match original")
	}
}

func TestShamirSplitCombine(t *testing.T) {
	key, _ := GenerateRootKey()

	shards, err := SplitRootKey(key, 5, 3)
	if err != nil {
		t.Fatalf("SplitRootKey failed: %v", err)
	}
	if len(shards) != 5 {
		t.Errorf("expected 5 shards, got %d", len(shards))
	}

	// Reconstruct with exactly threshold shards
	reconstructed, err := CombineShards(shards[:3])
	if err != nil {
		t.Fatalf("CombineShards failed: %v", err)
	}
	if !bytes.Equal(key, reconstructed) {
		t.Errorf("reconstructed key %x != original %x", reconstructed, key)
	}

	// Reconstruct with all 5 shards
	reconstructed2, err := CombineShards(shards)
	if err != nil {
		t.Fatalf("CombineShards (5 shards) failed: %v", err)
	}
	if !bytes.Equal(key, reconstructed2) {
		t.Error("reconstruction with all shards should match original")
	}

	// Different threshold combinations
	for _, combo := range [][]int{{0, 2, 4}, {1, 3, 4}, {0, 1, 2}} {
		subset := make([][]byte, len(combo))
		for i, idx := range combo {
			subset[i] = shards[idx]
		}
		r, err := CombineShards(subset)
		if err != nil {
			t.Fatalf("CombineShards combo %v failed: %v", combo, err)
		}
		if !bytes.Equal(key, r) {
			t.Errorf("combo %v: reconstructed key doesn't match original", combo)
		}
	}
}

func TestShamirInsufficientShards(t *testing.T) {
	key, _ := GenerateRootKey()
	shards, _ := SplitRootKey(key, 5, 3)

	// With only 2 shards (below threshold of 3), result should be wrong
	wrong, err := CombineShards(shards[:2])
	// No error per se — Lagrange interpolation will produce a value, just wrong
	if err == nil && bytes.Equal(wrong, key) {
		t.Error("2 shards below threshold should not reconstruct the key")
	}
}

func TestFullEnvelopeEncryption(t *testing.T) {
	// Simulate the full envelope encryption flow
	rootKey, _ := GenerateRootKey()
	kek, _ := DeriveKEK(rootKey, "vault-kek-v1")
	dek, _ := GenerateDEK()

	secretData := []byte(`{"password":"hunter2","api_key":"abc123"}`)

	// Encrypt secret with DEK
	ciphertext, nonce, err := EncryptAESGCM(secretData, dek)
	if err != nil {
		t.Fatalf("encrypting secret: %v", err)
	}

	// Wrap DEK with KEK
	encDEK, err := EncryptDEK(dek, kek)
	if err != nil {
		t.Fatalf("wrapping DEK: %v", err)
	}

	// --- Decryption path ---
	// Unwrap DEK
	decDEK, err := DecryptDEK(encDEK, kek)
	if err != nil {
		t.Fatalf("unwrapping DEK: %v", err)
	}

	// Decrypt secret
	plaintext, err := DecryptAESGCM(ciphertext, nonce, decDEK)
	if err != nil {
		t.Fatalf("decrypting secret: %v", err)
	}

	if !bytes.Equal(plaintext, secretData) {
		t.Errorf("plaintext mismatch: got %q want %q", plaintext, secretData)
	}
}
