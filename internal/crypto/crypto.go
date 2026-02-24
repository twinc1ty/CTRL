package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

// GenerateRootKey generates a 32-byte cryptographically secure random root key.
func GenerateRootKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generating root key: %w", err)
	}
	return key, nil
}

// DeriveKEK derives a Key Encryption Key from the root key using HKDF-SHA256.
func DeriveKEK(rootKey []byte, context string) ([]byte, error) {
	kek := make([]byte, 32)
	r := hkdf.New(sha256.New, rootKey, nil, []byte(context))
	if _, err := io.ReadFull(r, kek); err != nil {
		return nil, fmt.Errorf("deriving KEK: %w", err)
	}
	return kek, nil
}

// GenerateDEK generates a 32-byte random Data Encryption Key.
func GenerateDEK() ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("generating DEK: %w", err)
	}
	return dek, nil
}

// EncryptAESGCM encrypts plaintext with AES-256-GCM. Returns ciphertext and nonce separately.
func EncryptAESGCM(plaintext, key []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("creating GCM: %w", err)
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generating nonce: %w", err)
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// DecryptAESGCM decrypts AES-256-GCM ciphertext.
func DecryptAESGCM(ciphertext, nonce, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}
	return plaintext, nil
}

// EncryptDEK wraps a DEK with a KEK using AES-256-GCM.
func EncryptDEK(dek, kek []byte) ([]byte, error) {
	ciphertext, nonce, err := EncryptAESGCM(dek, kek)
	if err != nil {
		return nil, fmt.Errorf("encrypting DEK: %w", err)
	}
	// Prepend nonce to ciphertext for storage
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)
	return result, nil
}

// DecryptDEK unwraps an encrypted DEK using a KEK.
func DecryptDEK(encryptedDEK, kek []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(encryptedDEK) < nonceSize {
		return nil, errors.New("encrypted DEK too short")
	}
	nonce := encryptedDEK[:nonceSize]
	ciphertext := encryptedDEK[nonceSize:]
	dek, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting DEK: %w", err)
	}
	return dek, nil
}

// --- Shamir's Secret Sharing ---

// prime is a large prime used as the field modulus for Shamir's SS.
// Using a 256-bit prime that is larger than any 32-byte key.
var prime *big.Int

func init() {
	// 2^256 - 189 is a well-known 256-bit prime
	prime = new(big.Int)
	prime.SetString("115792089237316195423570985008687907853269984665640564039457584007908834671663", 10)
}

// SplitRootKey splits a root key into `shares` shares requiring `threshold` to reconstruct.
func SplitRootKey(key []byte, shares, threshold int) ([][]byte, error) {
	if threshold > shares {
		return nil, errors.New("threshold cannot exceed total shares")
	}
	if threshold < 2 {
		return nil, errors.New("threshold must be at least 2")
	}
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes")
	}

	secret := new(big.Int).SetBytes(key)

	// Generate random polynomial coefficients a_1, ..., a_{t-1}
	// Polynomial: f(x) = secret + a1*x + a2*x^2 + ... + a_{t-1}*x^{t-1}
	coeffs := make([]*big.Int, threshold)
	coeffs[0] = secret
	for i := 1; i < threshold; i++ {
		coeff, err := rand.Int(rand.Reader, prime)
		if err != nil {
			return nil, fmt.Errorf("generating coefficient: %w", err)
		}
		coeffs[i] = coeff
	}

	// Evaluate polynomial at points x = 1, 2, ..., shares
	result := make([][]byte, shares)
	for i := 1; i <= shares; i++ {
		x := big.NewInt(int64(i))
		y := evalPolynomial(coeffs, x)

		yBytes := y.Bytes()
		// Each share: 1 byte index + 4 bytes y-length + y bytes (padded to 33 bytes for the big.Int + index)
		share := encodeShare(i, yBytes)
		result[i-1] = share
	}
	return result, nil
}

// CombineShards reconstructs the root key from threshold or more shards.
func CombineShards(shards [][]byte) ([]byte, error) {
	if len(shards) < 2 {
		return nil, errors.New("need at least 2 shards")
	}

	// Decode shares
	points := make([]shamirPoint, len(shards))
	for i, shard := range shards {
		x, y, err := decodeShare(shard)
		if err != nil {
			return nil, fmt.Errorf("decoding shard %d: %w", i, err)
		}
		points[i] = shamirPoint{big.NewInt(int64(x)), y}
	}

	// Lagrange interpolation at x=0
	secret := lagrangeInterpolate(points)
	if secret == nil {
		return nil, errors.New("failed to reconstruct secret")
	}

	// Pad to 32 bytes
	result := make([]byte, 32)
	b := secret.Bytes()
	if len(b) > 32 {
		return nil, errors.New("reconstructed secret too large")
	}
	copy(result[32-len(b):], b)
	return result, nil
}

func evalPolynomial(coeffs []*big.Int, x *big.Int) *big.Int {
	result := new(big.Int).Set(coeffs[0])
	xPow := new(big.Int).Set(x)
	for i := 1; i < len(coeffs); i++ {
		term := new(big.Int).Mul(coeffs[i], xPow)
		term.Mod(term, prime)
		result.Add(result, term)
		result.Mod(result, prime)
		xPow.Mul(xPow, x)
		xPow.Mod(xPow, prime)
	}
	return result
}

type shamirPoint struct{ x, y *big.Int }

func lagrangeInterpolate(points []shamirPoint) *big.Int {
	secret := big.NewInt(0)
	for i, pi := range points {
		num := big.NewInt(1)
		den := big.NewInt(1)
		for j, pj := range points {
			if i == j {
				continue
			}
			// num *= -pj.x
			neg := new(big.Int).Neg(pj.x)
			num.Mul(num, neg)
			num.Mod(num, prime)
			// den *= (pi.x - pj.x)
			diff := new(big.Int).Sub(pi.x, pj.x)
			den.Mul(den, diff)
			den.Mod(den, prime)
		}
		// lagrange_i = pi.y * num * modInverse(den)
		inv := new(big.Int).ModInverse(den, prime)
		if inv == nil {
			return nil
		}
		term := new(big.Int).Mul(pi.y, num)
		term.Mod(term, prime)
		term.Mul(term, inv)
		term.Mod(term, prime)
		secret.Add(secret, term)
		secret.Mod(secret, prime)
	}
	return secret
}

// encodeShare encodes a share as: [1 byte x-index][4 byte y-length][y-bytes]
func encodeShare(x int, y []byte) []byte {
	buf := make([]byte, 1+4+len(y))
	buf[0] = byte(x)
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(y)))
	copy(buf[5:], y)
	return buf
}

// decodeShare decodes a share encoded by encodeShare.
func decodeShare(share []byte) (int, *big.Int, error) {
	if len(share) < 5 {
		return 0, nil, errors.New("share too short")
	}
	x := int(share[0])
	yLen := binary.BigEndian.Uint32(share[1:5])
	if len(share) < 5+int(yLen) {
		return 0, nil, errors.New("share data truncated")
	}
	y := new(big.Int).SetBytes(share[5 : 5+yLen])
	return x, y, nil
}
