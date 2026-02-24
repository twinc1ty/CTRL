package secret

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"github.com/org/secretvault/pkg/models"
)

// PEMFields are the standard keys for a PEM secret.
const (
	PEMFieldCertificate = "certificate"
	PEMFieldPrivateKey  = "private_key"
	PEMFieldCAChain     = "ca_chain"
	PEMFieldExpiresAt   = "expires_at"
)

// PEMEngine wraps KVEngine with PEM-specific helpers.
type PEMEngine struct {
	kv *KVEngine
}

// NewPEMEngine creates a PEMEngine.
func NewPEMEngine(kv *KVEngine) *PEMEngine {
	return &PEMEngine{kv: kv}
}

// Put stores a PEM secret. If certificate is provided, expires_at is parsed automatically.
func (e *PEMEngine) Put(ctx context.Context, token *models.Token, path, cert, privateKey, caChain string) error {
	data := map[string]any{
		PEMFieldCertificate: cert,
		PEMFieldPrivateKey:  privateKey,
		PEMFieldCAChain:     caChain,
	}

	// Auto-parse expiry from cert
	if cert != "" {
		if expiry, err := parseCertExpiry(cert); err == nil {
			data[PEMFieldExpiresAt] = expiry.UTC().Format(time.RFC3339)
		}
	}

	_, err := e.kv.Put(ctx, token, path, "pem", data)
	return err
}

// Get retrieves a PEM secret.
func (e *PEMEngine) Get(ctx context.Context, token *models.Token, path string, version int) (cert, privateKey, caChain string, expiresAt *time.Time, err error) {
	data, _, err := e.kv.Get(ctx, token, path, version)
	if err != nil {
		return "", "", "", nil, err
	}
	cert, _ = data[PEMFieldCertificate].(string)
	privateKey, _ = data[PEMFieldPrivateKey].(string)
	caChain, _ = data[PEMFieldCAChain].(string)
	if expStr, ok := data[PEMFieldExpiresAt].(string); ok {
		t, err := time.Parse(time.RFC3339, expStr)
		if err == nil {
			expiresAt = &t
		}
	}
	return
}

// parseCertExpiry extracts NotAfter from the first PEM certificate block.
func parseCertExpiry(pemData string) (time.Time, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return time.Time{}, errors.New("no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}
