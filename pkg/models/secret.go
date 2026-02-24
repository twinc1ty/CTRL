package models

import "time"

// SecretVersion stores one version of an encrypted secret.
type SecretVersion struct {
	ID           int64
	SecretID     int64
	Version      int
	EncryptedDEK []byte
	Ciphertext   []byte
	Nonce        []byte
	CreatedAt    time.Time
	DeletedAt    *time.Time
	Destroyed    bool
}

// VersionInfo is a lightweight summary of one version in metadata responses.
type VersionInfo struct {
	Version   int
	CreatedAt time.Time
	DeletedAt *time.Time
	Destroyed bool
}

// SecretMetadata describes a secret path and its version history.
type SecretMetadata struct {
	Path           string
	Type           string // "kv", "pem", "env"
	CurrentVersion int
	Versions       []VersionInfo
	CreatedAt      time.Time
	UpdatedAt      time.Time
}
