package models

import "time"

// Token represents an auth token.
type Token struct {
	ID          string
	DisplayName string
	Policies    []string
	TTL         time.Duration
	Renewable   bool
	CreatedAt   time.Time
	ExpiresAt   time.Time
	RevokedAt   *time.Time
	ParentID    *string
}

// IsExpired returns true if the token has passed its expiry time.
func (t *Token) IsExpired() bool {
	return !t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt)
}

// IsRevoked returns true if the token has been revoked.
func (t *Token) IsRevoked() bool {
	return t.RevokedAt != nil
}

// AppRole represents an AppRole authentication role.
type AppRole struct {
	ID          string
	Name        string
	Policies    []string
	SecretIDTTL time.Duration
	TokenTTL    time.Duration
	CreatedAt   time.Time
}

// AppRoleSecret represents a generated secret ID for an AppRole.
type AppRoleSecret struct {
	ID             string
	RoleID         string
	SecretIDHash   string
	UsesRemaining  int
	ExpiresAt      *time.Time
	UsedAt         *time.Time
}
