package models

import "time"

// Capability constants for policy path rules.
const (
	CapRead   = "read"
	CapWrite  = "write"
	CapList   = "list"
	CapDelete = "delete"
	CapSudo   = "sudo"
)

// PathRule defines what capabilities are allowed on a path.
type PathRule struct {
	Capabilities []string `json:"capabilities"`
}

// HasCapability returns true if the path rule grants the given capability.
func (p PathRule) HasCapability(cap string) bool {
	for _, c := range p.Capabilities {
		if c == cap || c == CapSudo {
			return true
		}
	}
	return false
}

// Policy is a named set of path-based access rules.
type Policy struct {
	Name      string               `json:"name"`
	Rules     map[string]PathRule  `json:"path"` // path glob → capabilities
	CreatedAt time.Time            `json:"created_at,omitempty"`
	UpdatedAt time.Time            `json:"updated_at,omitempty"`
}

// AuditEntry records a single request event.
type AuditEntry struct {
	ID             int64
	RequestID      string
	Timestamp      time.Time
	TokenHash      string
	Operation      string
	Path           string
	Status         string
	ResponseCode   int
	ResponseTimeMs int64
	ClientIP       string
	Metadata       map[string]any
}

// InitData holds the vault initialization state stored in the database.
type InitData struct {
	EncryptedRootKeyShares [][]byte // each shard is stored as base64
	KEKContext             string
	InitializedAt          time.Time
}
