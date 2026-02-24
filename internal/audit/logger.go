package audit

import (
	"context"
	"time"

	"github.com/org/secretvault/internal/storage"
	"github.com/org/secretvault/pkg/models"
)

// Logger writes structured audit entries.
type Logger struct {
	store storage.StorageBackend
}

// NewLogger creates an audit Logger.
func NewLogger(store storage.StorageBackend) *Logger {
	return &Logger{store: store}
}

// LogRequest records an API request to the audit log.
// Secret values must NEVER be passed here — only metadata.
func (l *Logger) LogRequest(ctx context.Context, entry *models.AuditEntry) {
	entry.Timestamp = time.Now().UTC()
	// Fire and forget — audit failures should not break request flow,
	// but in production you may want to fail-closed.
	_ = l.store.WriteAuditEntry(ctx, entry)
}

// Query retrieves paginated audit log entries.
func (l *Logger) Query(ctx context.Context, filter storage.AuditFilter) ([]*models.AuditEntry, error) {
	return l.store.QueryAuditLog(ctx, filter)
}
