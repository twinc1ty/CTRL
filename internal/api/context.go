package api

import (
	"context"

	"github.com/org/secretvault/pkg/models"
)

type contextKey string

const (
	ctxKeyToken     contextKey = "token"
	ctxKeyRequestID contextKey = "request_id"
)

func withToken(ctx context.Context, t *models.Token) context.Context {
	return context.WithValue(ctx, ctxKeyToken, t)
}

func tokenFromCtx(ctx context.Context) *models.Token {
	t, _ := ctx.Value(ctxKeyToken).(*models.Token)
	return t
}

func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKeyRequestID, id)
}

func requestIDFromCtx(ctx context.Context) string {
	id, _ := ctx.Value(ctxKeyRequestID).(string)
	return id
}
