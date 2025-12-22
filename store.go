package sanctum

import (
	"context"
	"time"
)

type Store[IDType, TokenableIDType comparable] interface {
	Create(ctx context.Context, t *Token[IDType, TokenableIDType]) error
	FindByToken(ctx context.Context, hashedToken string) (*Token[IDType, TokenableIDType], error)
	FindByID(ctx context.Context, id string) (*Token[IDType, TokenableIDType], error)
	UpdateLastUsedAt(ctx context.Context, id IDType, at time.Time) error
}
