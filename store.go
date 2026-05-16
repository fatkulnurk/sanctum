package sanctum

import (
	"context"
	"time"
)

type Store[IDType, TokenableIDType comparable] interface {
	Create(ctx context.Context, t *PersonalAccessToken[IDType, TokenableIDType]) error
	FindByToken(ctx context.Context, hashedToken string) (*PersonalAccessToken[IDType, TokenableIDType], error)
	FindByID(ctx context.Context, id IDType) (*PersonalAccessToken[IDType, TokenableIDType], error)
	Delete(ctx context.Context, id IDType) error
	UpdateLastUsedAt(ctx context.Context, id IDType, at time.Time) error
	PruneExpired(ctx context.Context, beforeTime time.Time) (int64, error)
}
