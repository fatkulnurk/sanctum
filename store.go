package sanctum

import (
	"context"
	"time"
)

type Store[IDType, TokenableIDType comparable] interface {
	Create(ctx context.Context, t *PersonalAccessToken[IDType, TokenableIDType]) error
	FindByToken(ctx context.Context, hashedToken string) (*PersonalAccessToken[IDType, TokenableIDType], error)
	FindByID(ctx context.Context, id string) (*PersonalAccessToken[IDType, TokenableIDType], error)
	Delete(ctx context.Context, id IDType) error
	UpdateLastUsedAt(ctx context.Context, id IDType, at time.Time) error
}
