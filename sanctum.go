package sanctum

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Manager interface {
	CreateToken(
		ctx context.Context,
		tokenableID string,
		tokenableType string,
		name string,
		abilities []string,
		expiresAt *time.Time,
	) (*AccessToken, error)

	// FindToken retrieves and validates a token from raw input (plain or "id|plain").
	FindToken(ctx context.Context, rawToken string) (*PersonalAccessToken[string, string], error)

	// RevokeToken deletes a token by its ID.
	RevokeToken(ctx context.Context, tokenID string) error
}

type Config struct {
	Prefix          string
	IsAutoIncrement bool
}

type Sanctum struct {
	cfg   Config
	store Store[string, string]
}

func NewSanctum(cfg Config, store Store[string, string]) Manager {
	return &Sanctum{
		cfg:   cfg,
		store: store,
	}
}

// FindToken retrieves token by raw input (plain or "id|plain" format)
func (s Sanctum) FindToken(ctx context.Context, rawInput string) (*PersonalAccessToken[string, string], error) {
	if rawInput == "" {
		return nil, ErrInvalidToken
	}

	now := time.Now()

	idx := strings.Index(rawInput, "|")
	if idx != -1 {
		// plain token only, example "abc"
		hashed := HashToken(rawInput)
		token, err := s.store.FindByToken(ctx, hashed)
		if err != nil || token == nil {
			return nil, ErrInvalidToken
		}

		// Explicit expiration check (defense in depth)
		if token.ExpiresAt != nil && token.ExpiresAt.Before(now) {
			return nil, ErrTokenExpired
		}

		return token, nil
	}

	// format: "id|plain", example: "1|abc...."
	id := rawInput[:idx]
	plain := rawInput[idx+1:]

	token, err := s.store.FindByID(ctx, id)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Explicit expiration check (defense in depth)
	if token.ExpiresAt != nil && token.ExpiresAt.Before(now) {
		return nil, ErrTokenExpired
	}

	// compares two hex-encoded hashes in constant time.
	isHashValid := subtle.ConstantTimeCompare([]byte(token.Token), []byte(HashToken(plain))) == 1
	if !isHashValid {
		return nil, ErrInvalidToken
	}

	return token, nil
}

func (s Sanctum) CreateToken(ctx context.Context, tokenableID string, tokenableType string, name string, abilities []string, expiresAt *time.Time) (*AccessToken, error) {
	plain, err := GenerateToken(s.cfg.Prefix)
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	hashed := HashToken(plain)
	tokenID := ""
	if !s.cfg.IsAutoIncrement {
		tokenID = uuid.NewString()
	}

	token := &PersonalAccessToken[string, string]{
		ID:            tokenID,
		TokenableID:   tokenableID,
		TokenableType: tokenableType,
		Name:          name,
		Token:         hashed,
		Abilities:     Abilities(abilities),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     expiresAt,
	}

	if err := s.store.Create(ctx, token); err != nil {
		return nil, fmt.Errorf("store token: %w", err)
	}

	hashedToken := fmt.Sprintf("%s|%s", token.ID, hashed)
	plainTextToken := fmt.Sprintf("%s|%s", token.ID, plain)

	return &AccessToken{
		AccessToken:    hashedToken,
		PlainTextToken: plainTextToken,
	}, nil
}

func (s Sanctum) RevokeToken(ctx context.Context, tokenID string) error {
	return s.store.Delete(ctx, tokenID)
}
