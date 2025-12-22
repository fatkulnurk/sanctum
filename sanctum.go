package sanctum

import (
	"context"
	"crypto/subtle"
	"strings"
	"time"
)

type Sanctum struct {
	Store Store[string, string]
}

func NewSanctum(store Store[string, string]) *Sanctum {
	return &Sanctum{
		Store: store,
	}
}

// FindToken retrieves token by raw input (plain or "id|plain" format)
func (s Sanctum) FindToken(ctx context.Context, rawInput string) (*Token[string, string], error) {
	if rawInput == "" {
		return nil, ErrInvalidToken
	}

	now := time.Now()

	idx := strings.Index(rawInput, "|")
	if idx != -1 {
		// plain token only, example "abc"
		hashed := HashToken(rawInput)
		token, err := s.Store.FindByToken(ctx, hashed)
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

	token, err := s.Store.FindByID(ctx, id)
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
