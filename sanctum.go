package sanctum

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Manager[IDType, TokenableIDType comparable] interface {
	CreateToken(
		ctx context.Context,
		tokenableID TokenableIDType,
		tokenableType string,
		name string,
		abilities []string,
		expiresAt *time.Time,
	) (*NewAccessToken[IDType, TokenableIDType], error)

	FindToken(ctx context.Context, rawToken string) (*PersonalAccessToken[IDType, TokenableIDType], error)
	RevokeToken(ctx context.Context, id IDType) error
	PruneExpired(ctx context.Context, hours int) error

	TokenCan(token *PersonalAccessToken[IDType, TokenableIDType], ability string) bool
	TokenCant(token *PersonalAccessToken[IDType, TokenableIDType], ability string) bool
	CheckAbilities(token HasAbilities, abilities ...string) error
	CheckForAnyAbility(token HasAbilities, abilities ...string) error

	SetTokenRetrievalCallback(callback func(ctx context.Context, rawToken string) (string, error))
	SetTokenAuthCallback(callback func(token *PersonalAccessToken[IDType, TokenableIDType], isValid bool) (bool, error))
}

type Config struct {
	Prefix          string
	IsAutoIncrement bool
	Expiration      *time.Duration
}

type Sanctum[IDType, TokenableIDType comparable] struct {
	cfg      Config
	store    Store[IDType, TokenableIDType]
	parseID  func(string) (IDType, error)
	idGen    func() IDType
	getToken func(ctx context.Context, rawToken string) (string, error)
	authCB   func(token *PersonalAccessToken[IDType, TokenableIDType], isValid bool) (bool, error)
}

func NewSanctum[IDType, TokenableIDType comparable](
	cfg Config,
	store Store[IDType, TokenableIDType],
	parseID func(string) (IDType, error),
	idGen func() IDType,
) *Sanctum[IDType, TokenableIDType] {
	return &Sanctum[IDType, TokenableIDType]{
		cfg:     cfg,
		store:   store,
		parseID: parseID,
		idGen:   idGen,
	}
}

func NewSanctumWithUUID(cfg Config, store Store[string, string]) *Sanctum[string, string] {
	return NewSanctum(cfg, store,
		func(s string) (string, error) { return s, nil },
		func() string { return uuid.NewString() },
	)
}

func NewSanctumWithAutoIncrement(cfg Config, store Store[string, string]) *Sanctum[string, string] {
	return NewSanctum(cfg, store,
		func(s string) (string, error) { return s, nil },
		nil,
	)
}

func (s *Sanctum[IDType, TokenableIDType]) SetTokenRetrievalCallback(callback func(ctx context.Context, rawToken string) (string, error)) {
	s.getToken = callback
}

func (s *Sanctum[IDType, TokenableIDType]) SetTokenAuthCallback(callback func(token *PersonalAccessToken[IDType, TokenableIDType], isValid bool) (bool, error)) {
	s.authCB = callback
}

func (s *Sanctum[IDType, TokenableIDType]) CreateToken(
	ctx context.Context,
	tokenableID TokenableIDType,
	tokenableType string,
	name string,
	abilities []string,
	expiresAt *time.Time,
) (*NewAccessToken[IDType, TokenableIDType], error) {
	plain, err := GenerateToken(s.cfg.Prefix)
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	hashed := HashToken(plain)
	now := time.Now()

	var tokenID IDType
	if !s.cfg.IsAutoIncrement && s.idGen != nil {
		tokenID = s.idGen()
	}

	token := &PersonalAccessToken[IDType, TokenableIDType]{
		ID:            tokenID,
		TokenableID:   tokenableID,
		TokenableType: tokenableType,
		Name:          name,
		Token:         hashed,
		Abilities:     Abilities(abilities),
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     expiresAt,
	}

	if err := s.store.Create(ctx, token); err != nil {
		return nil, fmt.Errorf("store token: %w", err)
	}

	plainTextToken := fmt.Sprintf("%v|%s", token.ID, plain)

	return &NewAccessToken[IDType, TokenableIDType]{
		AccessToken:    token,
		PlainTextToken: plainTextToken,
	}, nil
}

func (s *Sanctum[IDType, TokenableIDType]) FindToken(ctx context.Context, rawInput string) (*PersonalAccessToken[IDType, TokenableIDType], error) {
	if rawInput == "" {
		return nil, ErrInvalidToken
	}

	if s.getToken != nil {
		var err error
		rawInput, err = s.getToken(ctx, rawInput)
		if err != nil {
			return nil, ErrInvalidToken
		}
	}

	now := time.Now()

	idx := strings.Index(rawInput, "|")
	if idx == -1 {
		hashed := HashToken(rawInput)
		token, err := s.store.FindByToken(ctx, hashed)
		if err != nil || token == nil {
			return nil, ErrInvalidToken
		}

		if err := s.checkExpiration(token, now); err != nil {
			return nil, err
		}

		if !s.isValidAccessToken(token) {
			return nil, ErrInvalidToken
		}

		_ = s.store.UpdateLastUsedAt(ctx, token.ID, now)
		return token, nil
	}

	idStr := rawInput[:idx]
	plain := rawInput[idx+1:]

	id, err := s.parseID(idStr)
	if err != nil {
		return nil, ErrInvalidToken
	}

	token, err := s.store.FindByID(ctx, id)
	if err != nil || token == nil {
		return nil, ErrInvalidToken
	}

	if err := s.checkExpiration(token, now); err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare([]byte(token.Token), []byte(HashToken(plain))) != 1 {
		return nil, ErrInvalidToken
	}

	if !s.isValidAccessToken(token) {
		return nil, ErrInvalidToken
	}

	_ = s.store.UpdateLastUsedAt(ctx, token.ID, now)
	return token, nil
}

func (s *Sanctum[IDType, TokenableIDType]) RevokeToken(ctx context.Context, id IDType) error {
	return s.store.Delete(ctx, id)
}

func (s *Sanctum[IDType, TokenableIDType]) PruneExpired(ctx context.Context, hours int) error {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	if s.cfg.Expiration != nil {
		globalCutoff := time.Now().Add(-(*s.cfg.Expiration))
		if globalCutoff.Before(cutoff) {
			cutoff = globalCutoff
		}
	}

	_, err := s.store.PruneExpired(ctx, cutoff)
	return err
}

func (s *Sanctum[IDType, TokenableIDType]) TokenCan(token *PersonalAccessToken[IDType, TokenableIDType], ability string) bool {
	return token.Can(ability)
}

func (s *Sanctum[IDType, TokenableIDType]) TokenCant(token *PersonalAccessToken[IDType, TokenableIDType], ability string) bool {
	return token.Cant(ability)
}

func (s *Sanctum[IDType, TokenableIDType]) CheckAbilities(token HasAbilities, abilities ...string) error {
	for _, ability := range abilities {
		if !token.Can(ability) {
			return &MissingAbilityError{Abilities: []string{ability}}
		}
	}
	return nil
}

func (s *Sanctum[IDType, TokenableIDType]) CheckForAnyAbility(token HasAbilities, abilities ...string) error {
	for _, ability := range abilities {
		if token.Can(ability) {
			return nil
		}
	}
	return &MissingAbilityError{Abilities: abilities}
}

func (s *Sanctum[IDType, TokenableIDType]) checkExpiration(token *PersonalAccessToken[IDType, TokenableIDType], now time.Time) error {
	if token.ExpiresAt != nil && token.ExpiresAt.Before(now) {
		return ErrTokenExpired
	}

	if s.cfg.Expiration != nil {
		expirationCutoff := token.CreatedAt.Add(*s.cfg.Expiration)
		if now.After(expirationCutoff) {
			return ErrTokenExpired
		}
	}

	return nil
}

func (s *Sanctum[IDType, TokenableIDType]) isValidAccessToken(token *PersonalAccessToken[IDType, TokenableIDType]) bool {
	if s.authCB == nil {
		return true
	}
	valid, err := s.authCB(token, true)
	if err != nil {
		return false
	}
	return valid
}
