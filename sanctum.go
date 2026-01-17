package sanctum

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type HasApiTokens interface {
	TokenCan(ability string) bool
	TokenCant(ability string) bool
	CurrentAccessToken() HasAbilities
	WithAccessToken(token HasAbilities)
}

type HasApiTokensImpl[IDType, TokenableIDType comparable] struct {
	sanctum  *Sanctum[IDType, TokenableIDType]
	ctx      context.Context
	token    HasAbilities
	userID   TokenableIDType
	userType string
}

func NewHasApiTokens[IDType, TokenableIDType comparable](
	s *Sanctum[IDType, TokenableIDType],
	ctx context.Context,
	userID TokenableIDType,
	userType string,
) *HasApiTokensImpl[IDType, TokenableIDType] {
	return &HasApiTokensImpl[IDType, TokenableIDType]{
		sanctum:  s,
		ctx:      ctx,
		userID:   userID,
		userType: userType,
	}
}

func (h *HasApiTokensImpl[IDType, TokenableIDType]) CreateToken(
	name string,
	abilities []string,
	expiresAt *time.Time,
) (*NewAccessToken[IDType, TokenableIDType], error) {
	return h.sanctum.CreateToken(h.ctx, h.userID, h.userType, name, abilities, expiresAt)
}

func (h *HasApiTokensImpl[IDType, TokenableIDType]) TokenCan(ability string) bool {
	return h.token != nil && h.token.Can(ability)
}

func (h *HasApiTokensImpl[IDType, TokenableIDType]) TokenCant(ability string) bool {
	return !h.TokenCan(ability)
}

func (h *HasApiTokensImpl[IDType, TokenableIDType]) CurrentAccessToken() HasAbilities {
	return h.token
}

func (h *HasApiTokensImpl[IDType, TokenableIDType]) WithAccessToken(token HasAbilities) {
	h.token = token
}

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
	CheckScopes(token HasAbilities, scopes ...string) error
	CheckForAnyScope(token HasAbilities, scopes ...string) error

	IsValidBearerToken(token string) bool

	SetTokenRetrievalCallback(callback func(ctx context.Context, rawToken string) (string, error))
	SetTokenAuthCallback(callback func(token *PersonalAccessToken[IDType, TokenableIDType], isValid bool) (bool, error))
}

type Config struct {
	Prefix          string
	IsAutoIncrement bool
	Expiration      *time.Duration
	ProviderModel   string
}

type TokenAuthenticatedHandler[IDType, TokenableIDType comparable] func(ctx context.Context, token *PersonalAccessToken[IDType, TokenableIDType])

type Sanctum[IDType, TokenableIDType comparable] struct {
	cfg              Config
	store            Store[IDType, TokenableIDType]
	parseID          func(string) (IDType, error)
	idGen            func() IDType
	getToken         func(ctx context.Context, rawToken string) (string, error)
	authCB           func(token *PersonalAccessToken[IDType, TokenableIDType], isValid bool) (bool, error)
	onAuthenticated  TokenAuthenticatedHandler[IDType, TokenableIDType]
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
	cfg.IsAutoIncrement = true
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

func (s *Sanctum[IDType, TokenableIDType]) OnTokenAuthenticated(handler TokenAuthenticatedHandler[IDType, TokenableIDType]) {
	s.onAuthenticated = handler
}

func (s *Sanctum[IDType, TokenableIDType]) IsValidBearerToken(token string) bool {
	if token == "" {
		return false
	}
	if idx := strings.Index(token, "|"); idx != -1 {
		if s.cfg.IsAutoIncrement {
			idStr := token[:idx]
			for _, c := range idStr {
				if c < '0' || c > '9' {
					return false
				}
			}
		}
		return token[idx+1:] != ""
	}
	return token != ""
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

	if !s.IsValidBearerToken(rawInput) {
		return nil, ErrInvalidToken
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

		if err := s.checkProvider(token); err != nil {
			return nil, err
		}

		if s.onAuthenticated != nil {
			s.onAuthenticated(ctx, token)
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

	if err := s.checkProvider(token); err != nil {
		return nil, err
	}

	if s.onAuthenticated != nil {
		s.onAuthenticated(ctx, token)
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

func (s *Sanctum[IDType, TokenableIDType]) CheckScopes(token HasAbilities, scopes ...string) error {
	if err := s.CheckAbilities(token, scopes...); err != nil {
		if _, ok := err.(*MissingAbilityError); ok {
			return &MissingScopeError{Scopes: scopes}
		}
		return err
	}
	return nil
}

func (s *Sanctum[IDType, TokenableIDType]) CheckForAnyScope(token HasAbilities, scopes ...string) error {
	if err := s.CheckForAnyAbility(token, scopes...); err != nil {
		if _, ok := err.(*MissingAbilityError); ok {
			return &MissingScopeError{Scopes: scopes}
		}
		return err
	}
	return nil
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

func (s *Sanctum[IDType, TokenableIDType]) checkProvider(token *PersonalAccessToken[IDType, TokenableIDType]) error {
	if s.cfg.ProviderModel == "" {
		return nil
	}
	if token.TokenableType != s.cfg.ProviderModel {
		return ErrInvalidToken
	}
	return nil
}

type MockToken struct {
	Abilities []string
}

func (m *MockToken) Can(ability string) bool {
	for _, a := range m.Abilities {
		if a == "*" || a == ability {
			return true
		}
	}
	return false
}

func (m *MockToken) Cant(ability string) bool {
	return !m.Can(ability)
}

func ActingAs(tokenable HasApiTokens, abilities []string) HasAbilities {
	if len(abilities) == 1 && abilities[0] == "*" {
		tokenable.WithAccessToken(TransientToken{})
		return TransientToken{}
	}
	token := &MockToken{Abilities: abilities}
	tokenable.WithAccessToken(token)
	return token
}
