package sanctum

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

type testStore struct {
	mu     sync.RWMutex
	tokens map[string]*PersonalAccessToken[string, string]
}

func newTestStore() *testStore {
	return &testStore{tokens: make(map[string]*PersonalAccessToken[string, string])}
}

func (s *testStore) Create(ctx context.Context, t *PersonalAccessToken[string, string]) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.ID == "" {
		t.ID = fmt.Sprintf("%d", len(s.tokens)+1)
	}
	s.tokens[t.Token] = t
	return nil
}

func (s *testStore) FindByToken(ctx context.Context, hashedToken string) (*PersonalAccessToken[string, string], error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tokens[hashedToken]
	if !ok {
		return nil, nil
	}
	return t, nil
}

func (s *testStore) FindByID(ctx context.Context, id string) (*PersonalAccessToken[string, string], error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.tokens {
		if t.ID == id {
			return t, nil
		}
	}
	return nil, nil
}

func (s *testStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, t := range s.tokens {
		if t.ID == id {
			delete(s.tokens, k)
			return nil
		}
	}
	return nil
}

func (s *testStore) UpdateLastUsedAt(ctx context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tokens {
		if t.ID == id {
			t.LastUsedAt = &at
			return nil
		}
	}
	return nil
}

func (s *testStore) PruneExpired(ctx context.Context, beforeTime time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int64
	for k, t := range s.tokens {
		if t.ExpiresAt != nil && t.ExpiresAt.Before(beforeTime) {
			delete(s.tokens, k)
			count++
		}
	}
	return count, nil
}

func TestCreateToken(t *testing.T) {
	store := newTestStore()
	s := NewSanctumWithUUID(Config{Prefix: ""}, store)

	result, err := s.CreateToken(context.Background(), "user-uuid-1", "App\\Models\\User", "Test Token", []string{"*"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PlainTextToken == "" {
		t.Error("plain text token should not be empty")
	}

	if result.AccessToken == nil {
		t.Error("access token model should not be nil")
	}

	if result.AccessToken.Name != "Test Token" {
		t.Errorf("expected name 'Test Token', got %q", result.AccessToken.Name)
	}

	if result.AccessToken.TokenableID != "user-uuid-1" {
		t.Errorf("expected tokenableID 'user-uuid-1', got %q", result.AccessToken.TokenableID)
	}

	if result.AccessToken.TokenableType != "App\\Models\\User" {
		t.Errorf("expected tokenableType 'App\\Models\\User', got %q", result.AccessToken.TokenableType)
	}
}

func TestCreateTokenWithAbilities(t *testing.T) {
	store := newTestStore()
	s := NewSanctumWithUUID(Config{Prefix: "app_"}, store)

	result, err := s.CreateToken(context.Background(), "1", "App\\Models\\User", "API Token", []string{"read", "write"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AccessToken.Abilities) != 2 {
		t.Errorf("expected 2 abilities, got %d", len(result.AccessToken.Abilities))
	}

	if !s.TokenCan(result.AccessToken, "read") {
		t.Error("token should have 'read' ability")
	}
	if !s.TokenCan(result.AccessToken, "write") {
		t.Error("token should have 'write' ability")
	}
	if s.TokenCan(result.AccessToken, "delete") {
		t.Error("token should not have 'delete' ability")
	}
}

func TestCreateTokenWithExpiration(t *testing.T) {
	store := newTestStore()
	s := NewSanctumWithUUID(Config{Prefix: ""}, store)

	expiresAt := time.Now().Add(24 * time.Hour)
	result, err := s.CreateToken(context.Background(), "1", "App\\Models\\User", "Expiring Token", []string{"*"}, &expiresAt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.AccessToken.ExpiresAt == nil {
		t.Fatal("expires_at should be set")
	}

	if result.AccessToken.ExpiresAt.Before(time.Now()) {
		t.Error("expires_at should be in the future")
	}
}

func TestFindTokenWithPlainToken(t *testing.T) {
	store := newTestStore()
	s := NewSanctumWithUUID(Config{Prefix: ""}, store)

	result, err := s.CreateToken(context.Background(), "1", "App\\Models\\User", "Test Token", []string{"*"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	token, err := s.FindToken(context.Background(), result.PlainTextToken)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token == nil {
		t.Fatal("token should be found")
	}

	if token.TokenableID != "1" {
		t.Errorf("expected tokenableID '1', got %q", token.TokenableID)
	}
}

func TestFindTokenWithInvalidToken(t *testing.T) {
	store := newTestStore()
	s := NewSanctumWithUUID(Config{Prefix: ""}, store)

	_, err := s.FindToken(context.Background(), "invalid-token")
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestFindTokenWithEmptyToken(t *testing.T) {
	store := newTestStore()
	s := NewSanctumWithUUID(Config{Prefix: ""}, store)

	_, err := s.FindToken(context.Background(), "")
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestFindTokenWithExpiredToken(t *testing.T) {
	store := newTestStore()
	s := NewSanctumWithUUID(Config{Prefix: ""}, store)

	pastTime := time.Now().Add(-1 * time.Hour)
	result, err := s.CreateToken(context.Background(), "1", "App\\Models\\User", "Expired Token", []string{"*"}, &pastTime)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = s.FindToken(context.Background(), result.PlainTextToken)
	if err != ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestFindTokenWithGlobalExpiration(t *testing.T) {
	store := newTestStore()
	expiration := 30 * time.Minute
	s := NewSanctumWithUUID(Config{Prefix: "", Expiration: &expiration}, store)

	result, err := s.CreateToken(context.Background(), "1", "App\\Models\\User", "Test Token", []string{"*"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	token, err := s.FindToken(context.Background(), result.PlainTextToken)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token == nil {
		t.Fatal("token should be found within expiration window")
	}
}

func TestRevokeToken(t *testing.T) {
	store := newTestStore()
	s := NewSanctumWithUUID(Config{Prefix: ""}, store)

	result, err := s.CreateToken(context.Background(), "1", "App\\Models\\User", "Test Token", []string{"*"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = s.RevokeToken(context.Background(), result.AccessToken.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = s.FindToken(context.Background(), result.PlainTextToken)
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken after revocation, got %v", err)
	}
}

func TestCheckAbilities(t *testing.T) {
	store := newTestStore()
	s := NewSanctumWithUUID(Config{Prefix: ""}, store)

	result, err := s.CreateToken(context.Background(), "1", "App\\Models\\User", "Test Token", []string{"read", "write"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = s.CheckAbilities(result.AccessToken, "read", "write")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	err = s.CheckAbilities(result.AccessToken, "read", "delete")
	if err == nil {
		t.Error("expected error for missing 'delete' ability")
	}

	if err != nil {
		if !IsMissingAbility(err) {
			t.Error("expected MissingAbilityError")
		}
	}
}

func TestCheckForAnyAbility(t *testing.T) {
	store := newTestStore()
	s := NewSanctumWithUUID(Config{Prefix: ""}, store)

	result, err := s.CreateToken(context.Background(), "1", "App\\Models\\User", "Test Token", []string{"read", "write"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = s.CheckForAnyAbility(result.AccessToken, "read", "delete")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	err = s.CheckForAnyAbility(result.AccessToken, "delete", "admin")
	if err == nil {
		t.Error("expected error when no abilities match")
	}
}

func TestCheckScopes(t *testing.T) {
	store := newTestStore()
	s := NewSanctumWithUUID(Config{Prefix: ""}, store)

	result, err := s.CreateToken(context.Background(), "1", "App\\Models\\User", "Test Token", []string{"read", "write"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = s.CheckScopes(result.AccessToken, "read", "write")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	err = s.CheckScopes(result.AccessToken, "read", "delete")
	if err == nil {
		t.Error("expected error for missing scope")
	}

	if err != nil {
		var scopeErr *MissingScopeError
		if _, ok := err.(*MissingScopeError); !ok {
			t.Errorf("expected MissingScopeError, got %T", err)
		}
		_ = scopeErr
	}
}

func TestCheckForAnyScope(t *testing.T) {
	store := newTestStore()
	s := NewSanctumWithUUID(Config{Prefix: ""}, store)

	result, err := s.CreateToken(context.Background(), "1", "App\\Models\\User", "Test Token", []string{"read", "write"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = s.CheckForAnyScope(result.AccessToken, "read", "delete")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	err = s.CheckForAnyScope(result.AccessToken, "delete", "admin")
	if err == nil {
		t.Error("expected error when no scopes match")
	}
}

func TestIsValidBearerToken(t *testing.T) {
	store := newTestStore()

	sUUID := NewSanctumWithUUID(Config{Prefix: ""}, store)
	if !sUUID.IsValidBearerToken("some-token") {
		t.Error("UUID mode should accept any non-empty token")
	}
	if !sUUID.IsValidBearerToken("1|some-plain-token") {
		t.Error("UUID mode should accept id|plain format")
	}
	if sUUID.IsValidBearerToken("") {
		t.Error("empty token should be invalid")
	}

	sAI := NewSanctumWithAutoIncrement(Config{Prefix: ""}, store)
	if !sAI.IsValidBearerToken("123|some-plain-token") {
		t.Error("auto-increment should accept numeric id|plain format")
	}
	if sAI.IsValidBearerToken("abc|some-plain-token") {
		t.Error("auto-increment should reject non-numeric id|plain format")
	}
	if !sAI.IsValidBearerToken("some-token") {
		t.Error("auto-increment should accept plain token for hash-only lookup")
	}
	if sAI.IsValidBearerToken("123|") {
		t.Error("auto-increment should reject empty token part")
	}
	if sAI.IsValidBearerToken("") {
		t.Error("empty token should be invalid")
	}
}

func TestOnTokenAuthenticated(t *testing.T) {
	store := newTestStore()
	s := NewSanctumWithUUID(Config{Prefix: ""}, store)

	var authenticated bool
	var authenticatedToken *PersonalAccessToken[string, string]
	s.OnTokenAuthenticated(func(ctx context.Context, token *PersonalAccessToken[string, string]) {
		authenticated = true
		authenticatedToken = token
	})

	result, err := s.CreateToken(context.Background(), "1", "App\\Models\\User", "Test Token", []string{"*"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	token, err := s.FindToken(context.Background(), result.PlainTextToken)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !authenticated {
		t.Error("OnTokenAuthenticated callback should have been called")
	}

	if authenticatedToken != token {
		t.Error("callback should receive the same token")
	}
}

func TestHasApiTokens(t *testing.T) {
	store := newTestStore()
	s := NewSanctumWithUUID(Config{Prefix: ""}, store)

	user := NewHasApiTokens(s, context.Background(), "user-1", "App\\Models\\User")

	result, err := user.CreateToken("Test Token", []string{"read", "write"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PlainTextToken == "" {
		t.Error("plain text token should not be empty")
	}

	user.WithAccessToken(result.AccessToken)

	if !user.TokenCan("read") {
		t.Error("user should have 'read' ability")
	}
	if !user.TokenCan("write") {
		t.Error("user should have 'write' ability")
	}
	if user.TokenCan("delete") {
		t.Error("user should not have 'delete' ability")
	}
	if !user.TokenCant("delete") {
		t.Error("user should cant 'delete'")
	}

	currentToken := user.CurrentAccessToken()
	if currentToken == nil {
		t.Error("current access token should not be nil")
	}
}

func TestActingAs(t *testing.T) {
	store := newTestStore()
	s := NewSanctumWithUUID(Config{Prefix: ""}, store)

	user := NewHasApiTokens(s, context.Background(), "user-1", "App\\Models\\User")

	token := ActingAs(user, []string{"read", "write"})
	if token == nil {
		t.Fatal("ActingAs should return a token")
	}

	if !user.TokenCan("read") {
		t.Error("user should have 'read' ability after ActingAs")
	}
	if !user.TokenCan("write") {
		t.Error("user should have 'write' ability after ActingAs")
	}
	if user.TokenCan("delete") {
		t.Error("user should not have 'delete' ability after ActingAs")
	}
}

func TestActingAsWithWildcard(t *testing.T) {
	store := newTestStore()
	s := NewSanctumWithUUID(Config{Prefix: ""}, store)

	user := NewHasApiTokens(s, context.Background(), "user-1", "App\\Models\\User")

	token := ActingAs(user, []string{"*"})
	if token == nil {
		t.Fatal("ActingAs should return a token")
	}

	if !user.TokenCan("anything") {
		t.Error("user should have all abilities with wildcard")
	}
	if !user.TokenCan("read") {
		t.Error("user should have 'read' ability with wildcard")
	}
}

func TestPruneExpired(t *testing.T) {
	store := newTestStore()
	s := NewSanctumWithUUID(Config{Prefix: ""}, store)

	pastTime := time.Now().Add(-2 * time.Hour)
	_, err := s.CreateToken(context.Background(), "1", "App\\Models\\User", "Expired Token", []string{"*"}, &pastTime)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	futureTime := time.Now().Add(24 * time.Hour)
	_, err = s.CreateToken(context.Background(), "2", "App\\Models\\User", "Valid Token", []string{"*"}, &futureTime)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = s.PruneExpired(context.Background(), 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tokens := store.tokens
	if len(tokens) != 1 {
		t.Errorf("expected 1 token after pruning, got %d", len(tokens))
	}
}

func TestProviderModelValidation(t *testing.T) {
	store := newTestStore()
	s := NewSanctumWithUUID(Config{
		Prefix:        "",
		ProviderModel: "App\\Models\\User",
	}, store)

	result, err := s.CreateToken(context.Background(), "1", "App\\Models\\User", "Test Token", []string{"*"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	token, err := s.FindToken(context.Background(), result.PlainTextToken)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token == nil {
		t.Fatal("token should be found with matching provider model")
	}

	s2 := NewSanctumWithUUID(Config{
		Prefix:        "",
		ProviderModel: "App\\Models\\Admin",
	}, store)

	_, err = s2.FindToken(context.Background(), result.PlainTextToken)
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken for mismatched provider model, got %v", err)
	}
}

func TestSetTokenRetrievalCallback(t *testing.T) {
	store := newTestStore()
	s := NewSanctumWithUUID(Config{Prefix: ""}, store)

	result, err := s.CreateToken(context.Background(), "1", "App\\Models\\User", "Test Token", []string{"*"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s.SetTokenRetrievalCallback(func(ctx context.Context, rawToken string) (string, error) {
		return result.PlainTextToken, nil
	})

	token, err := s.FindToken(context.Background(), "anything")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token == nil {
		t.Fatal("token should be found with custom retrieval callback")
	}
}

func TestSetTokenAuthCallback(t *testing.T) {
	store := newTestStore()
	s := NewSanctumWithUUID(Config{Prefix: ""}, store)

	result, err := s.CreateToken(context.Background(), "1", "App\\Models\\User", "Test Token", []string{"*"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s.SetTokenAuthCallback(func(token *PersonalAccessToken[string, string], isValid bool) (bool, error) {
		return false, nil
	})

	_, err = s.FindToken(context.Background(), result.PlainTextToken)
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken when auth callback returns false, got %v", err)
	}

	s2 := NewSanctumWithUUID(Config{Prefix: ""}, store)
	s2.SetTokenAuthCallback(func(token *PersonalAccessToken[string, string], isValid bool) (bool, error) {
		return true, nil
	})

	token, err := s2.FindToken(context.Background(), result.PlainTextToken)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token == nil {
		t.Fatal("token should be found when auth callback returns true")
	}
}

func IsMissingAbility(err error) bool {
	_, ok := err.(*MissingAbilityError)
	return ok
}
