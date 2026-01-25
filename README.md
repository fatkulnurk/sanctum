# Laravel Sanctum Personal Access Tokens for Golang

[![Status](https://img.shields.io/badge/status-under%20development-orange)](https://github.com/fatkulnurk/sanctum)

Laravel Sanctum-compatible personal access tokens for Golang. Generate and validate tokens in the exact same format (`id|plain-token`), use the same database schema, and share tokens seamlessly between Laravel and Go services.

## Installation

```bash
go get github.com/fatkulnurk/sanctum
```

## Database Schema

The package supports two ID strategies matching Laravel Sanctum's configuration.

### Auto-increment (int/bigint)

Default Laravel migration using `$table->id()`:

```sql
CREATE TABLE personal_access_tokens (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    tokenable_type VARCHAR(255) NOT NULL,
    tokenable_id BIGINT UNSIGNED NOT NULL,
    name TEXT NOT NULL,
    token VARCHAR(64) NOT NULL UNIQUE,
    abilities TEXT NULL,
    last_used_at TIMESTAMP NULL,
    expires_at TIMESTAMP NULL INDEX,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);
```

### UUID / String

If your app uses UUID keys (`$table->uuid('id')->primary()` on tokenable):

```sql
CREATE TABLE personal_access_tokens (
    id CHAR(36) PRIMARY KEY,
    tokenable_type VARCHAR(255) NOT NULL,
    tokenable_id CHAR(36) NOT NULL,
    name TEXT NOT NULL,
    token VARCHAR(64) NOT NULL UNIQUE,
    abilities TEXT NULL,
    last_used_at TIMESTAMP NULL,
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);
```

## Quick Start

### 1. Implement the Store interface

```go
import (
    "context"
    "time"
    "sync"

    sanctum "github.com/fatkulnurk/sanctum"
)

type MemoryStore struct {
    mu     sync.RWMutex
    tokens map[string]*sanctum.PersonalAccessToken[string, string]
}

func (s *MemoryStore) Create(ctx context.Context, t *sanctum.PersonalAccessToken[string, string]) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    if t.ID == "" {
        t.ID = fmt.Sprintf("%d", len(s.tokens)+1) // simulate auto-increment
    }
    s.tokens[t.Token] = t
    return nil
}

func (s *MemoryStore) FindByToken(ctx context.Context, hashedToken string) (*sanctum.PersonalAccessToken[string, string], error) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    t, ok := s.tokens[hashedToken]
    if !ok {
        return nil, sanctum.ErrInvalidToken
    }
    return t, nil
}

func (s *MemoryStore) FindByID(ctx context.Context, id string) (*sanctum.PersonalAccessToken[string, string], error) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    for _, t := range s.tokens {
        if t.ID == id {
            return t, nil
        }
    }
    return nil, sanctum.ErrInvalidToken
}

func (s *MemoryStore) Delete(ctx context.Context, id string) error {
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

func (s *MemoryStore) UpdateLastUsedAt(ctx context.Context, id string, at time.Time) error {
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

func (s *MemoryStore) PruneExpired(ctx context.Context, beforeTime time.Time) (int64, error) {
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
```

### 2. UUID / String IDs (e.g. sharing with Laravel using UUIDs)

```go
store := &MemoryStore{}

sanctumManager := sanctum.NewSanctumWithUUID(
    sanctum.Config{
        Prefix:          "",      // optional token prefix (for secret scanning)
        IsAutoIncrement: false,   // UUID mode
        Expiration:      nil,     // optional global expiration duration
    },
    store,
)

// Create a token
result, err := sanctumManager.CreateToken(
    context.Background(),
    "550e8400-e29b-41d4-a716-446655440000", // tokenable ID (UUID)
    "App\\Models\\User",                     // tokenable type
    "API Token",
    []string{"*"},                           // abilities
    nil,                                     // expiresAt
)

fmt.Println(result.PlainTextToken)
// Output: 550e8400-e29b-41d4-a716-446655440000|prefixRandom40CharsCrc32

// Validate a token
token, err := sanctumManager.FindToken(ctx, "550e8400-...|prefixRandom40CharsCrc32")
if err != nil {
    // handle invalid/expired token
}

// Check abilities
err = sanctumManager.CheckAbilities(token, "read", "write")
err = sanctumManager.CheckForAnyAbility(token, "admin", "super-admin")

// Revoke
sanctumManager.RevokeToken(ctx, token.ID)
```

### 3. Auto-increment IDs (int/bigint)

```go
store := &MemoryStore{}

sanctumManager := sanctum.NewSanctumWithAutoIncrement(
    sanctum.Config{
        Prefix:          "myapp_",
        IsAutoIncrement: true,
    },
    store,
)

result, err := sanctumManager.CreateToken(
    context.Background(),
    "1",              // tokenable ID as string
    "App\\Models\\User",
    "Mobile App Token",
    []string{"read", "write"},
    nil,
)

fmt.Println(result.PlainTextToken)
// Output: 1|myapp_Random40CharsCrc32
```

### 4. Custom ID type (generic Sanctum)

For full control, use `NewSanctum` directly with your own ID types and parsers:

```go
import "strconv"

sanctum.NewSanctum[int64, string](
    sanctum.Config{Prefix: "", IsAutoIncrement: true},
    myStore, // Store[int64, string]
    func(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) },
    nil, // idGen only needed when IsAutoIncrement=false
)
```

## Features

### Ability Checking

```go
// Requires ALL abilities
err := sanctumManager.CheckAbilities(token, "read", "write")
if err != nil {
    var missing *sanctum.MissingAbilityError
    errors.As(err, &missing)
}

// Requires ANY of the abilities
err = sanctumManager.CheckForAnyAbility(token, "admin", "super-admin")

// Direct checks on the token
sanctumManager.TokenCan(token, "read")  // bool
sanctumManager.TokenCant(token, "write") // bool
```

### Token Expiration

```go
// Per-token expiration
expiresAt := time.Now().Add(24 * time.Hour)
result, _ := sanctumManager.CreateToken(ctx, id, type, name, abilities, &expiresAt)

// Global expiration (applied to all tokens without individual expires_at)
sanctumManager := sanctum.NewSanctumWithUUID(
    sanctum.Config{
        Expiration: durationPtr(30 * 24 * time.Hour), // 30 days
    },
    store,
)
```

### Prune Expired Tokens

```go
// Remove tokens expired for more than 24 hours
sanctumManager.PruneExpired(ctx, 24)
```

### TransientToken (Session Auth)

For session-authenticated users (like Laravel Sanctum's SPA support), `TransientToken` grants all abilities:

```go
var token sanctum.HasAbilities = sanctum.TransientToken{}
token.Can("anything")  // true
```

### Custom Callbacks

**Custom token extraction** (like `Sanctum::getAccessTokenFromRequestUsing`):

```go
sanctumManager.SetTokenRetrievalCallback(func(ctx context.Context, rawToken string) (string, error) {
    // Custom logic to extract/transform the token from request
    return rawToken, nil
})
```

**Custom authentication validation** (like `Sanctum::authenticateAccessTokensUsing`):

```go
sanctumManager.SetTokenAuthCallback(func(token *sanctum.PersonalAccessToken[string, string], isValid bool) (bool, error) {
    // Additional validation logic
    return isValid, nil
})
```

## API Reference

### Types

| Type | Description |
|------|-------------|
| `Sanctum[IDType, TokenableIDType]` | Main manager, generic over ID and tokenable ID types |
| `Config` | `Prefix`, `IsAutoIncrement`, `Expiration` |
| `PersonalAccessToken[IDType, TokenableIDType]` | Token model |
| `NewAccessToken[IDType, TokenableIDType]` | Returned by `CreateToken` |
| `Store[IDType, TokenableIDType]` | Storage backend interface |
| `TransientToken` | Grants all abilities (session auth) |
| `HasAbilities` | Interface with `Can`/`Cant` |
| `MissingAbilityError` | Error with list of missing abilities |

### Errors

| Error | Description |
|-------|-------------|
| `ErrInvalidToken` | Token not found or hash mismatch |
| `ErrTokenExpired` | Token has expired |
| `MissingAbilityError` | Required abilities missing |

### Functions

| Function | Description |
|----------|-------------|
| `GenerateToken(prefix)` | Generate `prefix + random(40) + crc32` |
| `HashToken(plain)` | SHA-256 hex of input |
| `NewSanctum(cfg, store, parseID, idGen)` | Generic constructor |
| `NewSanctumWithUUID(cfg, store)` | UUID/string IDs |
| `NewSanctumWithAutoIncrement(cfg, store)` | Auto-increment string IDs |
