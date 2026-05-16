# Laravel Sanctum Personal Access Tokens for Golang

[![Status](https://img.shields.io/badge/status-active-brightgreen)](https://github.com/fatkulnurk/sanctum)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Laravel Sanctum-compatible personal access tokens for Golang. Generate and validate tokens in the exact same format (`id|plain-token`), use the same database schema, and share tokens seamlessly between Laravel and Go services.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
  - [1. Implement the Store Interface](#1-implement-the-store-interface)
    - [Memory Store](#memory-store)
    - [MySQL Store](#mysql-store)
    - [PostgreSQL Store](#postgresql-store)
    - [SQLite Store](#sqlite-store)
    - [Redis Store](#redis-store)
  - [2. UUID / String IDs](#2-uuid--string-ids)
  - [3. Auto-increment IDs](#3-auto-increment-ids)
  - [4. Custom ID Type](#4-custom-id-type)
- [Features](#features)
  - [Token Creation & Validation](#token-creation--validation)
  - [Ability Checking](#ability-checking)
  - [Scope Checking (Deprecated)](#scope-checking-deprecated)
  - [Token Expiration](#token-expiration)
  - [Prune Expired Tokens](#prune-expired-tokens)
  - [TransientToken (Session Auth)](#transienttoken-session-auth)
  - [Provider Model Validation](#provider-model-validation)
  - [Custom Callbacks](#custom-callbacks)
  - [Testing Helper](#testing-helper)
- [HasApiTokens (User Model Integration)](#hasapitokens-user-model-integration)
- [API Reference](#api-reference)
  - [Types](#types)
  - [Errors](#errors)
  - [Functions](#functions)
- [API Comparison: Laravel Sanctum vs Go Sanctum](#api-comparison-laravel-sanctum-vs-go-sanctum)
  - [Interfaces / Contracts](#interfaces--contracts)
  - [Token Model](#token-model)
  - [NewAccessToken DTO](#newaccesstoken-dto)
  - [TransientToken](#transienttoken)
  - [Sanctum Utility](#sanctum-utility)
  - [HasApiTokens (on User model)](#hasapitokens-on-user-model)
  - [Guard / Token Validation](#guard--token-validation)
  - [Ability / Scope Middleware](#ability--scope-middleware)
  - [Exceptions / Errors](#exceptions--errors)
  - [Token Generation](#token-generation)
  - [Pruning](#pruning)
  - [Config](#config)
- [Database Schema](#database-schema)
  - [Auto-increment (int/bigint)](#auto-increment-intbigint)
  - [UUID / String](#uuid--string)

---

## Installation

```bash
go get github.com/fatkulnurk/sanctum
```

---

## Quick Start

### 1. Implement the Store Interface

The `Store` interface is the only thing you need to implement. It abstracts the database operations and gives you full control over the storage layer:

```go
type Store[IDType, TokenableIDType comparable] interface {
    Create(ctx context.Context, t *PersonalAccessToken[IDType, TokenableIDType]) error
    FindByToken(ctx context.Context, hashedToken string) (*PersonalAccessToken[IDType, TokenableIDType], error)
    FindByID(ctx context.Context, id IDType) (*PersonalAccessToken[IDType, TokenableIDType], error)
    Delete(ctx context.Context, id IDType) error
    UpdateLastUsedAt(ctx context.Context, id IDType, at time.Time) error
    PruneExpired(ctx context.Context, beforeTime time.Time) (int64, error)
}
```

Below are examples for different storage backends.

#### Memory Store

```go
import (
    "context"
    "fmt"
    "sync"
    "time"

    sanctum "github.com/fatkulnurk/sanctum"
)

type MemoryStore struct {
    mu     sync.RWMutex
    tokens map[string]*sanctum.PersonalAccessToken[string, string]
}

func NewMemoryStore() *MemoryStore {
    return &MemoryStore{tokens: make(map[string]*sanctum.PersonalAccessToken[string, string])}
}

func (s *MemoryStore) Create(ctx context.Context, t *sanctum.PersonalAccessToken[string, string]) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    if t.ID == "" {
        t.ID = fmt.Sprintf("%d", len(s.tokens)+1)
    }
    s.tokens[t.Token] = t
    return nil
}

func (s *MemoryStore) FindByToken(ctx context.Context, hashedToken string) (*sanctum.PersonalAccessToken[string, string], error) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    t, ok := s.tokens[hashedToken]
    if !ok {
        return nil, nil
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
    return nil, nil
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

#### MySQL Store

```go
import (
    "context"
    "database/sql"
    "encoding/json"
    "time"

    sanctum "github.com/fatkulnurk/sanctum"
    _ "github.com/go-sql-driver/mysql"
)

type MySQLStore struct {
    db *sql.DB
}

func NewMySQLStore(dsn string) (*MySQLStore, error) {
    db, err := sql.Open("mysql", dsn)
    if err != nil {
        return nil, err
    }
    return &MySQLStore{db: db}, db.Ping()
}

func (s *MySQLStore) Create(ctx context.Context, t *sanctum.PersonalAccessToken[string, string]) error {
    abilities, _ := json.Marshal(t.Abilities)
    _, err := s.db.ExecContext(ctx,
        `INSERT INTO personal_access_tokens (id, tokenable_type, tokenable_id, name, token, abilities, expires_at, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        t.ID, t.TokenableType, t.TokenableID, t.Name, t.Token, abilities, t.ExpiresAt, t.CreatedAt, t.UpdatedAt,
    )
    return err
}

func (s *MySQLStore) FindByToken(ctx context.Context, hashedToken string) (*sanctum.PersonalAccessToken[string, string], error) {
    row := s.db.QueryRowContext(ctx,
        `SELECT id, tokenable_type, tokenable_id, name, token, abilities, last_used_at, expires_at, created_at, updated_at
         FROM personal_access_tokens WHERE token = ?`, hashedToken)
    return scanToken(row)
}

func (s *MySQLStore) FindByID(ctx context.Context, id string) (*sanctum.PersonalAccessToken[string, string], error) {
    row := s.db.QueryRowContext(ctx,
        `SELECT id, tokenable_type, tokenable_id, name, token, abilities, last_used_at, expires_at, created_at, updated_at
         FROM personal_access_tokens WHERE id = ?`, id)
    return scanToken(row)
}

func (s *MySQLStore) Delete(ctx context.Context, id string) error {
    _, err := s.db.ExecContext(ctx, `DELETE FROM personal_access_tokens WHERE id = ?`, id)
    return err
}

func (s *MySQLStore) UpdateLastUsedAt(ctx context.Context, id string, at time.Time) error {
    _, err := s.db.ExecContext(ctx, `UPDATE personal_access_tokens SET last_used_at = ? WHERE id = ?`, at, id)
    return err
}

func (s *MySQLStore) PruneExpired(ctx context.Context, beforeTime time.Time) (int64, error) {
    res, err := s.db.ExecContext(ctx, `DELETE FROM personal_access_tokens WHERE expires_at IS NOT NULL AND expires_at < ?`, beforeTime)
    if err != nil {
        return 0, err
    }
    return res.RowsAffected()
}

func scanToken(row *sql.Row) (*sanctum.PersonalAccessToken[string, string], error) {
    t := &sanctum.PersonalAccessToken[string, string]{}
    var abilities, lastUsedAt, expiresAt sql.NullString
    err := row.Scan(&t.ID, &t.TokenableType, &t.TokenableID, &t.Name, &t.Token,
        &abilities, &lastUsedAt, &expiresAt, &t.CreatedAt, &t.UpdatedAt)
    if err == sql.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }
    if abilities.Valid {
        json.Unmarshal([]byte(abilities.String), &t.Abilities)
    }
    if lastUsedAt.Valid {
        parsed, _ := time.Parse("2006-01-02 15:04:05", lastUsedAt.String)
        t.LastUsedAt = &parsed
    }
    if expiresAt.Valid {
        parsed, _ := time.Parse("2006-01-02 15:04:05", expiresAt.String)
        t.ExpiresAt = &parsed
    }
    return t, nil
}
```

#### PostgreSQL Store

```go
import (
    "context"
    "database/sql"
    "encoding/json"
    "time"

    sanctum "github.com/fatkulnurk/sanctum"
    _ "github.com/lib/pq"
)

type PostgresStore struct {
    db *sql.DB
}

func NewPostgresStore(dsn string) (*PostgresStore, error) {
    db, err := sql.Open("postgres", dsn)
    if err != nil {
        return nil, err
    }
    return &PostgresStore{db: db}, db.Ping()
}

func (s *PostgresStore) Create(ctx context.Context, t *sanctum.PersonalAccessToken[string, string]) error {
    abilities, _ := json.Marshal(t.Abilities)
    _, err := s.db.ExecContext(ctx,
        `INSERT INTO personal_access_tokens (id, tokenable_type, tokenable_id, name, token, abilities, expires_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        t.ID, t.TokenableType, t.TokenableID, t.Name, t.Token, abilities, t.ExpiresAt, t.CreatedAt, t.UpdatedAt,
    )
    return err
}

func (s *PostgresStore) FindByToken(ctx context.Context, hashedToken string) (*sanctum.PersonalAccessToken[string, string], error) {
    row := s.db.QueryRowContext(ctx,
        `SELECT id, tokenable_type, tokenable_id, name, token, abilities, last_used_at, expires_at, created_at, updated_at
         FROM personal_access_tokens WHERE token = $1`, hashedToken)
    return scanToken(row)
}

func (s *PostgresStore) FindByID(ctx context.Context, id string) (*sanctum.PersonalAccessToken[string, string], error) {
    row := s.db.QueryRowContext(ctx,
        `SELECT id, tokenable_type, tokenable_id, name, token, abilities, last_used_at, expires_at, created_at, updated_at
         FROM personal_access_tokens WHERE id = $1`, id)
    return scanToken(row)
}

func (s *PostgresStore) Delete(ctx context.Context, id string) error {
    _, err := s.db.ExecContext(ctx, `DELETE FROM personal_access_tokens WHERE id = $1`, id)
    return err
}

func (s *PostgresStore) UpdateLastUsedAt(ctx context.Context, id string, at time.Time) error {
    _, err := s.db.ExecContext(ctx, `UPDATE personal_access_tokens SET last_used_at = $1 WHERE id = $2`, at, id)
    return err
}

func (s *PostgresStore) PruneExpired(ctx context.Context, beforeTime time.Time) (int64, error) {
    res, err := s.db.ExecContext(ctx, `DELETE FROM personal_access_tokens WHERE expires_at IS NOT NULL AND expires_at < $1`, beforeTime)
    if err != nil {
        return 0, err
    }
    return res.RowsAffected()
}

func scanToken(row *sql.Row) (*sanctum.PersonalAccessToken[string, string], error) {
    t := &sanctum.PersonalAccessToken[string, string]{}
    var abilities, lastUsedAt, expiresAt sql.NullString
    err := row.Scan(&t.ID, &t.TokenableType, &t.TokenableID, &t.Name, &t.Token,
        &abilities, &lastUsedAt, &expiresAt, &t.CreatedAt, &t.UpdatedAt)
    if err == sql.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }
    if abilities.Valid {
        json.Unmarshal([]byte(abilities.String), &t.Abilities)
    }
    if lastUsedAt.Valid {
        t.LastUsedAt = &lastUsedAt.Time
    }
    if expiresAt.Valid {
        t.ExpiresAt = &expiresAt.Time
    }
    return t, nil
}
```

#### SQLite Store

```go
import (
    "context"
    "database/sql"
    "encoding/json"
    "time"

    sanctum "github.com/fatkulnurk/sanctum"
    _ "github.com/mattn/go-sqlite3"
)

type SQLiteStore struct {
    db *sql.DB
}

func NewSQLiteStore(path string) (*SQLiteStore, error) {
    db, err := sql.Open("sqlite3", path)
    if err != nil {
        return nil, err
    }
    if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS personal_access_tokens (
        id TEXT PRIMARY KEY,
        tokenable_type TEXT NOT NULL,
        tokenable_id TEXT NOT NULL,
        name TEXT NOT NULL,
        token TEXT NOT NULL UNIQUE,
        abilities TEXT,
        last_used_at DATETIME,
        expires_at DATETIME,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL
    )`); err != nil {
        return nil, err
    }
    return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Create(ctx context.Context, t *sanctum.PersonalAccessToken[string, string]) error {
    abilities, _ := json.Marshal(t.Abilities)
    _, err := s.db.ExecContext(ctx,
        `INSERT INTO personal_access_tokens (id, tokenable_type, tokenable_id, name, token, abilities, expires_at, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        t.ID, t.TokenableType, t.TokenableID, t.Name, t.Token, abilities, t.ExpiresAt, t.CreatedAt, t.UpdatedAt,
    )
    return err
}

func (s *SQLiteStore) FindByToken(ctx context.Context, hashedToken string) (*sanctum.PersonalAccessToken[string, string], error) {
    return s.scanRow(s.db.QueryRowContext(ctx,
        `SELECT id, tokenable_type, tokenable_id, name, token, abilities, last_used_at, expires_at, created_at, updated_at
         FROM personal_access_tokens WHERE token = ?`, hashedToken))
}

func (s *SQLiteStore) FindByID(ctx context.Context, id string) (*sanctum.PersonalAccessToken[string, string], error) {
    return s.scanRow(s.db.QueryRowContext(ctx,
        `SELECT id, tokenable_type, tokenable_id, name, token, abilities, last_used_at, expires_at, created_at, updated_at
         FROM personal_access_tokens WHERE id = ?`, id))
}

func (s *SQLiteStore) Delete(ctx context.Context, id string) error {
    _, err := s.db.ExecContext(ctx, `DELETE FROM personal_access_tokens WHERE id = ?`, id)
    return err
}

func (s *SQLiteStore) UpdateLastUsedAt(ctx context.Context, id string, at time.Time) error {
    _, err := s.db.ExecContext(ctx, `UPDATE personal_access_tokens SET last_used_at = ? WHERE id = ?`, at, id)
    return err
}

func (s *SQLiteStore) PruneExpired(ctx context.Context, beforeTime time.Time) (int64, error) {
    res, err := s.db.ExecContext(ctx, `DELETE FROM personal_access_tokens WHERE expires_at IS NOT NULL AND expires_at < ?`, beforeTime)
    if err != nil {
        return 0, err
    }
    return res.RowsAffected()
}

func (s *SQLiteStore) scanRow(row *sql.Row) (*sanctum.PersonalAccessToken[string, string], error) {
    t := &sanctum.PersonalAccessToken[string, string]{}
    var abilities, lastUsedAt, expiresAt sql.NullString
    err := row.Scan(&t.ID, &t.TokenableType, &t.TokenableID, &t.Name, &t.Token,
        &abilities, &lastUsedAt, &expiresAt, &t.CreatedAt, &t.UpdatedAt)
    if err == sql.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }
    if abilities.Valid {
        json.Unmarshal([]byte(abilities.String), &t.Abilities)
    }
    if lastUsedAt.Valid {
        p, _ := time.Parse("2006-01-02 15:04:05", lastUsedAt.String)
        t.LastUsedAt = &p
    }
    if expiresAt.Valid {
        p, _ := time.Parse("2006-01-02 15:04:05", expiresAt.String)
        t.ExpiresAt = &p
    }
    return t, nil
}
```

#### Redis Store

```go
import (
    "context"
    "encoding/json"
    "fmt"
    "time"

    sanctum "github.com/fatkulnurk/sanctum"
    "github.com/redis/go-redis/v9"
)

type RedisStore struct {
    rdb *redis.Client
}

func NewRedisStore(addr string) *RedisStore {
    return &RedisStore{
        rdb: redis.NewClient(&redis.Options{Addr: addr}),
    }
}

func tokenKey(hashed string) string  { return "sanctum:token:" + hashed }
func idKey(id string) string         { return "sanctum:id:" + id }

func tokenToMap(t *sanctum.PersonalAccessToken[string, string]) map[string]interface{} {
    abilities, _ := json.Marshal(t.Abilities)
    return map[string]interface{}{
        "id":             t.ID,
        "tokenable_type": t.TokenableType,
        "tokenable_id":   t.TokenableID,
        "name":           t.Name,
        "token":          t.Token,
        "abilities":      string(abilities),
        "last_used_at":   timePtrToUnix(t.LastUsedAt),
        "expires_at":     timePtrToUnix(t.ExpiresAt),
        "created_at":     t.CreatedAt.Unix(),
        "updated_at":     t.UpdatedAt.Unix(),
    }
}

func mapToToken(m map[string]string) *sanctum.PersonalAccessToken[string, string] {
    t := &sanctum.PersonalAccessToken[string, string]{
        ID:            m["id"],
        TokenableType: m["tokenable_type"],
        TokenableID:   m["tokenable_id"],
        Name:          m["name"],
        Token:         m["token"],
    }
    abilities := m["abilities"]
    if abilities != "" {
        json.Unmarshal([]byte(abilities), &t.Abilities)
    }
    if v := m["last_used_at"]; v != "" {
        t.LastUsedAt = unixToTimePtr(v)
    }
    if v := m["expires_at"]; v != "" {
        t.ExpiresAt = unixToTimePtr(v)
    }
    if v := m["created_at"]; v != "" {
        unix, _ := fmt.Sscanf(v, "%d", &unix)
        _ = unix
        t.CreatedAt = time.Unix(unix, 0)
    }
    if v := m["updated_at"]; v != "" {
        unix, _ := fmt.Sscanf(v, "%d", &unix)
        _ = unix
        t.UpdatedAt = time.Unix(unix, 0)
    }
    return t
}

func timePtrToUnix(t *time.Time) *int64 {
    if t == nil {
        return nil
    }
    v := t.Unix()
    return &v
}

func unixToTimePtr(s string) *time.Time {
    var unix int64
    fmt.Sscanf(s, "%d", &unix)
    t := time.Unix(unix, 0)
    return &t
}

func (s *RedisStore) Create(ctx context.Context, t *sanctum.PersonalAccessToken[string, string]) error {
    pipe := s.rdb.Pipeline()
    pipe.HSet(ctx, tokenKey(t.Token), tokenToMap(t))
    pipe.Set(ctx, idKey(t.ID), t.Token, 0)
    _, err := pipe.Exec(ctx)
    return err
}

func (s *RedisStore) FindByToken(ctx context.Context, hashedToken string) (*sanctum.PersonalAccessToken[string, string], error) {
    m, err := s.rdb.HGetAll(ctx, tokenKey(hashedToken)).Result()
    if err != nil || len(m) == 0 {
        return nil, nil
    }
    return mapToToken(m), nil
}

func (s *RedisStore) FindByID(ctx context.Context, id string) (*sanctum.PersonalAccessToken[string, string], error) {
    token, err := s.rdb.Get(ctx, idKey(id)).Result()
    if err != nil {
        return nil, nil
    }
    return s.FindByToken(ctx, token)
}

func (s *RedisStore) Delete(ctx context.Context, id string) error {
    token, err := s.rdb.Get(ctx, idKey(id)).Result()
    if err != nil {
        return nil
    }
    pipe := s.rdb.Pipeline()
    pipe.Del(ctx, tokenKey(token))
    pipe.Del(ctx, idKey(id))
    _, err = pipe.Exec(ctx)
    return err
}

func (s *RedisStore) UpdateLastUsedAt(ctx context.Context, id string, at time.Time) error {
    token, err := s.rdb.Get(ctx, idKey(id)).Result()
    if err != nil {
        return nil
    }
    return s.rdb.HSet(ctx, tokenKey(token), "last_used_at", at.Unix()).Err()
}

func (s *RedisStore) PruneExpired(ctx context.Context, beforeTime time.Time) (int64, error) {
    var cursor uint64
    var count int64
    for {
        keys, next, err := s.rdb.Scan(ctx, cursor, "sanctum:token:*", 100).Result()
        if err != nil {
            return count, err
        }
        for _, key := range keys {
            expiresAt, err := s.rdb.HGet(ctx, key, "expires_at").Int64()
            if err != nil {
                continue
            }
            if time.Unix(expiresAt, 0).Before(beforeTime) {
                id, _ := s.rdb.HGet(ctx, key, "id").Result()
                pipe := s.rdb.Pipeline()
                pipe.Del(ctx, key)
                pipe.Del(ctx, idKey(id))
                pipe.Exec(ctx)
                count++
            }
        }
        if next == 0 {
            break
        }
        cursor = next
    }
    return count, nil
}
```

### 2. UUID / String IDs

For applications using UUID keys (matching Laravel's UUID configuration):

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

### 3. Auto-increment IDs

For applications using auto-increment integer IDs (matching Laravel's default migration):

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

### 4. Custom ID Type

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

---

## Features

### Token Creation & Validation

Create tokens with customizable abilities and expiration, then validate them with the `id|plain-text` format that Laravel uses:

```go
result, err := sanctumManager.CreateToken(ctx, userID, userType, name, abilities, expiresAt)
// result.PlainTextToken -> "1|random40charsCRC32"
// result.AccessToken    -> *PersonalAccessToken

token, err := sanctumManager.FindToken(ctx, "1|random40charsCRC32")
// Returns the token or ErrInvalidToken / ErrTokenExpired
```

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

### Scope Checking (deprecated)

Mirrors Laravel's deprecated `CheckScopes` and `CheckForAnyScope`:

```go
// Requires ALL scopes (deprecated, use CheckAbilities)
err := sanctumManager.CheckScopes(token, "read", "write")

// Requires ANY scope (deprecated, use CheckForAnyAbility)
err = sanctumManager.CheckForAnyScope(token, "admin", "super-admin")
```

### Token Expiration

Support both per-token expiration and global expiration duration:

```go
// Per-token expiration
expiresAt := time.Now().Add(24 * time.Hour)
result, _ := sanctumManager.CreateToken(ctx, id, userType, name, abilities, &expiresAt)

// Global expiration (applied to all tokens without individual expires_at)
sanctumManager := sanctum.NewSanctumWithUUID(
    sanctum.Config{
        Expiration: durationPtr(30 * 24 * time.Hour), // 30 days
    },
    store,
)
```

### Prune Expired Tokens

Remove tokens that have been expired beyond a specified hour threshold:

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

### Provider Model Validation

Restrict tokens to a specific tokenable type:

```go
sanctumManager := sanctum.NewSanctumWithUUID(
    sanctum.Config{
        ProviderModel: "App\\Models\\User", // Validate tokenable type
    },
    store,
)
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

**Token authenticated callback** (like Laravel's `TokenAuthenticated` event):

```go
sanctumManager.OnTokenAuthenticated(func(ctx context.Context, token *sanctum.PersonalAccessToken[string, string]) {
    // Called every time a token is successfully validated
    log.Printf("Token %s authenticated for user %s", token.ID, token.TokenableID)
})
```

### Testing Helper

```go
// Like Laravel's Sanctum::actingAs()
sanctum.ActingAs(user, []string{"read", "write"})

// With wildcard (all abilities)
sanctum.ActingAs(user, []string{"*"})
```

---

## HasApiTokens (User Model Integration)

Embed `HasApiTokensImpl` in your user model to get Laravel's `HasApiTokens` trait behavior:

```go
type User struct {
    ID   string
    Name string
    *sanctum.HasApiTokensImpl[string, string]
}

// Initialize
user := &User{ID: "user-uuid-1", Name: "John"}
user.HasApiTokensImpl = sanctum.NewHasApiTokens(sanctumManager, ctx, user.ID, "App\\Models\\User")

// Create token (like Laravel's $user->createToken())
result, _ := user.CreateToken("API Token", []string{"*"}, nil)

// Check abilities (like Laravel's $user->tokenCan())
user.WithAccessToken(result.AccessToken)
user.TokenCan("read")   // bool
user.TokenCant("admin") // bool
user.CurrentAccessToken() // HasAbilities
```

---

## API Reference

### Types

| Type | Description |
|------|-------------|
| `Sanctum[IDType, TokenableIDType]` | Main manager, generic over ID and tokenable ID types |
| `Config` | `Prefix`, `IsAutoIncrement`, `Expiration`, `ProviderModel` |
| `PersonalAccessToken[IDType, TokenableIDType]` | Token model |
| `NewAccessToken[IDType, TokenableIDType]` | Returned by `CreateToken` |
| `Store[IDType, TokenableIDType]` | Storage backend interface |
| `TransientToken` | Grants all abilities (session auth) |
| `HasAbilities` | Interface with `Can`/`Cant` |
| `HasApiTokens[IDType, TokenableIDType]` | Generic interface with `TokenCan`, `TokenCant`, `CreateToken`, `CurrentAccessToken`, `WithAccessToken` |
| `HasApiTokensImpl[IDType, TokenableIDType]` | Embeddable struct implementing `HasApiTokens` |
| `MissingAbilityError` | Error with list of missing abilities |
| `MissingScopeError` | Deprecated error with list of missing scopes |
| `MockToken` | Test helper token with configurable abilities |

### Errors

| Error | Description |
|-------|-------------|
| `ErrInvalidToken` | Token not found or hash mismatch |
| `ErrTokenExpired` | Token has expired |
| `MissingAbilityError` | Required abilities missing |
| `MissingScopeError` | Required scopes missing (deprecated) |

### Functions

| Function | Description |
|----------|-------------|
| `GenerateToken(prefix)` | Generate `prefix + random(40) + crc32` |
| `HashToken(plain)` | SHA-256 hex of input |
| `NewSanctum(cfg, store, parseID, idGen)` | Generic constructor |
| `NewSanctumWithUUID(cfg, store)` | UUID/string IDs |
| `NewSanctumWithAutoIncrement(cfg, store)` | Auto-increment string IDs |
| `ActingAs(tokenable, abilities)` | Testing helper (mirrors `Sanctum::actingAs`) |
| `NewHasApiTokens(sanctum, ctx, userID, userType)` | Create HasApiTokens for a user model |

---

## API Comparison: Laravel Sanctum vs Go Sanctum

### Interfaces / Contracts

| Laravel Sanctum | Go Sanctum | Notes |
|-----------------|------------|-------|
| `HasAbilities` interface (`can`, `cant`) | `HasAbilities` interface (`Can`, `Cant`) | Exact match |
| `HasApiTokens` interface (`tokenCan`, `tokenCant`, `createToken`, `currentAccessToken`, `withAccessToken`) | `HasApiTokens[IDType, TokenableIDType]` generic interface | Same methods, Go idiomatic |

### Token Model

| Laravel Sanctum | Go Sanctum | Notes |
|-----------------|------------|-------|
| `PersonalAccessToken` (Eloquent model) | `PersonalAccessToken[IDType, TokenableIDType]` | Generic version |
| `PersonalAccessToken::findToken($token)` | `Sanctum.FindToken(ctx, rawToken)` | Equivalent |
| `$token->can($ability)` | `$token.Can(ability)` | Exact match |
| `$token->cant($ability)` | `$token.Cant(ability)` | Exact match |
| `$token->tokenable()` (MorphTo relation) | Store handles | Not needed in Go |

### NewAccessToken DTO

| Laravel Sanctum | Go Sanctum | Notes |
|-----------------|------------|-------|
| `NewAccessToken($accessToken, $plainTextToken)` | `NewAccessToken[IDType, TokenableIDType]{AccessToken, PlainTextToken}` | Exact match |
| `$dto->toArray()` | `$dto.ToArray()` | Exact match |
| `$dto->toJson($options)` | `$dto.ToJson()` | Returns `[]byte` in Go |

### TransientToken

| Laravel Sanctum | Go Sanctum | Notes |
|-----------------|------------|-------|
| `TransientToken implements HasAbilities` | `TransientToken` struct | Exact match |
| `$token->can($ability)` → `true` | `$token.Can(ability)` → `true` | Exact match |
| `$token->cant($ability)` → `false` | `$token.Cant(ability)` → `false` | Exact match |

### Sanctum Utility

| Laravel Sanctum | Go Sanctum | Notes |
|-----------------|------------|-------|
| `Sanctum::getAccessTokenFromRequestUsing($callback)` | `SetTokenRetrievalCallback(callback)` | Exact match |
| `Sanctum::authenticateAccessTokensUsing($callback)` | `SetTokenAuthCallback(callback)` | Exact match |
| `Sanctum::usePersonalAccessTokenModel($model)` | N/A | Not needed (generics) |
| `Sanctum::actingAs($user, $abilities, $guard)` | `ActingAs(tokenable, abilities)` | Equivalent |
| `Sanctum::personalAccessTokenModel()` | N/A | Not needed |
| `TokenAuthenticated` event | `OnTokenAuthenticated(handler)` | Callback equivalent |

### HasApiTokens (on User model)

| Laravel Sanctum | Go Sanctum | Notes |
|-----------------|------------|-------|
| `$user->tokenCan($ability)` | `user.TokenCan(ability)` | Exact match |
| `$user->tokenCant($ability)` | `user.TokenCant(ability)` | Exact match |
| `$user->createToken($name, $abilities, $expiresAt)` | `user.CreateToken(name, abilities, expiresAt)` | Exact match |
| `$user->currentAccessToken()` | `user.CurrentAccessToken()` | Exact match |
| `$user->withAccessToken($token)` | `user.WithAccessToken(token)` | Exact match |
| `$user->tokens()` (MorphMany relation) | N/A | Not needed (Store handles) |

### Guard / Token Validation

| Laravel Sanctum | Go Sanctum | Notes |
|-----------------|------------|-------|
| `Guard::__invoke($request)` | `Sanctum.FindToken(ctx, rawToken)` | Equivalent |
| `Guard::isValidBearerToken($token)` | `Sanctum.IsValidBearerToken(token)` | Exact match |
| `Guard::hasValidProvider($tokenable)` | `Config.ProviderModel` + internal check | Equivalent |
| `Guard::supportsTokens($tokenable)` | N/A | Not needed in Go |
| `Guard::updateLastUsedAt($accessToken)` | `Store.UpdateLastUsedAt` | Equivalent |

### Ability / Scope Middleware

| Laravel Sanctum | Go Sanctum | Notes |
|-----------------|------------|-------|
| `CheckAbilities` middleware (ALL required) | `Sanctum.CheckAbilities(token, abilities...)` | Equivalent |
| `CheckForAnyAbility` middleware (ANY required) | `Sanctum.CheckForAnyAbility(token, abilities...)` | Equivalent |
| `CheckScopes` (deprecated, wraps CheckAbilities) | `Sanctum.CheckScopes(token, scopes...)` | Exact match |
| `CheckForAnyScope` (deprecated, wraps CheckForAnyAbility) | `Sanctum.CheckForAnyScope(token, scopes...)` | Exact match |
| `EnsureFrontendRequestsAreStateful` | N/A | HTTP-framework specific |

### Exceptions / Errors

| Laravel Sanctum | Go Sanctum | Notes |
|-----------------|------------|-------|
| `MissingAbilityException` | `MissingAbilityError` | Exact match |
| `MissingAbilityException->abilities()` | `MissingAbilityError.Abilities` | Exact match |
| `MissingScopeException` (deprecated) | `MissingScopeError` | Exact match |
| `MissingScopeException->scopes()` | `MissingScopeError.Scopes` | Exact match |
| `ErrInvalidToken` | `ErrInvalidToken` | Exact match |
| `ErrTokenExpired` | `ErrTokenExpired` | Exact match |

### Token Generation

| Laravel Sanctum | Go Sanctum | Notes |
|-----------------|------------|-------|
| `generateTokenString()` | `GenerateToken(prefix)` | Exact match |
| `hash('sha256', $plain)` | `HashToken(plain)` | Exact match |
| Token format: `{prefix}{random(40)}{crc32b}` | Same format | Exact match |

### Pruning

| Laravel Sanctum | Go Sanctum | Notes |
|-----------------|------------|-------|
| `sanctum:prune-expired --hours=N` | `Sanctum.PruneExpired(ctx, hours)` | Equivalent |

### Config

| Laravel Sanctum (`config/sanctum.php`) | Go Sanctum (`Config` struct) | Notes |
|----------------------------------------|------------------------------|-------|
| `stateful` | N/A | HTTP-framework specific |
| `guard` | N/A | HTTP-framework specific |
| `expiration` | `Config.Expiration` | Exact match |
| `token_prefix` | `Config.Prefix` | Exact match |
| N/A | `Config.IsAutoIncrement` | Go-specific |
| N/A | `Config.ProviderModel` | Go-specific |

---

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
