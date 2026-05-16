package sanctum

import (
	"database/sql/driver"
	"encoding/json"
	"testing"
	"time"
)

func TestTransientTokenCan(t *testing.T) {
	token := TransientToken{}
	if !token.Can("anything") {
		t.Error("TransientToken should grant all abilities")
	}
}

func TestTransientTokenCant(t *testing.T) {
	token := TransientToken{}
	if token.Cant("anything") {
		t.Error("TransientToken.Cant should return false")
	}
}

func TestPersonalAccessTokenCanWithWildcard(t *testing.T) {
	token := PersonalAccessToken[string, string]{
		Abilities: Abilities{"*"},
	}
	if !token.Can("any-ability") {
		t.Error("token with '*' should grant any ability")
	}
	if !token.Can("") {
		t.Error("token with '*' should grant empty ability")
	}
}

func TestPersonalAccessTokenCanWithSpecificAbility(t *testing.T) {
	token := PersonalAccessToken[string, string]{
		Abilities: Abilities{"read", "write"},
	}
	if !token.Can("read") {
		t.Error("token should have 'read' ability")
	}
	if !token.Can("write") {
		t.Error("token should have 'write' ability")
	}
	if token.Can("delete") {
		t.Error("token should not have 'delete' ability")
	}
	if token.Can("admin") {
		t.Error("token should not have 'admin' ability")
	}
}

func TestPersonalAccessTokenCanWithEmptyAbilities(t *testing.T) {
	token := PersonalAccessToken[string, string]{
		Abilities: Abilities{},
	}
	if token.Can("anything") {
		t.Error("token with empty abilities should not grant anything")
	}
}

func TestPersonalAccessTokenCant(t *testing.T) {
	token := PersonalAccessToken[string, string]{
		Abilities: Abilities{"read"},
	}
	if !token.Cant("write") {
		t.Error("token should not be able to 'write'")
	}
	if token.Cant("read") {
		t.Error("token should be able to 'read'")
	}
}

func TestPersonalAccessTokenCanWithMultipleAbilitiesIncludingWildcard(t *testing.T) {
	token := PersonalAccessToken[string, string]{
		Abilities: Abilities{"read", "write", "*"},
	}
	if !token.Can("read") {
		t.Error("token should have 'read'")
	}
	if !token.Can("anything-really") {
		t.Error("token with '*' should grant everything")
	}
}

func TestHasAbilitiesInterface(t *testing.T) {
	var h HasAbilities
	h = TransientToken{}
	if !h.Can("anything") {
		t.Error("TransientToken should implement HasAbilities")
	}

	h = &PersonalAccessToken[string, string]{Abilities: Abilities{"*"}}
	if !h.Can("anything") {
		t.Error("PersonalAccessToken should implement HasAbilities")
	}
}

func TestNewAccessTokenToArray(t *testing.T) {
	token := &PersonalAccessToken[string, string]{
		ID:          "1",
		TokenableID: "user-1",
		Name:        "Test",
		Abilities:   Abilities{"read"},
	}
	nat := NewAccessToken[string, string]{
		AccessToken:    token,
		PlainTextToken: "1|plaintext",
	}

	arr := nat.ToArray()
	if arr["accessToken"] != token {
		t.Error("ToArray should contain the access token")
	}
	if arr["plainTextToken"] != "1|plaintext" {
		t.Error("ToArray should contain the plain text token")
	}
}

func TestNewAccessTokenToJson(t *testing.T) {
	token := &PersonalAccessToken[string, string]{
		ID:            "1",
		TokenableID:   "user-1",
		TokenableType: "App\\Models\\User",
		Name:          "Test",
		Abilities:     Abilities{"read"},
		CreatedAt:     mustParseTime("2024-01-01T00:00:00Z"),
		UpdatedAt:     mustParseTime("2024-01-01T00:00:00Z"),
	}
	nat := NewAccessToken[string, string]{
		AccessToken:    token,
		PlainTextToken: "1|plaintext",
	}

	b, err := nat.ToJson()
	if err != nil {
		t.Fatalf("ToJson failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if result["plain_text_token"] != "1|plaintext" {
		t.Error("JSON should contain plain_text_token")
	}
}

func mustParseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestAbilitiesValue(t *testing.T) {
	a := Abilities{"read", "write"}
	v, err := a.Value()
	if err != nil {
		t.Fatalf("Value failed: %v", err)
	}

	b, ok := v.([]byte)
	if !ok {
		t.Fatalf("expected []byte, got %T", v)
	}

	var decoded Abilities
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if len(decoded) != 2 || decoded[0] != "read" || decoded[1] != "write" {
		t.Error("unexpected abilities after Value round-trip")
	}
}

func TestAbilitiesValueNil(t *testing.T) {
	var a Abilities
	v, err := a.Value()
	if err != nil {
		t.Fatalf("Value failed for nil: %v", err)
	}
	if v != nil {
		t.Error("nil Abilities should return nil driver.Value")
	}
}

func TestAbilitiesScan(t *testing.T) {
	var a Abilities
	data := []byte(`["read","write"]`)
	if err := a.Scan(data); err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(a) != 2 || a[0] != "read" || a[1] != "write" {
		t.Error("unexpected abilities after Scan")
	}
}

func TestAbilitiesScanNil(t *testing.T) {
	var a Abilities
	if err := a.Scan(nil); err != nil {
		t.Fatalf("Scan nil failed: %v", err)
	}
	if a != nil {
		t.Error("Scan(nil) should set abilities to nil")
	}
}

func TestAbilitiesScanString(t *testing.T) {
	var a Abilities
	if err := a.Scan(`["admin"]`); err != nil {
		t.Fatalf("Scan string failed: %v", err)
	}
	if len(a) != 1 || a[0] != "admin" {
		t.Error("unexpected abilities after Scan from string")
	}
}

func TestAbilitiesImplementsDriver(t *testing.T) {
	var a Abilities
	var _ driver.Valuer = a
	var _ driver.Valuer = &a
	_ = a
}

func TestMockTokenCan(t *testing.T) {
	token := &MockToken{Abilities: []string{"read", "write"}}
	if !token.Can("read") {
		t.Error("MockToken should have 'read' ability")
	}
	if token.Can("delete") {
		t.Error("MockToken should not have 'delete' ability")
	}
}

func TestMockTokenCanWithWildcard(t *testing.T) {
	token := &MockToken{Abilities: []string{"*"}}
	if !token.Can("anything") {
		t.Error("MockToken with '*' should grant any ability")
	}
}

func TestMockTokenCant(t *testing.T) {
	token := &MockToken{Abilities: []string{"read"}}
	if !token.Cant("write") {
		t.Error("MockToken should not be able to 'write'")
	}
	if token.Cant("read") {
		t.Error("MockToken should be able to 'read'")
	}
}

func TestMockTokenEmptyAbilities(t *testing.T) {
	token := &MockToken{}
	if token.Can("anything") {
		t.Error("MockToken with empty abilities should not grant anything")
	}
}

func TestPersonalAccessTokenCantWithNilAbilities(t *testing.T) {
	token := PersonalAccessToken[string, string]{}
	if !token.Cant("anything") {
		t.Error("PersonalAccessToken with nil abilities should cant everything")
	}
}

func TestPersonalAccessTokenCantWithWildcard(t *testing.T) {
	token := PersonalAccessToken[string, string]{
		Abilities: Abilities{"*"},
	}
	if token.Cant("anything") {
		t.Error("PersonalAccessToken with '*' should not cant anything")
	}
}
