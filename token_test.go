package sanctum

import (
	"testing"
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
