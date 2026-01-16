package sanctum

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidToken = errors.New("invalid or unknown token")
	ErrTokenExpired = errors.New("token has expired")
)

type MissingAbilityError struct {
	Abilities []string
}

func (e *MissingAbilityError) Error() string {
	return fmt.Sprintf("missing abilities: %v", e.Abilities)
}

func (e *MissingAbilityError) AbilitiesList() []string {
	return e.Abilities
}

type MissingScopeError struct {
	Scopes []string
}

func (e *MissingScopeError) Error() string {
	return fmt.Sprintf("missing scopes: %v", e.Scopes)
}

func (e *MissingScopeError) ScopesList() []string {
	return e.Scopes
}
