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
