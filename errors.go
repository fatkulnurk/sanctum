package sanctum

import "errors"

var (
	ErrInvalidToken = errors.New("invalid or unknown token")
	ErrTokenExpired = errors.New("token has expired")
)
