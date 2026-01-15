package sanctum

import (
	"database/sql/driver"
	"encoding/json"
	"time"
)

type HasAbilities interface {
	Can(ability string) bool
	Cant(ability string) bool
}

type TransientToken struct{}

func (t TransientToken) Can(ability string) bool  { return true }
func (t TransientToken) Cant(ability string) bool { return false }

type PersonalAccessToken[IDType, TokenableIDType comparable] struct {
	ID            IDType
	TokenableID   TokenableIDType
	TokenableType string
	Name          string
	Token         string
	Abilities     Abilities
	LastUsedAt    *time.Time
	ExpiresAt     *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (t PersonalAccessToken[IDType, TokenableIDType]) Can(ability string) bool {
	for _, a := range t.Abilities {
		if a == "*" || a == ability {
			return true
		}
	}
	return false
}

func (t PersonalAccessToken[IDType, TokenableIDType]) Cant(ability string) bool {
	return !t.Can(ability)
}

type Abilities []string

func (a Abilities) Value() (driver.Value, error) {
	if a == nil {
		return nil, nil
	}
	return json.Marshal(a)
}

func (a *Abilities) Scan(v interface{}) error {
	if v == nil {
		*a = nil
		return nil
	}
	if b, ok := v.([]byte); ok {
		return json.Unmarshal(b, a)
	}
	return json.Unmarshal(v.([]byte), a)
}

type NewAccessToken[IDType, TokenableIDType comparable] struct {
	AccessToken    *PersonalAccessToken[IDType, TokenableIDType] `json:"access_token"`
	PlainTextToken string                                        `json:"plain_text_token"`
}

func (a NewAccessToken[IDType, TokenableIDType]) ToArray() map[string]interface{} {
	return map[string]interface{}{
		"accessToken":    a.AccessToken,
		"plainTextToken": a.PlainTextToken,
	}
}

func (a NewAccessToken[IDType, TokenableIDType]) ToJson() ([]byte, error) {
	return json.Marshal(a)
}
