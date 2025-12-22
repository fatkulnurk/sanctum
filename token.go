package sanctum

import (
	"database/sql/driver"
	"encoding/json"
	"time"
)

type Token[IDType, TokenableIDType comparable] struct {
	ID            IDType          // ada yang ID berupa int64, ada yang uuid atau string, jadi harus generic
	TokenableID   TokenableIDType // sama seperti ID
	TokenableType string
	Name          string
	Token         string // ini yang disimpan hasil hashednya, bukan plain
	Abilities     Abilities
	LastUsedAt    *time.Time
	ExpiresAt     *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (t Token[IDType, TokenableIDType]) Can(ability string) bool {
	for _, a := range t.Abilities {
		if a == "*" || a == ability {
			return true
		}
	}

	return false
}

func (t Token[IDType, TokenableIDType]) Cant(ability string) bool {
	return !t.Can(ability)
}

// Abilities selalu valuenya []string
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
