package sanctum

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

func GenerateToken() (string, error) {
	b := make([]byte, 40) // 40 bytes = 80 hex chars
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

// HashToken return the SHA-256 hash (hex-decoded) of plain text
func HashToken(plainToken string) string {
	h := sha256.Sum256([]byte(plainToken))
	return hex.EncodeToString(h[:])
}
