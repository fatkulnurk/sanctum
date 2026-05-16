package sanctum

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"math/big"
)

const alphaNum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// GenerateToken reference: https://github.com/laravel/sanctum/blob/4.x/src/HasApiTokens.php
func GenerateToken(prefix string) (string, error) {
	// 1. Generate 40-character alphanumeric string (like Str::random(40))
	tokenEntropy := make([]byte, 40)
	for i := range tokenEntropy {
		// Secure random index in [0, 62)
		num, err := rand.Int(rand.Reader, big.NewInt(62))
		if err != nil {
			return "", err
		}

		tokenEntropy[i] = alphaNum[num.Int64()]
	}
	randomStr := string(tokenEntropy) // 40-character alphanumeric string

	// 2. Compute CRC32B of the random string (as bytes)
	crc := crc32.ChecksumIEEE([]byte(randomStr))
	crcHex := fmt.Sprintf("%08x", crc) // 8 hex chars, lowercase

	// 3. combine with prefix (matches Laravel: prefix + random(40) + crc32b)
	return prefix + randomStr + crcHex, nil
}

// HashToken return the SHA-256 hash (hex-decoded) of plain text
func HashToken(plainToken string) string {
	h := sha256.Sum256([]byte(plainToken))
	return hex.EncodeToString(h[:])
}
