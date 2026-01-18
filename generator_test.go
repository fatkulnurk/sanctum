package sanctum

import (
	"fmt"
	"hash/crc32"
	"strings"
	"testing"
)

func TestGenerateTokenFormat(t *testing.T) {
	prefix := "test_"
	token, err := GenerateToken(prefix)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(token, prefix) {
		t.Errorf("token should start with prefix %q, got %q", prefix, token)
	}

	expectedLen := len(prefix) + 48
	if len(token) != expectedLen {
		t.Errorf("expected token length %d, got %d", expectedLen, len(token))
	}
}

func TestGenerateTokenCRCIsLast8Chars(t *testing.T) {
	prefix := ""
	token, err := GenerateToken(prefix)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entropy := token[:40]
	crcHex := token[40:]

	expectedCRC := crc32.ChecksumIEEE([]byte(entropy))
	expectedCRCStr := fmt.Sprintf("%08x", expectedCRC)

	if crcHex != expectedCRCStr {
		t.Errorf("CRC mismatch: got %s, expected %s", crcHex, expectedCRCStr)
	}
}

func TestGenerateTokenRandomness(t *testing.T) {
	tokens := make(map[string]bool)
	for i := 0; i < 100; i++ {
		token, err := GenerateToken("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tokens[token] {
			t.Error("duplicate token generated")
		}
		tokens[token] = true
	}
}

func TestGenerateTokenWithEmptyPrefix(t *testing.T) {
	token, err := GenerateToken("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(token) != 48 {
		t.Errorf("expected length 48, got %d", len(token))
	}
}

func TestHashToken(t *testing.T) {
	plain := "test-token-123"
	hash := HashToken(plain)
	if len(hash) != 64 {
		t.Errorf("SHA-256 hex should be 64 chars, got %d", len(hash))
	}

	hash2 := HashToken(plain)
	if hash != hash2 {
		t.Error("same input should produce same hash")
	}

	hash3 := HashToken("different")
	if hash == hash3 {
		t.Error("different input should produce different hash")
	}
}
