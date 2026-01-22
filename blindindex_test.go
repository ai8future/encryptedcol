package encryptedcol

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBlindIndex_Deterministic(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	plaintext := []byte("test@example.com")

	idx1 := cipher.BlindIndex(plaintext)
	idx2 := cipher.BlindIndex(plaintext)

	require.True(t, bytes.Equal(idx1, idx2), "same plaintext should produce same index")
}

func TestBlindIndex_DifferentPlaintext(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	idx1 := cipher.BlindIndex([]byte("alice@example.com"))
	idx2 := cipher.BlindIndex([]byte("bob@example.com"))

	require.False(t, bytes.Equal(idx1, idx2), "different plaintext should produce different index")
}

func TestBlindIndex_DifferentKeys(t *testing.T) {
	cipher1, _ := New(WithKey("v1", testKey("v1")))
	cipher2, _ := New(WithKey("v1", testKey("different")))

	plaintext := []byte("test@example.com")

	idx1 := cipher1.BlindIndex(plaintext)
	idx2 := cipher2.BlindIndex(plaintext)

	require.False(t, bytes.Equal(idx1, idx2), "same plaintext with different keys should produce different index")
}

func TestBlindIndex_NullPreservation(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	idx := cipher.BlindIndex(nil)
	require.Nil(t, idx)
}

func TestBlindIndex_EmptySlice(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	idx := cipher.BlindIndex([]byte{})
	require.NotNil(t, idx)
	require.Len(t, idx, 32) // SHA256 output
}

func TestBlindIndex_OutputSize(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	tests := [][]byte{
		[]byte("short"),
		[]byte("medium length string"),
		bytes.Repeat([]byte("x"), 10000),
	}

	for _, plaintext := range tests {
		idx := cipher.BlindIndex(plaintext)
		require.Len(t, idx, 32, "blind index should always be 32 bytes (SHA256)")
	}
}

func TestBlindIndexWithKey(t *testing.T) {
	cipher, _ := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
	)

	plaintext := []byte("test")

	idx1, err := cipher.BlindIndexWithKey("v1", plaintext)
	require.NoError(t, err)

	idx2, err := cipher.BlindIndexWithKey("v2", plaintext)
	require.NoError(t, err)

	require.False(t, bytes.Equal(idx1, idx2), "different keys should produce different indexes")
}

func TestBlindIndexWithKey_NotFound(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	_, err := cipher.BlindIndexWithKey("nonexistent", []byte("test"))
	require.ErrorIs(t, err, ErrKeyNotFound)
}

func TestBlindIndexWithKey_NullPreservation(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	idx, err := cipher.BlindIndexWithKey("v1", nil)
	require.NoError(t, err)
	require.Nil(t, idx)
}

func TestBlindIndexes(t *testing.T) {
	cipher, _ := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
	)

	plaintext := []byte("test@example.com")

	indexes := cipher.BlindIndexes(plaintext)

	require.Len(t, indexes, 2)
	require.Contains(t, indexes, "v1")
	require.Contains(t, indexes, "v2")
	require.Len(t, indexes["v1"], 32)
	require.Len(t, indexes["v2"], 32)
	require.False(t, bytes.Equal(indexes["v1"], indexes["v2"]))
}

func TestBlindIndexes_NullPreservation(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	indexes := cipher.BlindIndexes(nil)
	require.Nil(t, indexes)
}

func TestBlindIndexString(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	s := "test@example.com"
	idx1 := cipher.BlindIndexString(s)
	idx2 := cipher.BlindIndex([]byte(s))

	require.True(t, bytes.Equal(idx1, idx2))
}

func TestBlindIndex_DifferentFromEncryptionKey(t *testing.T) {
	// Verify that HMAC key is different from encryption key
	cipher, _ := New(WithKey("v1", testKey("v1")))

	plaintext := []byte("test")

	// Get blind index (uses HMAC key)
	idx := cipher.BlindIndex(plaintext)

	// Encrypt same data (uses encryption key)
	ciphertext := cipher.Seal(plaintext)

	// They should be different lengths at minimum
	// (ciphertext has format overhead, blind index is exactly 32 bytes)
	require.NotEqual(t, len(idx), len(ciphertext))

	// And the first bytes should differ
	require.False(t, bytes.Equal(idx, ciphertext[:32]))
}

func TestBlindIndex_CaseSensitive(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	idx1 := cipher.BlindIndex([]byte("Test@Example.com"))
	idx2 := cipher.BlindIndex([]byte("test@example.com"))

	// Without normalization, different cases produce different indexes
	require.False(t, bytes.Equal(idx1, idx2), "blind index should be case-sensitive by default")
}

func TestBlindIndex_UseAfterClose(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))
	cipher.Close()

	// All BlindIndex methods should return error or handle closed state
	require.Panics(t, func() {
		cipher.BlindIndex([]byte("test"))
	}, "BlindIndex should panic after Close")

	require.Panics(t, func() {
		cipher.BlindIndexString("test")
	}, "BlindIndexString should panic after Close")

	require.Panics(t, func() {
		cipher.BlindIndexes([]byte("test"))
	}, "BlindIndexes should panic after Close")

	_, err := cipher.BlindIndexWithKey("v1", []byte("test"))
	require.ErrorIs(t, err, ErrCipherClosed, "BlindIndexWithKey should return ErrCipherClosed")
}
