package encryptedcol

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeriveKeys_Deterministic(t *testing.T) {
	masterKey := []byte("01234567890123456789012345678901") // 32 bytes

	// Derive keys twice
	keys1, err := deriveKeys(masterKey)
	require.NoError(t, err)

	keys2, err := deriveKeys(masterKey)
	require.NoError(t, err)

	// Same master key should produce same derived keys
	require.Equal(t, keys1.encryption, keys2.encryption)
	require.Equal(t, keys1.hmac, keys2.hmac)
}

func TestDeriveKeys_DifferentMasterKeys(t *testing.T) {
	masterKey1 := []byte("01234567890123456789012345678901")
	masterKey2 := []byte("01234567890123456789012345678902") // One byte different

	keys1, err := deriveKeys(masterKey1)
	require.NoError(t, err)

	keys2, err := deriveKeys(masterKey2)
	require.NoError(t, err)

	// Different master keys should produce different derived keys
	require.NotEqual(t, keys1.encryption, keys2.encryption)
	require.NotEqual(t, keys1.hmac, keys2.hmac)
}

func TestDeriveKeys_EncryptionAndHMACAreDifferent(t *testing.T) {
	masterKey := []byte("01234567890123456789012345678901")

	keys, err := deriveKeys(masterKey)
	require.NoError(t, err)

	// Encryption and HMAC keys should be different (derived with different info strings)
	require.False(t, bytes.Equal(keys.encryption[:], keys.hmac[:]),
		"encryption and hmac keys should be different")
}

func TestDeriveKeys_InvalidKeySize(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
	}{
		{"empty", 0},
		{"too short", 16},
		{"too long", 64},
		{"31 bytes", 31},
		{"33 bytes", 33},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			_, err := deriveKeys(key)
			require.ErrorIs(t, err, ErrInvalidKeySize)
		})
	}
}

func TestDeriveKeys_32BytesExactly(t *testing.T) {
	key := make([]byte, 32)
	keys, err := deriveKeys(key)
	require.NoError(t, err)
	require.NotNil(t, keys)
	require.Len(t, keys.encryption[:], 32)
	require.Len(t, keys.hmac[:], 32)
}

func TestDeriveKeys_OutputIsNonZero(t *testing.T) {
	// Even with a zero master key, HKDF should produce non-trivial output
	masterKey := make([]byte, 32)

	keys, err := deriveKeys(masterKey)
	require.NoError(t, err)

	// Check encryption key is not all zeros
	allZeros := make([]byte, 32)
	require.False(t, bytes.Equal(keys.encryption[:], allZeros), "encryption key should not be all zeros")
	require.False(t, bytes.Equal(keys.hmac[:], allZeros), "hmac key should not be all zeros")
}

func TestHkdfDerive_DifferentInfoProducesDifferentKeys(t *testing.T) {
	masterKey := []byte("01234567890123456789012345678901")

	out1 := make([]byte, 32)
	out2 := make([]byte, 32)

	err := hkdfDerive(masterKey, "info1", out1)
	require.NoError(t, err)

	err = hkdfDerive(masterKey, "info2", out2)
	require.NoError(t, err)

	require.False(t, bytes.Equal(out1, out2), "different info strings should produce different keys")
}

func TestHkdfDerive_SameInfoProducesSameKey(t *testing.T) {
	masterKey := []byte("01234567890123456789012345678901")

	out1 := make([]byte, 32)
	out2 := make([]byte, 32)

	err := hkdfDerive(masterKey, "same-info", out1)
	require.NoError(t, err)

	err = hkdfDerive(masterKey, "same-info", out2)
	require.NoError(t, err)

	require.True(t, bytes.Equal(out1, out2), "same info string should produce same key")
}

// TestDeriveKeys_KnownVector ensures HKDF produces expected output for a known input.
// This helps catch accidental changes to the derivation algorithm.
func TestDeriveKeys_KnownVector(t *testing.T) {
	// Fixed master key for reproducibility
	masterKey := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") // 32 'A's

	keys, err := deriveKeys(masterKey)
	require.NoError(t, err)

	// These values were computed once and captured as test vectors.
	// If they change, the key derivation has changed (breaking backward compatibility).
	expectedEncFirst4 := []byte{0x23, 0xd0, 0x18, 0x35}
	expectedHMACFirst4 := []byte{0xed, 0xb9, 0x92, 0xb6}

	require.Equal(t, expectedEncFirst4, keys.encryption[:4],
		"encryption key derivation changed - this breaks backward compatibility")
	require.Equal(t, expectedHMACFirst4, keys.hmac[:4],
		"hmac key derivation changed - this breaks backward compatibility")
}
