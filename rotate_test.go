package encryptedcol

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRotateValue(t *testing.T) {
	cipher, _ := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
		WithDefaultKeyID("v2"),
	)

	// Encrypt with v1
	oldCiphertext, _ := cipher.SealWithKey("v1", []byte("secret data"))

	// Rotate to v2
	newCiphertext, err := cipher.RotateValue(oldCiphertext)
	require.NoError(t, err)

	// Should be different ciphertext
	require.False(t, bytes.Equal(oldCiphertext, newCiphertext))

	// But same plaintext
	result, err := cipher.Open(newCiphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("secret data"), result)

	// New ciphertext should use v2
	keyID, _ := cipher.ExtractKeyID(newCiphertext)
	require.Equal(t, "v2", keyID)
}

func TestRotateValue_Null(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	result, err := cipher.RotateValue(nil)
	require.NoError(t, err)
	require.Nil(t, result)
}

func TestRotateBlindIndex(t *testing.T) {
	cipher, _ := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
		WithDefaultKeyID("v2"),
	)

	plaintext := []byte("test@example.com")

	// Get index for v1
	idx1, _ := cipher.BlindIndexWithKey("v1", plaintext)

	// Rotate to v2 (using plaintext)
	idx2 := cipher.RotateBlindIndex(plaintext)

	// Should be different (different keys)
	require.False(t, bytes.Equal(idx1, idx2))

	// Should match v2 index
	expectedV2, _ := cipher.BlindIndexWithKey("v2", plaintext)
	require.True(t, bytes.Equal(idx2, expectedV2))
}

func TestRotateBlindIndex_Null(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	result := cipher.RotateBlindIndex(nil)
	require.Nil(t, result)
}

func TestRotateStringIndexed(t *testing.T) {
	cipher, _ := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
		WithDefaultKeyID("v2"),
	)

	// Encrypt with v1
	oldCiphertext, _ := cipher.SealWithKey("v1", []byte("alice@example.com"))

	// Rotate
	sealed, err := cipher.RotateStringIndexed(oldCiphertext)
	require.NoError(t, err)

	require.NotNil(t, sealed.Ciphertext)
	require.NotNil(t, sealed.BlindIndex)
	require.Equal(t, "v2", sealed.KeyID)

	// Verify plaintext preserved
	result, _ := cipher.OpenString(sealed.Ciphertext)
	require.Equal(t, "alice@example.com", result)

	// Verify blind index is for v2
	expectedIdx, _ := cipher.BlindIndexWithKey("v2", []byte("alice@example.com"))
	require.True(t, bytes.Equal(sealed.BlindIndex, expectedIdx))
}

func TestRotateStringIndexed_Null(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	sealed, err := cipher.RotateStringIndexed(nil)
	require.NoError(t, err)
	require.Nil(t, sealed.Ciphertext)
	require.Nil(t, sealed.BlindIndex)
}

func TestRotateStringIndexedNormalized(t *testing.T) {
	cipher, _ := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
		WithDefaultKeyID("v2"),
	)

	// Encrypt with v1 (original case preserved)
	oldCiphertext, _ := cipher.SealWithKey("v1", []byte("Alice@Example.COM"))

	// Rotate with normalization
	sealed, err := cipher.RotateStringIndexedNormalized(oldCiphertext, NormalizeEmail)
	require.NoError(t, err)

	// Ciphertext should preserve original case
	result, _ := cipher.OpenString(sealed.Ciphertext)
	require.Equal(t, "Alice@Example.COM", result)

	// Blind index should be normalized
	expectedIdx, _ := cipher.BlindIndexWithKey("v2", []byte("alice@example.com"))
	require.True(t, bytes.Equal(sealed.BlindIndex, expectedIdx))
}

func TestRotateStringIndexedNormalized_Null(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	sealed, err := cipher.RotateStringIndexedNormalized(nil, NormalizeEmail)
	require.NoError(t, err)
	require.Nil(t, sealed.Ciphertext)
	require.Nil(t, sealed.BlindIndex)
}

func TestNeedsRotation(t *testing.T) {
	cipher, _ := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
		WithDefaultKeyID("v2"),
	)

	// Encrypted with v1 (old key)
	ct1, _ := cipher.SealWithKey("v1", []byte("test"))
	require.True(t, cipher.NeedsRotation(ct1))

	// Encrypted with v2 (current default)
	ct2 := cipher.Seal([]byte("test"))
	require.False(t, cipher.NeedsRotation(ct2))

	// NULL doesn't need rotation
	require.False(t, cipher.NeedsRotation(nil))
}

func TestExtractKeyID(t *testing.T) {
	cipher, _ := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
	)

	ct1, _ := cipher.SealWithKey("v1", []byte("test"))
	keyID1, err := cipher.ExtractKeyID(ct1)
	require.NoError(t, err)
	require.Equal(t, "v1", keyID1)

	ct2, _ := cipher.SealWithKey("v2", []byte("test"))
	keyID2, err := cipher.ExtractKeyID(ct2)
	require.NoError(t, err)
	require.Equal(t, "v2", keyID2)
}

func TestExtractKeyID_Null(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	keyID, err := cipher.ExtractKeyID(nil)
	require.NoError(t, err)
	require.Equal(t, "", keyID)
}

func TestExtractKeyID_Invalid(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	_, err := cipher.ExtractKeyID([]byte{0x00})
	require.ErrorIs(t, err, ErrInvalidFormat)
}

func TestRotateValue_DecryptionError(t *testing.T) {
	cipher1, _ := New(WithKey("v1", testKey("v1")))
	cipher2, _ := New(WithKey("v2", testKey("v2")))

	ct := cipher1.Seal([]byte("test"))

	// cipher2 can't decrypt cipher1's ciphertext
	_, err := cipher2.RotateValue(ct)
	require.Error(t, err)
}

func TestRotateStringIndexed_DecryptionError(t *testing.T) {
	cipher1, _ := New(WithKey("v1", testKey("v1")))
	cipher2, _ := New(WithKey("v2", testKey("v2")))

	ct := cipher1.Seal([]byte("test@example.com"))

	_, err := cipher2.RotateStringIndexed(ct)
	require.Error(t, err)
}

func TestRotateStringIndexedNormalized_DecryptionError(t *testing.T) {
	cipher1, _ := New(WithKey("v1", testKey("v1")))
	cipher2, _ := New(WithKey("v2", testKey("v2")))

	ct := cipher1.Seal([]byte("test@example.com"))

	_, err := cipher2.RotateStringIndexedNormalized(ct, NormalizeEmail)
	require.Error(t, err)
}

func TestNeedsRotation_InvalidFormat(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	// Invalid ciphertext should return false (graceful degradation)
	require.False(t, cipher.NeedsRotation([]byte{0x00}))
}

func TestRotation_CompleteWorkflow(t *testing.T) {
	// Simulate a complete key rotation workflow

	// Phase 1: Start with v1
	cipher1, _ := New(WithKey("v1", testKey("v1")))

	originalData := "alice@example.com"
	ct1 := cipher1.SealString(originalData)
	idx1 := cipher1.BlindIndexString(NormalizeEmail(originalData))

	// Phase 2: Add v2, make it default (both keys available)
	cipher2, _ := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
		WithDefaultKeyID("v2"),
	)

	// Can still decrypt v1 data
	data, err := cipher2.OpenString(ct1)
	require.NoError(t, err)
	require.Equal(t, originalData, data)

	// Rotate to v2
	newSealed, err := cipher2.RotateStringIndexedNormalized(ct1, NormalizeEmail)
	require.NoError(t, err)

	// Verify new ciphertext uses v2
	require.Equal(t, "v2", newSealed.KeyID)
	keyID, _ := cipher2.ExtractKeyID(newSealed.Ciphertext)
	require.Equal(t, "v2", keyID)

	// Phase 3: Remove v1 (only v2 available)
	cipher3, _ := New(WithKey("v2", testKey("v2")))

	// Can decrypt rotated data
	data, err = cipher3.OpenString(newSealed.Ciphertext)
	require.NoError(t, err)
	require.Equal(t, originalData, data)

	// Old index (v1) won't work for search
	idx3 := cipher3.BlindIndexString(NormalizeEmail(originalData))
	require.False(t, bytes.Equal(idx1, idx3), "v1 and v2 indexes should differ")

	// New index matches rotated data
	require.True(t, bytes.Equal(newSealed.BlindIndex, idx3))
}
