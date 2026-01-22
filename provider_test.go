package encryptedcol

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStaticKeyProvider(t *testing.T) {
	keys := map[string][]byte{
		"v1": testKey("v1"),
		"v2": testKey("v2"),
	}

	provider := NewStaticKeyProvider("v2", keys)

	// Test GetKey
	key, err := provider.GetKey("v1")
	require.NoError(t, err)
	require.True(t, bytes.Equal(testKey("v1"), key))

	key, err = provider.GetKey("v2")
	require.NoError(t, err)
	require.True(t, bytes.Equal(testKey("v2"), key))

	// Test GetKey not found
	_, err = provider.GetKey("nonexistent")
	require.ErrorIs(t, err, ErrKeyNotFound)

	// Test DefaultKeyID
	require.Equal(t, "v2", provider.DefaultKeyID())

	// Test ActiveKeyIDs
	ids := provider.ActiveKeyIDs()
	require.Len(t, ids, 2)
	require.Contains(t, ids, "v1")
	require.Contains(t, ids, "v2")
}

func TestNewWithProvider(t *testing.T) {
	keys := map[string][]byte{
		"v1": testKey("v1"),
		"v2": testKey("v2"),
	}

	provider := NewStaticKeyProvider("v2", keys)

	cipher, err := NewWithProvider(provider)
	require.NoError(t, err)
	require.Equal(t, "v2", cipher.DefaultKeyID())
	require.Len(t, cipher.ActiveKeyIDs(), 2)

	// Verify encryption works
	plaintext := []byte("test data")
	ciphertext := cipher.Seal(plaintext)
	decrypted, err := cipher.Open(ciphertext)
	require.NoError(t, err)
	require.True(t, bytes.Equal(plaintext, decrypted))
}

func TestNewWithProvider_NoKeys(t *testing.T) {
	provider := NewStaticKeyProvider("v1", map[string][]byte{})

	_, err := NewWithProvider(provider)
	require.ErrorIs(t, err, ErrNoKeys)
}

func TestNewWithProvider_DefaultKeyNotFound(t *testing.T) {
	keys := map[string][]byte{
		"v1": testKey("v1"),
	}

	provider := NewStaticKeyProvider("nonexistent", keys)

	_, err := NewWithProvider(provider)
	require.ErrorIs(t, err, ErrDefaultKeyNotFound)
}

func TestNewWithProvider_InvalidKeySize(t *testing.T) {
	keys := map[string][]byte{
		"v1": []byte("too short"),
	}

	provider := NewStaticKeyProvider("v1", keys)

	_, err := NewWithProvider(provider)
	require.ErrorIs(t, err, ErrInvalidKeySize)
}

// mockKeyProvider for testing error cases
type mockKeyProvider struct {
	keys      map[string][]byte
	defaultID string
	getKeyErr error
}

func (m *mockKeyProvider) GetKey(keyID string) ([]byte, error) {
	if m.getKeyErr != nil {
		return nil, m.getKeyErr
	}
	key, ok := m.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return key, nil
}

func (m *mockKeyProvider) DefaultKeyID() string {
	return m.defaultID
}

func (m *mockKeyProvider) ActiveKeyIDs() []string {
	ids := make([]string, 0, len(m.keys))
	for id := range m.keys {
		ids = append(ids, id)
	}
	return ids
}

func TestNewWithProvider_GetKeyError(t *testing.T) {
	provider := &mockKeyProvider{
		keys:      map[string][]byte{"v1": testKey("v1")},
		defaultID: "v1",
		getKeyErr: ErrKeyNotFound,
	}

	_, err := NewWithProvider(provider)
	require.ErrorIs(t, err, ErrKeyNotFound)
}

func TestStaticKeyProvider_ActiveKeyIDs_Sorted(t *testing.T) {
	// Add keys in non-alphabetical order
	keys := map[string][]byte{
		"zebra":   testKey("zebra"),
		"alpha":   testKey("alpha"),
		"charlie": testKey("charlie"),
		"bravo":   testKey("bravo"),
	}

	provider := NewStaticKeyProvider("alpha", keys)

	ids := provider.ActiveKeyIDs()
	require.Equal(t, []string{"alpha", "bravo", "charlie", "zebra"}, ids,
		"ActiveKeyIDs should return keys in alphabetical order")
}

func TestStaticKeyProvider_Close(t *testing.T) {
	originalKey := make([]byte, 32)
	copy(originalKey, testKey("v1"))

	keys := map[string][]byte{
		"v1": originalKey,
	}

	provider := NewStaticKeyProvider("v1", keys)

	// Verify key works before close
	key, err := provider.GetKey("v1")
	require.NoError(t, err)
	require.NotNil(t, key)

	// Close zeroes out keys
	provider.Close()

	// Keys should be nil after close
	require.Nil(t, provider.keys)
}

func TestStaticKeyProvider_GetKey_ReturnsCopy(t *testing.T) {
	originalKey := testKey("v1")
	keys := map[string][]byte{
		"v1": originalKey,
	}

	provider := NewStaticKeyProvider("v1", keys)

	// Get the key
	key1, err := provider.GetKey("v1")
	require.NoError(t, err)

	// Modify the returned key
	key1[0] = 0xFF
	key1[1] = 0xFF

	// Get the key again - should be unaffected
	key2, err := provider.GetKey("v1")
	require.NoError(t, err)

	require.NotEqual(t, key1[0], key2[0], "GetKey should return a copy, not internal reference")
}
