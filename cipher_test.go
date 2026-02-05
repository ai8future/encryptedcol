package encryptedcol

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/secretbox"
)

func testKey(id string) []byte {
	// Generate a deterministic 32-byte key for testing
	key := make([]byte, 32)
	copy(key, []byte(id))
	for i := len(id); i < 32; i++ {
		key[i] = byte(i)
	}
	return key
}

func TestNew_SingleKey(t *testing.T) {
	cipher, err := New(WithKey("v1", testKey("v1")))
	require.NoError(t, err)
	require.NotNil(t, cipher)
	require.Equal(t, "v1", cipher.DefaultKeyID())
	require.Equal(t, []string{"v1"}, cipher.ActiveKeyIDs())
}

func TestNew_MultipleKeys(t *testing.T) {
	cipher, err := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
		WithDefaultKeyID("v2"),
	)
	require.NoError(t, err)
	require.Equal(t, "v2", cipher.DefaultKeyID())
	require.Len(t, cipher.ActiveKeyIDs(), 2)
}

func TestNew_NoKeys(t *testing.T) {
	_, err := New()
	require.ErrorIs(t, err, ErrNoKeys)
}

func TestNew_DefaultKeyNotFound(t *testing.T) {
	_, err := New(
		WithKey("v1", testKey("v1")),
		WithDefaultKeyID("nonexistent"),
	)
	require.ErrorIs(t, err, ErrDefaultKeyNotFound)
}

func TestNew_InvalidKeySize(t *testing.T) {
	_, err := New(WithKey("v1", []byte("too short")))
	require.ErrorIs(t, err, ErrInvalidKeySize)
}

func TestSealOpen_RoundTrip(t *testing.T) {
	cipher, err := New(WithKey("v1", testKey("v1")))
	require.NoError(t, err)

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"simple text", []byte("hello world")},
		{"empty slice", []byte{}},
		{"binary data", []byte{0x00, 0x01, 0x02, 0xff, 0xfe}},
		{"unicode", []byte("こんにちは世界")},
		{"large text", []byte(strings.Repeat("x", 10000))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext := cipher.Seal(tt.plaintext)
			require.NotNil(t, ciphertext)
			require.NotEqual(t, tt.plaintext, ciphertext)

			decrypted, err := cipher.Open(ciphertext)
			require.NoError(t, err)
			require.True(t, bytes.Equal(tt.plaintext, decrypted))
		})
	}
}

func TestSealOpen_NullPreservation(t *testing.T) {
	cipher, err := New(WithKey("v1", testKey("v1")))
	require.NoError(t, err)

	// nil input -> nil output
	ciphertext := cipher.Seal(nil)
	require.Nil(t, ciphertext)

	// nil ciphertext -> nil plaintext, no error
	plaintext, err := cipher.Open(nil)
	require.NoError(t, err)
	require.Nil(t, plaintext)
}

func TestSealOpen_EmptySlice(t *testing.T) {
	cipher, err := New(WithKey("v1", testKey("v1")))
	require.NoError(t, err)

	// Empty slice is NOT nil - it should encrypt
	ciphertext := cipher.Seal([]byte{})
	require.NotNil(t, ciphertext)

	plaintext, err := cipher.Open(ciphertext)
	require.NoError(t, err)
	require.NotNil(t, plaintext)
	require.Len(t, plaintext, 0)
}

func TestSealOpen_MultiKey(t *testing.T) {
	cipher, err := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
		WithDefaultKeyID("v2"),
	)
	require.NoError(t, err)

	// Encrypt with v1
	ct1, err := cipher.SealWithKey("v1", []byte("hello"))
	require.NoError(t, err)

	// Encrypt with v2 (default)
	ct2 := cipher.Seal([]byte("world"))

	// Both should decrypt correctly
	pt1, err := cipher.Open(ct1)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt1)

	pt2, err := cipher.Open(ct2)
	require.NoError(t, err)
	require.Equal(t, []byte("world"), pt2)
}

func TestSealWithKey_NotFound(t *testing.T) {
	cipher, err := New(WithKey("v1", testKey("v1")))
	require.NoError(t, err)

	_, err = cipher.SealWithKey("nonexistent", []byte("test"))
	require.ErrorIs(t, err, ErrKeyNotFound)
}

func TestOpen_KeyNotFound(t *testing.T) {
	cipher1, _ := New(WithKey("v1", testKey("v1")))
	cipher2, _ := New(WithKey("v2", testKey("v2")))

	ciphertext := cipher1.Seal([]byte("test"))

	// cipher2 doesn't have v1 key
	_, err := cipher2.Open(ciphertext)
	require.ErrorIs(t, err, ErrKeyNotFound)
}

func TestOpen_WrongKey(t *testing.T) {
	cipher1, _ := New(WithKey("v1", testKey("v1")))
	cipher2, _ := New(WithKey("v1", testKey("different")))

	ciphertext := cipher1.Seal([]byte("test"))

	// cipher2 has v1 key but with different value
	_, err := cipher2.Open(ciphertext)
	require.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestOpen_TamperedKeyID(t *testing.T) {
	cipher, _ := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
	)

	ciphertext := cipher.Seal([]byte("test"))

	// Tamper with outer key_id (byte 2 is start of key_id)
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	// Change "v1" to "v2" in outer header
	tampered[2] = 'v'
	tampered[3] = '2'

	// Should fail with key_id mismatch (inner still says v1)
	_, err := cipher.Open(tampered)
	// Could fail with decryption failed or key_id mismatch depending on order
	require.Error(t, err)
}

func TestOpen_InvalidFormat(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{0x00, 0x02, 'v', '1'}},
		{"truncated", []byte{0x00, 0x02, 'v', '1', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := cipher.Open(tt.data)
			require.Error(t, err)
		})
	}
}

func TestOpenWithKey_Mismatch(t *testing.T) {
	cipher, _ := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
	)

	ciphertext := cipher.Seal([]byte("test"))

	// Try to decrypt with wrong key
	_, err := cipher.OpenWithKey("v2", ciphertext)
	require.ErrorIs(t, err, ErrKeyIDMismatch)
}

func TestOpenWithKey_KeyNotFound(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	ciphertext := cipher.Seal([]byte("test"))

	// Try to decrypt with non-existent key
	_, err := cipher.OpenWithKey("nonexistent", ciphertext)
	require.ErrorIs(t, err, ErrKeyNotFound)
}

func TestSealOpen_Concurrent(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	var wg sync.WaitGroup
	errors := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()

			plaintext := []byte(strings.Repeat("x", n%1000+1))
			ciphertext := cipher.Seal(plaintext)

			decrypted, err := cipher.Open(ciphertext)
			if err != nil {
				errors <- err
				return
			}

			if !bytes.Equal(plaintext, decrypted) {
				errors <- ErrDecryptionFailed
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Fatalf("concurrent error: %v", err)
	}
}

func TestSeal_DifferentCiphertextEachTime(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	plaintext := []byte("test")

	ct1 := cipher.Seal(plaintext)
	ct2 := cipher.Seal(plaintext)

	// Same plaintext should produce different ciphertext (random nonce)
	require.False(t, bytes.Equal(ct1, ct2), "ciphertext should differ due to random nonce")
}

func TestSealOpen_WithCompression(t *testing.T) {
	cipher, err := New(
		WithKey("v1", testKey("v1")),
		WithCompressionThreshold(100),
	)
	require.NoError(t, err)

	// Large compressible data
	plaintext := []byte(strings.Repeat("hello world ", 100))

	ciphertext := cipher.Seal(plaintext)
	require.NotNil(t, ciphertext)

	// Ciphertext should be smaller than plaintext + overhead due to compression
	// (plaintext is ~1200 bytes, compressed should be much smaller)
	require.Less(t, len(ciphertext), len(plaintext))

	decrypted, err := cipher.Open(ciphertext)
	require.NoError(t, err)
	require.True(t, bytes.Equal(plaintext, decrypted))
}

func TestSealOpen_CompressionDisabled(t *testing.T) {
	cipher, err := New(
		WithKey("v1", testKey("v1")),
		WithCompressionDisabled(),
	)
	require.NoError(t, err)

	plaintext := []byte(strings.Repeat("hello world ", 100))

	ciphertext := cipher.Seal(plaintext)

	// Should still work, just won't be compressed
	decrypted, err := cipher.Open(ciphertext)
	require.NoError(t, err)
	require.True(t, bytes.Equal(plaintext, decrypted))
}

func TestGenerateNonce_Unique(t *testing.T) {
	nonces := make(map[[24]byte]bool)

	for i := 0; i < 1000; i++ {
		nonce := generateNonce()
		require.False(t, nonces[nonce], "nonce collision detected")
		nonces[nonce] = true
	}
}

func TestClose(t *testing.T) {
	cipher, err := New(WithKey("v1", testKey("v1")))
	require.NoError(t, err)

	// Encrypt something first
	plaintext := []byte("secret data")
	ciphertext := cipher.Seal(plaintext)
	require.NotNil(t, ciphertext)

	// Close zeros out keys
	cipher.Close()

	// Keys should be nil after Close
	require.Nil(t, cipher.keys)
}

func TestClose_UseAfterClose(t *testing.T) {
	cipher, err := New(WithKey("v1", testKey("v1")))
	require.NoError(t, err)

	ciphertext := cipher.Seal([]byte("test"))
	require.NotNil(t, ciphertext)

	cipher.Close()

	// Seal should panic after Close
	require.Panics(t, func() {
		cipher.Seal([]byte("test"))
	})

	// Open should return ErrCipherClosed
	_, err = cipher.Open(ciphertext)
	require.ErrorIs(t, err, ErrCipherClosed)

	// SealWithKey should return ErrCipherClosed
	_, err = cipher.SealWithKey("v1", []byte("test"))
	require.ErrorIs(t, err, ErrCipherClosed)

	// OpenWithKey should return ErrCipherClosed
	_, err = cipher.OpenWithKey("v1", ciphertext)
	require.ErrorIs(t, err, ErrCipherClosed)
}

func TestNew_InvalidKeyID_Empty(t *testing.T) {
	_, err := New(WithKey("", testKey("v1")))
	require.ErrorIs(t, err, ErrInvalidKeyID)
}

func TestNew_InvalidKeyID_TooLong(t *testing.T) {
	longKeyID := strings.Repeat("x", 256)
	_, err := New(WithKey(longKeyID, testKey("v1")))
	require.ErrorIs(t, err, ErrInvalidKeyID)
}

func TestNew_InvalidKeyID_MaxLength(t *testing.T) {
	// 255 bytes should work (max valid length)
	maxKeyID := strings.Repeat("x", 255)
	cipher, err := New(WithKey(maxKeyID, testKey("v1")))
	require.NoError(t, err)
	require.NotNil(t, cipher)
}

func TestSealWithKey_NullPreservation(t *testing.T) {
	cipher, err := New(WithKey("v1", testKey("v1")))
	require.NoError(t, err)

	ciphertext, err := cipher.SealWithKey("v1", nil)
	require.NoError(t, err)
	require.Nil(t, ciphertext)
}

func TestOpenWithKey_NullPreservation(t *testing.T) {
	cipher, err := New(WithKey("v1", testKey("v1")))
	require.NoError(t, err)

	plaintext, err := cipher.OpenWithKey("v1", nil)
	require.NoError(t, err)
	require.Nil(t, plaintext)
}

func TestOpen_InvalidFlag(t *testing.T) {
	cipher, err := New(WithKey("v1", testKey("v1")))
	require.NoError(t, err)

	ciphertext := cipher.Seal([]byte("test"))

	// Tamper with flag byte to invalid value (0xFF)
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[0] = 0xFF

	_, err = cipher.Open(tampered)
	require.ErrorIs(t, err, ErrInvalidFormat)
}

func TestOpen_SnappyFlagUnsupported(t *testing.T) {
	cipher, err := New(WithKey("v1", testKey("v1")))
	require.NoError(t, err)

	ciphertext := cipher.Seal([]byte("test"))

	// Tamper with flag byte to snappy (0x02)
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[0] = flagSnappy

	_, err = cipher.Open(tampered)
	require.ErrorIs(t, err, ErrUnsupportedCompression)
}

func TestActiveKeyIDs_Sorted(t *testing.T) {
	cipher, err := New(
		WithKey("charlie", testKey("charlie")),
		WithKey("alpha", testKey("alpha")),
		WithKey("bravo", testKey("bravo")),
	)
	require.NoError(t, err)

	ids := cipher.ActiveKeyIDs()
	require.Equal(t, []string{"alpha", "bravo", "charlie"}, ids)
}

func TestNew_DefaultKeySelection_FirstRegistered(t *testing.T) {
	// When no default is specified via WithDefaultKeyID,
	// the first key registered via WithKey becomes default
	cipher, err := New(
		WithKey("zebra", testKey("zebra")),
		WithKey("alpha", testKey("alpha")),
		WithKey("mike", testKey("mike")),
	)
	require.NoError(t, err)

	// "zebra" should be selected as default (first registered)
	require.Equal(t, "zebra", cipher.DefaultKeyID())

	// Encryption should use zebra key
	ct := cipher.Seal([]byte("test"))
	keyID, _ := cipher.ExtractKeyID(ct)
	require.Equal(t, "zebra", keyID)
}

func TestNew_DefaultKeyID_AlwaysSetByWithKey(t *testing.T) {
	// This test documents that WithKey always sets defaultKeyID
	// so the sortedMapKeys fallback in New() is dead code
	cfg := defaultConfig()

	// Before any WithKey, defaultKeyID is empty
	require.Equal(t, "", cfg.defaultKeyID)

	// After WithKey, defaultKeyID is set
	WithKey("zebra", testKey("zebra"))(cfg)
	require.Equal(t, "zebra", cfg.defaultKeyID, "WithKey should set defaultKeyID")

	// Additional WithKey calls don't change it
	WithKey("alpha", testKey("alpha"))(cfg)
	require.Equal(t, "zebra", cfg.defaultKeyID, "defaultKeyID should remain first key")
}

// TestOpen_InnerKeyIDMismatch tests the key confusion attack defense.
// This is a security-critical test that verifies the inner key_id
// (authenticated by secretbox) detects when outer key_id is tampered.
func TestOpen_InnerKeyIDMismatch(t *testing.T) {
	cipher, _ := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
	)

	// Manually construct ciphertext with mismatched inner/outer key IDs:
	// - Outer key_id = "v1" (so cipher looks up v1 key)
	// - Inner key_id = "v2" (different from outer)
	// - Encrypt with v1 key (so decryption succeeds)
	// This simulates an attacker who swapped the outer key_id header

	plaintext := []byte("secret data")
	wrongInnerKeyID := "v2"

	// Format inner plaintext with WRONG key ID
	innerPlaintext := formatInnerPlaintext(wrongInnerKeyID, plaintext)

	// Encrypt with v1 key (correct key for outer header)
	keys := cipher.keys["v1"]
	nonce := generateNonce()
	encrypted := secretbox.Seal(nil, innerPlaintext, &nonce, &keys.encryption)

	// Format outer ciphertext with v1 (so it passes key lookup)
	ciphertext := formatCiphertext(flagNoCompression, "v1", nonce, encrypted)

	// Open should succeed in decryption but fail inner key_id verification
	_, err := cipher.Open(ciphertext)
	require.ErrorIs(t, err, ErrKeyIDMismatch)
}

// TestOpen_InvalidInnerPlaintext tests handling of malformed decrypted data.
// After successful decryption, the inner plaintext must have valid format.
func TestOpen_InvalidInnerPlaintext(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	keys := cipher.keys["v1"]
	nonce := generateNonce()

	tests := []struct {
		name         string
		innerPayload []byte
		wantErr      error
	}{
		{
			name:         "single byte (missing key_id)",
			innerPayload: []byte{0x00}, // keyIDLen=0 is invalid
			wantErr:      ErrInvalidFormat,
		},
		{
			name:         "keyIDLen exceeds data",
			innerPayload: []byte{0x05, 'v', '1'}, // claims 5 bytes but only has 2
			wantErr:      ErrInvalidFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt the invalid inner payload
			encrypted := secretbox.Seal(nil, tt.innerPayload, &nonce, &keys.encryption)
			ciphertext := formatCiphertext(flagNoCompression, "v1", nonce, encrypted)

			_, err := cipher.Open(ciphertext)
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}
