package encryptedcol

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestErrors_Identity(t *testing.T) {
	// Verify each error is a distinct sentinel error
	allErrors := []error{
		ErrDecryptionFailed,
		ErrKeyIDMismatch,
		ErrKeyNotFound,
		ErrInvalidKeySize,
		ErrWasNull,
		ErrDecompressionFailed,
		ErrInvalidFormat,
		ErrNoKeys,
		ErrDefaultKeyNotFound,
		ErrInvalidKeyID,
		ErrUnsupportedCompression,
		ErrCipherClosed,
	}

	// Each error should be equal to itself
	for _, err := range allErrors {
		require.True(t, errors.Is(err, err), "error should be equal to itself: %v", err)
	}

	// Each pair of different errors should not be equal
	for i, err1 := range allErrors {
		for j, err2 := range allErrors {
			if i != j {
				require.False(t, errors.Is(err1, err2), "different errors should not be equal: %v and %v", err1, err2)
			}
		}
	}
}

func TestErrors_Messages(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains string
	}{
		{"ErrDecryptionFailed", ErrDecryptionFailed, "decryption failed"},
		{"ErrKeyIDMismatch", ErrKeyIDMismatch, "key_id mismatch"},
		{"ErrKeyNotFound", ErrKeyNotFound, "key not found"},
		{"ErrInvalidKeySize", ErrInvalidKeySize, "32 bytes"},
		{"ErrWasNull", ErrWasNull, "null"},
		{"ErrDecompressionFailed", ErrDecompressionFailed, "decompression failed"},
		{"ErrInvalidFormat", ErrInvalidFormat, "invalid ciphertext format"},
		{"ErrNoKeys", ErrNoKeys, "no keys"},
		{"ErrDefaultKeyNotFound", ErrDefaultKeyNotFound, "default key not found"},
		{"ErrInvalidKeyID", ErrInvalidKeyID, "key ID"},
		{"ErrUnsupportedCompression", ErrUnsupportedCompression, "unsupported compression"},
		{"ErrCipherClosed", ErrCipherClosed, "cipher is closed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Contains(t, tt.err.Error(), tt.contains)
			require.Contains(t, tt.err.Error(), "encryptedcol:")
		})
	}
}

func TestErrors_Wrapping(t *testing.T) {
	// Verify errors can be wrapped and unwrapped
	wrapped := errors.Join(ErrDecryptionFailed, errors.New("additional context"))
	require.True(t, errors.Is(wrapped, ErrDecryptionFailed))
}
