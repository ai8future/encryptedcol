package encryptedcol

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWithKey(t *testing.T) {
	key := testKey("v1")

	cipher, err := New(WithKey("v1", key))
	require.NoError(t, err)
	require.Equal(t, "v1", cipher.DefaultKeyID())
}

func TestWithKey_Multiple(t *testing.T) {
	cipher, err := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
		WithKey("v3", testKey("v3")),
	)
	require.NoError(t, err)
	require.Len(t, cipher.ActiveKeyIDs(), 3)
}

func TestWithKey_FirstKeyBecomesDefault(t *testing.T) {
	// First key should become default if not specified
	cipher, err := New(
		WithKey("first", testKey("first")),
		WithKey("second", testKey("second")),
	)
	require.NoError(t, err)
	require.Equal(t, "first", cipher.DefaultKeyID())
}

func TestWithDefaultKeyID(t *testing.T) {
	cipher, err := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
		WithDefaultKeyID("v2"),
	)
	require.NoError(t, err)
	require.Equal(t, "v2", cipher.DefaultKeyID())
}

func TestWithDefaultKeyID_NotFound(t *testing.T) {
	_, err := New(
		WithKey("v1", testKey("v1")),
		WithDefaultKeyID("nonexistent"),
	)
	require.ErrorIs(t, err, ErrDefaultKeyNotFound)
}

func TestWithCompressionThreshold(t *testing.T) {
	cipher, err := New(
		WithKey("v1", testKey("v1")),
		WithCompressionThreshold(500),
	)
	require.NoError(t, err)
	require.Equal(t, 500, cipher.config.compressionThreshold)
}

func TestWithCompressionAlgorithm(t *testing.T) {
	cipher, err := New(
		WithKey("v1", testKey("v1")),
		WithCompressionAlgorithm("zstd"),
	)
	require.NoError(t, err)
	require.Equal(t, "zstd", cipher.config.compressionAlgorithm)
}

func TestWithCompressionAlgorithm_Unsupported(t *testing.T) {
	_, err := New(
		WithKey("v1", testKey("v1")),
		WithCompressionAlgorithm("snappy"),
	)
	require.ErrorIs(t, err, ErrUnsupportedCompression)
}

func TestWithCompressionDisabled(t *testing.T) {
	cipher, err := New(
		WithKey("v1", testKey("v1")),
		WithCompressionDisabled(),
	)
	require.NoError(t, err)
	require.True(t, cipher.config.compressionDisabled)
}

func TestWithEmptyStringAsNull(t *testing.T) {
	cipher, err := New(
		WithKey("v1", testKey("v1")),
		WithEmptyStringAsNull(),
	)
	require.NoError(t, err)
	require.True(t, cipher.config.emptyStringAsNull)
}

func TestDefaultConfig(t *testing.T) {
	cipher, err := New(WithKey("v1", testKey("v1")))
	require.NoError(t, err)

	// Check defaults
	require.Equal(t, defaultCompressionThreshold, cipher.config.compressionThreshold)
	require.Equal(t, compressionAlgorithmZstd, cipher.config.compressionAlgorithm)
	require.False(t, cipher.config.compressionDisabled)
	require.False(t, cipher.config.emptyStringAsNull)
}

func TestOptions_ChainedCorrectly(t *testing.T) {
	cipher, err := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
		WithDefaultKeyID("v2"),
		WithCompressionThreshold(2048),
		WithCompressionAlgorithm("zstd"),
	)
	require.NoError(t, err)

	require.Equal(t, "v2", cipher.DefaultKeyID())
	require.Len(t, cipher.ActiveKeyIDs(), 2)
	require.Equal(t, 2048, cipher.config.compressionThreshold)
	require.Equal(t, "zstd", cipher.config.compressionAlgorithm)
}
