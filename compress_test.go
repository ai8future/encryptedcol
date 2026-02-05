package encryptedcol

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompressZstd_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"small text", []byte("hello world")},
		{"empty", []byte{}},
		{"binary", []byte{0x00, 0x01, 0x02, 0xff, 0xfe}},
		{"large text", []byte(strings.Repeat("hello world ", 1000))},
		{"json-like", []byte(`{"name":"test","values":[1,2,3,4,5],"nested":{"a":"b"}}`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed, err := compressZstd(tt.data)
			require.NoError(t, err)

			decompressed, err := decompressZstd(compressed)
			require.NoError(t, err)
			require.True(t, bytes.Equal(tt.data, decompressed))
		})
	}
}

func TestCompressZstd_ActuallyCompresses(t *testing.T) {
	// Highly compressible data
	data := []byte(strings.Repeat("aaaaaaaaaa", 1000)) // 10KB of 'a's

	compressed, err := compressZstd(data)
	require.NoError(t, err)

	// Should be significantly smaller
	require.Less(t, len(compressed), len(data)/2, "compression should reduce size by at least 50%")
}

func TestMaybeCompress_BelowThreshold(t *testing.T) {
	data := []byte("small")
	threshold := 1024

	result, flag := maybeCompress(data, threshold, compressionAlgorithmZstd, false)

	require.Equal(t, flagNoCompression, flag)
	require.True(t, bytes.Equal(data, result))
}

func TestMaybeCompress_AboveThreshold(t *testing.T) {
	// Compressible data above threshold
	data := []byte(strings.Repeat("hello world ", 200)) // ~2.4KB

	result, flag := maybeCompress(data, 1024, compressionAlgorithmZstd, false)

	require.Equal(t, flagZstd, flag)
	require.Less(t, len(result), len(data), "compressed should be smaller")
}

func TestMaybeCompress_Disabled(t *testing.T) {
	data := []byte(strings.Repeat("hello world ", 200))

	result, flag := maybeCompress(data, 1024, compressionAlgorithmZstd, true)

	require.Equal(t, flagNoCompression, flag)
	require.True(t, bytes.Equal(data, result))
}

func TestMaybeCompress_InsufficientSavings(t *testing.T) {
	// Random-looking data that doesn't compress well
	data := make([]byte, 2000)
	for i := range data {
		data[i] = byte(i * 17 % 256) // pseudo-random pattern
	}

	result, flag := maybeCompress(data, 1024, compressionAlgorithmZstd, false)

	// If savings < 10%, should not compress
	if flag == flagNoCompression {
		require.True(t, bytes.Equal(data, result))
	} else {
		// If it did compress, verify savings >= 10%
		savings := float64(len(data)-len(result)) / float64(len(data))
		require.GreaterOrEqual(t, savings, minCompressionSavings)
	}
}

func TestMaybeCompress_UnsupportedAlgorithm(t *testing.T) {
	data := []byte(strings.Repeat("hello ", 500))

	result, flag := maybeCompress(data, 100, "unknown", false)

	require.Equal(t, flagNoCompression, flag)
	require.True(t, bytes.Equal(data, result))
}

func TestDecompress_NoCompression(t *testing.T) {
	data := []byte("uncompressed data")

	result, err := decompress(data, flagNoCompression)
	require.NoError(t, err)
	require.True(t, bytes.Equal(data, result))
}

func TestDecompress_Zstd(t *testing.T) {
	original := []byte("test data for compression")
	compressed, err := compressZstd(original)
	require.NoError(t, err)

	result, err := decompress(compressed, flagZstd)
	require.NoError(t, err)
	require.True(t, bytes.Equal(original, result))
}

func TestDecompress_InvalidZstd(t *testing.T) {
	invalidData := []byte("not valid zstd data")

	_, err := decompress(invalidData, flagZstd)
	require.ErrorIs(t, err, ErrDecompressionFailed)
}

func TestDecompress_UnknownFlag(t *testing.T) {
	data := []byte("data")

	_, err := decompress(data, 0xFF)
	require.ErrorIs(t, err, ErrInvalidFormat)
}

func TestDecompress_Snappy(t *testing.T) {
	// Snappy is reserved but not implemented
	data := []byte("data")

	_, err := decompress(data, flagSnappy)
	require.ErrorIs(t, err, ErrUnsupportedCompression)
}

func TestCompressZstd_Concurrent(t *testing.T) {
	// Test that zstd encoder/decoder are safe for concurrent use
	data := []byte(strings.Repeat("concurrent test data ", 100))

	var wg sync.WaitGroup
	errors := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			compressed, err := compressZstd(data)
			if err != nil {
				errors <- err
				return
			}

			decompressed, err := decompressZstd(compressed)
			if err != nil {
				errors <- err
				return
			}

			if !bytes.Equal(data, decompressed) {
				errors <- ErrDecompressionFailed
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Fatalf("concurrent compression error: %v", err)
	}
}

func TestMaybeCompress_ExactThreshold(t *testing.T) {
	// Data exactly at threshold
	data := make([]byte, 1024)
	for i := range data {
		data[i] = 'a' // Compressible
	}

	result, flag := maybeCompress(data, 1024, compressionAlgorithmZstd, false)

	// At exactly threshold, should attempt compression
	require.Equal(t, flagZstd, flag, "at threshold should compress")
	require.Less(t, len(result), len(data))
}

func TestMaybeCompress_JustBelowThreshold(t *testing.T) {
	data := make([]byte, 1023)
	for i := range data {
		data[i] = 'a'
	}

	result, flag := maybeCompress(data, 1024, compressionAlgorithmZstd, false)

	require.Equal(t, flagNoCompression, flag, "below threshold should not compress")
	require.True(t, bytes.Equal(data, result))
}
