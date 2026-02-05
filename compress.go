package encryptedcol

import (
	"sync"

	"github.com/klauspost/compress/zstd"
)

// Default compression settings
const (
	defaultCompressionThreshold = 1024 // 1KB
	minCompressionSavings       = 0.10 // 10% minimum savings to use compression

	// maxDecompressedSize is the maximum allowed decompressed size (64MB).
	// This prevents zip bomb attacks where a small compressed payload
	// expands to consume all available memory.
	maxDecompressedSize = 64 * 1024 * 1024
)

// Compression algorithm identifiers
const (
	compressionAlgorithmZstd   = "zstd"
	compressionAlgorithmSnappy = "snappy"
)

var (
	// zstd encoder and decoder are thread-safe and reusable
	zstdEncoder *zstd.Encoder
	zstdDecoder *zstd.Decoder
	zstdOnce    sync.Once
	zstdErr     error
)

// initZstd initializes the zstd encoder and decoder once.
func initZstd() (*zstd.Encoder, *zstd.Decoder, error) {
	zstdOnce.Do(func() {
		zstdEncoder, zstdErr = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
		if zstdErr != nil {
			return
		}
		zstdDecoder, zstdErr = zstd.NewReader(nil)
		if zstdErr != nil {
			// Clean up encoder if decoder creation fails
			zstdEncoder.Close()
			zstdEncoder = nil
		}
	})
	return zstdEncoder, zstdDecoder, zstdErr
}

// compressZstd compresses data using zstd.
// Returns the compressed data.
func compressZstd(data []byte) ([]byte, error) {
	encoder, _, err := initZstd()
	if err != nil {
		return nil, err
	}
	return encoder.EncodeAll(data, nil), nil
}

// decompressZstd decompresses zstd-compressed data.
// Returns ErrDecompressionFailed if decompressed size exceeds maxDecompressedSize.
func decompressZstd(data []byte) ([]byte, error) {
	_, decoder, err := initZstd()
	if err != nil {
		return nil, err
	}
	result, err := decoder.DecodeAll(data, nil)
	if err != nil {
		return nil, ErrDecompressionFailed
	}
	if len(result) > maxDecompressedSize {
		return nil, ErrDecompressionFailed
	}
	return result, nil
}

// maybeCompress compresses data if it exceeds the threshold and compression is beneficial.
// Returns the (possibly compressed) data and the flag byte indicating compression status.
func maybeCompress(data []byte, threshold int, algorithm string, disabled bool) ([]byte, byte) {
	// Skip compression if disabled or below threshold
	if disabled || len(data) < threshold {
		return data, flagNoCompression
	}

	// Only zstd is supported for now
	if algorithm != compressionAlgorithmZstd {
		return data, flagNoCompression
	}

	compressed, err := compressZstd(data)
	if err != nil {
		// If compression fails, return uncompressed
		return data, flagNoCompression
	}

	// Check if compression achieved minimum savings (10%)
	originalSize := len(data)
	compressedSize := len(compressed)
	savings := float64(originalSize-compressedSize) / float64(originalSize)

	if savings < minCompressionSavings {
		// Compression didn't save enough, use original
		return data, flagNoCompression
	}

	return compressed, flagZstd
}

// decompress decompresses data based on the flag byte.
func decompress(data []byte, flag byte) ([]byte, error) {
	switch flag {
	case flagNoCompression:
		return data, nil
	case flagZstd:
		return decompressZstd(data)
	case flagSnappy:
		// NOTE: Snappy is reserved for future implementation. The constant is
		// defined to maintain forward compatibility in the ciphertext format.
		return nil, ErrUnsupportedCompression
	default:
		return nil, ErrInvalidFormat
	}
}
