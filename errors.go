package encryptedcol

import "errors"

var (
	// ErrDecryptionFailed indicates secretbox authentication failed (wrong key or corrupted data).
	ErrDecryptionFailed = errors.New("encryptedcol: decryption failed")

	// ErrKeyIDMismatch indicates the inner key_id doesn't match the outer key_id (tampering detected).
	ErrKeyIDMismatch = errors.New("encryptedcol: key_id mismatch")

	// ErrKeyNotFound indicates the requested key_id is not in the registry or provider.
	ErrKeyNotFound = errors.New("encryptedcol: key not found")

	// ErrInvalidKeySize indicates the master key is not exactly 32 bytes.
	ErrInvalidKeySize = errors.New("encryptedcol: key must be 32 bytes")

	// ErrWasNull indicates the ciphertext was nil (database NULL).
	// Returned by OpenString when input is nil; value will be "".
	ErrWasNull = errors.New("encryptedcol: value was null")

	// ErrDecompressionFailed indicates zstd/snappy decompression failed.
	ErrDecompressionFailed = errors.New("encryptedcol: decompression failed")

	// ErrInvalidFormat indicates the ciphertext format is malformed.
	ErrInvalidFormat = errors.New("encryptedcol: invalid ciphertext format")

	// ErrNoKeys indicates no keys were provided to the cipher.
	ErrNoKeys = errors.New("encryptedcol: no keys provided")

	// ErrDefaultKeyNotFound indicates the specified default key ID was not found.
	ErrDefaultKeyNotFound = errors.New("encryptedcol: default key not found")

	// ErrInvalidKeyID indicates the key ID is invalid (empty or too long).
	ErrInvalidKeyID = errors.New("encryptedcol: key ID must be 1-255 bytes")

	// ErrUnsupportedCompression indicates an unsupported compression algorithm.
	ErrUnsupportedCompression = errors.New("encryptedcol: unsupported compression algorithm")

	// ErrCipherClosed indicates the cipher was used after Close() was called.
	ErrCipherClosed = errors.New("encryptedcol: cipher is closed")
)
