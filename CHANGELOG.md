# Changelog

## [1.0.3] - 2026-03-27

### Added
- Test coverage improvements from 95.7% to 97.4% based on rcodegen report analysis (Claude:Opus 4.6)
- `TestOpenWithKey_SuccessPath` - covers happy path of explicit-key decryption
- `TestOpenWithKey_InvalidFormat` - covers parseFormat error path in OpenWithKey
- `TestOpenWithKey_OuterKeyIDMismatch` - covers outer key ID verification in OpenWithKey
- `TestOpenJSON_DecryptionError` - covers Open() error propagation in OpenJSON
- `TestOpenInt64_DecryptionError` - covers Open() error propagation in OpenInt64
- `TestWithKey_InitializesNilKeysMap` - covers defensive nil map check in WithKey
- `TestDecompressZstd_ExceedsMaxSize` - covers zip bomb protection (64MB limit)
- `TestDecompressZstd_AtExactLimit` - covers boundary at exactly maxDecompressedSize
- Column name validation tests for digit-first characters (starts_with_digit, only_digits)

## [1.0.2] - 2026-03-07
- Sync uncommitted changes

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-02-17

### Changed
- Comprehensive README rewrite with full API documentation, usage examples, ciphertext format specification, error reference, security notes, and database schema guidance (Claude:Opus 4.6)

## [1.0.0] - 2026-02-08

### Changed
- Promoted to v1.0.0 stable release

## [0.1.0] - 2026-01-19

### Added
- Initial implementation of encryptedcol library
- XSalsa20-Poly1305 (secretbox) encryption with 24-byte random nonces
- HKDF-SHA256 key derivation from master keys
- HMAC-SHA256 blind indexing for searchable encryption
- Multi-key support for key rotation
- Zstd compression for large payloads (threshold-based)
- Normalizers for email, username, phone (case-insensitive search)
- Type-safe helpers for strings, JSON, and integers
- SearchCondition builder for multi-key blind index queries
- Key rotation helpers (RotateValue, RotateBlindIndex)
- NULL vs empty string preservation
- Buffer pooling for compression work buffers
