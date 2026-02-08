# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
