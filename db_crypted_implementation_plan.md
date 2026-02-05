# encryptedcol Implementation Plan

Implementation plan for the `encryptedcol` Go library based on the design document at `db_crypted_design.md`.

## Project Setup

**Location:** `/Users/cliff/Desktop/_code/encryptedcol`

**Package name:** `encryptedcol`

**Module name:** `github.com/yourorg/encryptedcol` (replace `yourorg` with your GitHub org/username)

---

## Phase 1: Core Foundation

**Goal:** Basic encryption/decryption working with single key

### 1.1 Project Initialization

```bash
mkdir -p encryptedcol
cd encryptedcol
go mod init github.com/yourorg/encryptedcol
```

**Files to create:**
- `go.mod`
- `errors.go`
- `kdf.go`
- `cipher.go`

### 1.2 Error Types (`errors.go`)

```go
var (
    ErrDecryptionFailed
    ErrKeyIDMismatch
    ErrKeyNotFound
    ErrInvalidKeySize
    ErrWasNull
    ErrDecompressionFailed
)
```

**Tests:** `errors_test.go` - Error identity and message checks

### 1.3 HKDF Key Derivation (`kdf.go`)

Implement:
- `derivedKeys` struct (encryption [32]byte, hmac [32]byte)
- `deriveKeys(masterKey []byte) *derivedKeys`
- Use `golang.org/x/crypto/hkdf` with SHA-256
- Info strings: `"encryptedcol-encryption"`, `"encryptedcol-blind-index"`

**Tests:** `kdf_test.go`
- Deterministic: same input → same output
- Different info → different keys
- Compare against known HKDF test vectors

### 1.4 Basic Cipher (`cipher.go`)

Implement:
- `Cipher` struct with key registry map
- `New(masterKey []byte) (*Cipher, error)` - simple path
- `Seal(plaintext []byte) []byte`
- `Open(ciphertext []byte) ([]byte, error)`
- Nonce generation with `crypto/rand`
- Key ID authentication (inner key_id in payload)

**Ciphertext format:**
```
[flag:1][keyIDLen:1][keyID:n][nonce:24][innerKeyID+ciphertext]
```

**Tests:** `cipher_test.go`
- Round-trip encryption/decryption
- NULL handling (nil → nil)
- Empty slice handling
- Key ID authentication verification
- Wrong key detection

**Estimated effort:** 4-6 hours

---

## Phase 2: Options and Multi-Key Support

**Goal:** Support multiple keys and configuration options

### 2.1 Options Pattern (`options.go`)

Implement:
- `Option` type
- `WithKey(keyID string, masterKey []byte) Option`
- `WithDefaultKeyID(keyID string) Option`
- `config` struct
- Update `New()` to accept variadic options

**Tests:** `options_test.go`
- Multiple keys
- Default key selection
- Key not found errors

### 2.2 Key Provider Interface (`provider.go`)

Implement:
- `KeyProvider` interface
- `NewWithProvider(provider KeyProvider) (*Cipher, error)`

**Tests:** `provider_test.go`
- Mock provider
- Dynamic key retrieval

**Estimated effort:** 2-3 hours

---

## Phase 3: Compression

**Goal:** Transparent compression for large payloads

### 3.1 Compression Module (`compress.go`)

Implement:
- `maybeCompress(data []byte, workBuf []byte) ([]byte, flag)`
- `decompress(data []byte, flag byte) ([]byte, error)`
- Zstd compression (primary)
- Flag byte handling (0x00=none, 0x01=zstd)
- Threshold check (default 1KB)
- 10% minimum savings check

**Options:**
- `WithCompressionThreshold(bytes int) Option`
- `WithCompressionAlgorithm(algo string) Option`
- `WithCompressionDisabled() Option`

**Dependencies:** `github.com/klauspost/compress/zstd`

**Tests:** `compress_test.go`
- Compressible data compressed
- Small data skipped
- Incompressible data skipped
- Round-trip with compression
- Flag byte correctness

### 3.2 Buffer Pooling

Implement:
- `sync.Pool` for compression work buffers
- Correct lifecycle (pool for intermediate, allocate for return)

**Tests:** `compress_test.go` - concurrent compression safety

**Estimated effort:** 3-4 hours

---

## Phase 4: Blind Indexing

**Goal:** HMAC-based searchable encryption

### 4.1 Blind Index Core (`blindindex.go`)

Implement:
- `BlindIndex(plaintext []byte) []byte`
- `BlindIndexWithKey(keyID string, plaintext []byte) ([]byte, error)`
- `BlindIndexes(plaintext []byte) map[string][]byte` (all active keys)
- HMAC-SHA256 using derived HMAC key

**Tests:** `blindindex_test.go`
- Deterministic (same input → same hash)
- Different keys → different hashes
- Compare against RFC 4231 test vectors

### 4.2 Normalizers (`normalize.go`)

Implement:
- `Normalizer` type (`func(string) string`)
- `NormalizeEmail` - lowercase + trim
- `NormalizeUsername` - lowercase + trim
- `NormalizePhone` - digits only
- `NormalizeNone` - identity

**Tests:** `normalize_test.go`
- Each normalizer behavior
- Edge cases (empty, whitespace, unicode)

### 4.3 Search Condition Builder (`search.go`)

Implement:
- `SearchCondition` struct
- `SearchCondition(column string, plaintext []byte, paramOffset int) *SearchCondition`
- `SearchConditionString(...)` variant
- `SearchConditionStringNormalized(...)` variant
- SQL generation with correct parameter numbering

**Tests:** `search_test.go`
- Single key SQL generation
- Multiple keys SQL generation
- Parameter offset handling
- Normalization integration

**Estimated effort:** 4-5 hours

---

## Phase 5: Type-Safe Helpers

**Goal:** Ergonomic API for common types

### 5.1 String Helpers (`helpers.go`)

Implement:
- `SealString(s string) []byte`
- `OpenString(ciphertext []byte) (string, error)`
- `SealStringPtr(s *string) []byte`
- `OpenStringPtr(ciphertext []byte) (*string, error)`
- `SealStringIndexed(s string) *SealedValue`
- `SealStringIndexedNormalized(s string, norm Normalizer) *SealedValue`
- `BlindIndexString(s string) []byte`

**Tests:** `helpers_test.go`
- Round-trip for each method
- NULL vs empty string distinction
- Normalization preservation (ciphertext) vs normalization (index)

### 5.2 JSON Helpers (`helpers.go`)

Implement:
- `SealJSON[T any](c *Cipher, data T) ([]byte, error)`
- `OpenJSON[T any](c *Cipher, ciphertext []byte) (T, error)`
- `SealJSONIndexed[T any](c *Cipher, data T) (*SealedValue, error)`

**Tests:** `helpers_test.go`
- Struct round-trip
- Nil handling

### 5.3 Integer Helpers (`helpers.go`)

Implement:
- `SealInt64(n int64) []byte`
- `OpenInt64(ciphertext []byte) (int64, error)`

**Tests:** `helpers_test.go`
- Round-trip
- Edge cases (0, negative, max int64)

### 5.4 NULL Check (`helpers.go`)

Implement:
- `WasNull(ciphertext []byte) bool`

**Estimated effort:** 3-4 hours

---

## Phase 6: Format and Parsing

**Goal:** Robust ciphertext format handling

### 6.1 Format Module (`format.go`)

Implement:
- `formatCiphertext(flag byte, keyID string, nonce [24]byte, ciphertext []byte) []byte`
- `parseFormat(data []byte) (flag byte, keyID string, nonce [24]byte, ciphertext []byte, err error)`
- Inner key_id encoding/decoding
- Validation and error handling

**Tests:** `format_test.go`
- Round-trip format/parse
- Malformed input handling
- Key ID extraction without decryption

**Estimated effort:** 2-3 hours

---

## Phase 7: Key Rotation Helpers

**Goal:** Tools for migrating encrypted data

### 7.1 Rotation Helpers (`rotate.go`)

Implement:
- `RotateValue(oldCiphertext []byte) ([]byte, error)` - NULL-safe
- `RotateBlindIndex(plaintext []byte) []byte` - NULL-safe
- Documentation for batch migration pattern

**Tests:** `rotate_test.go`
- Rotate from v1 to v2
- NULL handling
- Key ID update verification

**Estimated effort:** 1-2 hours

---

## Phase 8: Integration Testing

**Goal:** Verify end-to-end behavior with real PostgreSQL

### 8.1 Integration Test Suite (`integration_test.go`)

Requires: Docker or local PostgreSQL

Tests:
- Insert encrypted data, retrieve and decrypt
- Blind index search (exact match)
- Multi-key search during rotation
- NULL column handling
- Key rotation migration

### 8.2 Benchmarks (`benchmark_test.go`)

Benchmarks:
- Seal/Open at various payload sizes
- BlindIndex computation
- SearchCondition generation
- Compression overhead

**Estimated effort:** 3-4 hours

---

## Phase 9: Documentation and Examples

**Goal:** Production-ready documentation

### 9.1 Package Documentation

- `doc.go` - Package overview
- GoDoc comments on all public types/functions
- Example code in `example_test.go`

### 9.2 README.md

- Quick start
- Installation
- Basic usage
- Configuration options
- Migration guide
- Security considerations

### 9.3 Examples Directory

- `examples/basic/` - Simple encryption
- `examples/repository/` - Repository pattern integration
- `examples/migration/` - Key rotation

**Estimated effort:** 2-3 hours

---

## Implementation Order Summary

| Phase | Description | Dependencies | Est. Hours |
|-------|-------------|--------------|------------|
| 1 | Core Foundation | None | 4-6 |
| 2 | Options & Multi-Key | Phase 1 | 2-3 |
| 3 | Compression | Phase 1 | 3-4 |
| 4 | Blind Indexing | Phase 2 | 4-5 |
| 5 | Type-Safe Helpers | Phase 4 | 3-4 |
| 6 | Format & Parsing | Phase 1 | 2-3 |
| 7 | Key Rotation | Phase 2 | 1-2 |
| 8 | Integration Testing | All above | 3-4 |
| 9 | Documentation | All above | 2-3 |

**Total estimated effort:** 24-34 hours

---

## File Structure (Final)

```
encryptedcol/
├── go.mod
├── go.sum
├── doc.go              # Package documentation
├── errors.go           # Error types
├── kdf.go              # HKDF key derivation
├── cipher.go           # Core Cipher type
├── options.go          # Configuration options
├── provider.go         # KeyProvider interface
├── format.go           # Ciphertext format encoding/decoding
├── compress.go         # Zstd compression
├── blindindex.go       # HMAC blind indexing
├── normalize.go        # Normalizer functions
├── search.go           # SearchCondition builder
├── helpers.go          # Type-safe helpers (string, JSON, int64)
├── rotate.go           # Key rotation helpers
├── errors_test.go
├── kdf_test.go
├── cipher_test.go
├── options_test.go
├── provider_test.go
├── format_test.go
├── compress_test.go
├── blindindex_test.go
├── normalize_test.go
├── search_test.go
├── helpers_test.go
├── rotate_test.go
├── integration_test.go
├── benchmark_test.go
├── example_test.go
└── README.md
```

---

## Dependencies

```go
require (
    golang.org/x/crypto v0.x.x    // hkdf, nacl/secretbox
    github.com/klauspost/compress v1.x.x  // zstd
)
```

---

## Definition of Done

Each phase is complete when:
1. All functions implemented per design doc
2. Unit tests pass with >90% coverage
3. No race conditions (`go test -race`)
4. GoDoc comments on all public symbols
5. Code reviewed against design doc

Project is complete when:
1. All phases complete
2. Integration tests pass
3. Benchmarks documented
4. README complete
5. Example code works
6. Ready for import into Airborne

---

## Next Steps

1. Create project directory and initialize Go module
2. Begin Phase 1 implementation
3. Commit after each phase with tests passing
