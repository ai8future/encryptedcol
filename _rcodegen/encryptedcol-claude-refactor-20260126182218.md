Date Created: 2026-01-26 18:22:18 UTC
TOTAL_SCORE: 92/100

# Encryptedcol Refactoring Analysis Report

## Executive Summary

The `encryptedcol` library is an exceptionally well-crafted Go package for client-side encrypted columns with blind indexing support. The codebase demonstrates professional cryptographic implementation, consistent patterns, excellent test coverage, and minimal code duplication. Only minor opportunities for improvement exist.

---

## Scoring Breakdown

| Category | Score | Weight | Weighted |
|----------|-------|--------|----------|
| Code Organization | 95 | 15% | 14.25 |
| Consistency | 93 | 15% | 13.95 |
| Duplication | 90 | 15% | 13.50 |
| Error Handling | 95 | 10% | 9.50 |
| Test Coverage | 98 | 15% | 14.70 |
| Security Practices | 98 | 15% | 14.70 |
| Documentation | 90 | 10% | 9.00 |
| Dependencies | 95 | 5% | 4.75 |
| **TOTAL** | | | **94.35 -> 92** |

*Score adjusted down slightly for minor improvement opportunities noted below.*

---

## Codebase Overview

**Total Source Files:** 13 non-test files, 14 test files
**Total Lines of Code:** ~4,650 LOC
**Test Functions:** 170+ test cases
**Benchmark Functions:** 25+ benchmarks

### File Structure (Well-Organized)

```
Core Cryptography:
  cipher.go (294 lines)    - Main Cipher type, Seal/Open operations
  kdf.go (56 lines)        - HKDF-SHA256 key derivation
  format.go (117 lines)    - Ciphertext format encoding/decoding
  compress.go (125 lines)  - Zstd compression support

Search & Indexing:
  blindindex.go (77 lines) - HMAC-SHA256 blind indexes
  search.go (133 lines)    - SQL search condition builder
  normalize.go (60 lines)  - String normalizers (email, phone, etc.)

Configuration & Helpers:
  options.go (68 lines)    - Functional options pattern
  provider.go (108 lines)  - KeyProvider interface
  helpers.go (181 lines)   - Type-safe wrappers
  rotate.go (110 lines)    - Key rotation utilities
  errors.go (43 lines)     - Error definitions
  doc.go (92 lines)        - Package documentation
```

---

## Strengths

### 1. Cryptographic Soundness (Excellent)

- **XSalsa20-Poly1305** via NaCl secretbox - proven authenticated encryption
- **HKDF-SHA256** for key derivation - industry standard
- **Key ID embedded in both header AND payload** - prevents key confusion attacks
- **Constant-time comparison** for key ID verification (`subtle.ConstantTimeCompare`)
- **Explicit key material zeroing** in `Close()` and after initialization

### 2. Consistent Patterns

**Functional Options Pattern (options.go)**
```go
cipher, err := encryptedcol.New(
    encryptedcol.WithKey("v1", masterKey1),
    encryptedcol.WithDefaultKeyID("v1"),
    encryptedcol.WithCompressionDisabled(),
)
```

**NULL Preservation** - Consistent across all 15+ methods:
```go
if plaintext == nil {
    return nil // NULL preservation
}
```

**Error-vs-Panic Strategy** - Well-defined and consistent:
- Errors for recoverable conditions (key not found, decryption failed)
- Panics for programmer errors (invalid column name, crypto/rand failure)

### 3. Test Coverage (Exceptional)

- 170+ test functions with comprehensive edge cases
- Table-driven tests with `t.Run()` throughout
- Benchmarks at multiple data sizes (100B, 1KB, 10KB, 100KB, 1MB)
- All error types tested with `require.ErrorIs()`
- Concurrent stress tests for `Close()` behavior

### 4. Minimal Dependencies

Only essential cryptographic libraries:
- `golang.org/x/crypto/nacl/secretbox`
- `golang.org/x/crypto/hkdf`
- `github.com/klauspost/compress/zstd`
- `github.com/stretchr/testify` (tests only)

---

## Improvement Opportunities

### 1. Closed Cipher Check Duplication (Minor)

**Current State:** 7 instances of the closed cipher check pattern across 2 files

```go
// cipher.go:128
if c.closed.Load() {
    panic("encryptedcol: use of closed Cipher")
}

// cipher.go:139, 208, 233
if c.closed.Load() {
    return nil, ErrCipherClosed
}

// blindindex.go:16, 27, 45 (similar patterns)
```

**Opportunity:** Could extract to a helper method:
```go
func (c *Cipher) checkClosed(panicking bool) error {
    if c.closed.Load() {
        if panicking {
            panic("encryptedcol: use of closed Cipher")
        }
        return ErrCipherClosed
    }
    return nil
}
```

**Impact:** Low - current code is clear and consistent. Extraction would save ~15 lines but add indirection.

**Recommendation:** Keep as-is. The explicit checks serve as documentation at each entry point.

---

### 2. Search Method Proliferation (Moderate)

**Current State:** 4 search condition methods with similar signatures:
- `SearchCondition(column string, plaintext []byte, paramOffset int)`
- `SearchConditionString(column string, plaintext string, paramOffset int)`
- `SearchConditionStringNormalized(..., norm Normalizer)`
- `SearchConditionNormalized(column string, plaintext []byte, ..., norm Normalizer)`

**Opportunity:** Could consolidate with optional normalizer:
```go
func (c *Cipher) SearchCondition(column string, plaintext []byte, paramOffset int, opts ...SearchOption) *SearchCondition
```

**Impact:** Medium - would reduce API surface from 4 methods to 1-2.

**Trade-off:** Current explicit methods are more discoverable and type-safe. The method proliferation follows Go's preference for explicit over implicit.

**Recommendation:** Keep as-is. The explicit API is clearer for users.

---

### 3. Rotation Method Pattern (Minor)

**Current State:** 4 rotation methods with similar decrypt-re-encrypt pattern:
- `RotateValue(ciphertext []byte) ([]byte, error)`
- `RotateBlindIndex(plaintext []byte) ([]byte, error)`
- `RotateStringIndexed(s string) (*SealedValue, error)`
- `RotateStringIndexedNormalized(s string, norm Normalizer) (*SealedValue, error)`

**Observation:** Each has different return types and semantics, so they can't be trivially merged. The pattern duplication is justified.

**Recommendation:** No change needed.

---

### 4. Generic Function Placement (Minor)

**Current State:** Generic functions are standalone rather than methods:
```go
func SealJSON[T any](c *Cipher, data T) ([]byte, error)
func OpenJSON[T any](c *Cipher, ciphertext []byte) (T, error)
func SealJSONIndexed[T any](c *Cipher, data T) (*SealedValue, error)
```

**Observation:** These are functions rather than methods due to Go's limitation that methods cannot have their own type parameters.

**Recommendation:** Keep as-is. This is idiomatic Go for generic operations.

---

### 5. Missing Fuzzing Tests

**Current State:** No fuzz tests detected.

**Opportunity:** Add fuzz tests for:
- `parseFormat()` - ciphertext format parsing
- `decompress()` - decompression of attacker-controlled data
- `parseInnerPlaintext()` - inner format parsing

**Recommendation:** Add fuzzing as a defense-in-depth measure:
```go
func FuzzParseFormat(f *testing.F) {
    f.Add([]byte{0x00, 0x02, 'v', '1'})
    f.Fuzz(func(t *testing.T, data []byte) {
        parseFormat(data) // Should not panic
    })
}
```

---

### 6. Documentation Cross-References (Minor)

**Current State:** Method documentation is thorough but lacks cross-references.

**Example Improvement:**
```go
// SealStringIndexedNormalized encrypts a string and computes a normalized blind index.
// ...
// See also: SearchConditionStringNormalized for searching normalized blind indexes.
```

**Recommendation:** Add "See also" cross-references between related methods.

---

## Anti-Patterns Verified (Intentional Design)

Per CLAUDE.md, the following patterns are **intentional** and should NOT be changed:

1. **Static HMAC Keys for Blind Indexes** - Enables global search across all rows
2. **Panic on crypto/rand Failure** - System is unrecoverable
3. **Key ID in Both Header AND Payload** - Prevents key confusion attacks

All three patterns are correctly implemented and documented.

---

## Security Observations (All Positive)

| Security Practice | Status |
|-------------------|--------|
| Key material zeroing | Implemented in `Close()` and `New()` |
| Constant-time comparison | Used for key ID verification |
| No hardcoded keys | All keys provided via options |
| Input validation | Column names validated before SQL interpolation |
| Parameter limits | PostgreSQL max params enforced |
| Compression bombs | Size limits in zstd decoder |
| Memory safety | No unsafe pointer operations |

---

## Metrics Summary

| Metric | Value | Assessment |
|--------|-------|------------|
| Cyclomatic Complexity | Low | Most functions are 5-15 |
| Method Count (Cipher) | 35+ | Reasonable for feature set |
| Error Types | 12 | All distinct, well-documented |
| Test Coverage | High | All public methods tested |
| Benchmark Coverage | Comprehensive | All sizes and paths |

---

## Final Recommendations

### Do Not Change

1. Core cryptographic patterns (already optimal)
2. Error-vs-panic strategy (well-defined)
3. NULL preservation pattern (consistent)
4. Key material handling (security-critical)

### Consider Adding

1. **Fuzz tests** for format parsing and decompression
2. **Documentation cross-references** between related methods
3. **Memory allocation benchmarks** (in addition to time benchmarks)

### Low Priority

1. Extracting closed cipher check to helper (marginal benefit)
2. Consolidating search methods (trade-off with explicitness)

---

## Conclusion

The `encryptedcol` codebase is **production-ready** and demonstrates excellent software engineering practices. The score of 92/100 reflects a mature, well-designed library with only minor opportunities for enhancement. The code serves as a model for cryptographic library design in Go.

No significant refactoring is recommended. The identified improvements are cosmetic and should be weighed against the cost of churn in a security-critical library.
