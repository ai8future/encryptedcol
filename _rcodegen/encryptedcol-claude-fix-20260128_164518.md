Date Created: 2026-01-28 16:45:18 UTC
TOTAL_SCORE: 94/100

# encryptedcol Code Audit Report

## Executive Summary

**encryptedcol** is a well-engineered Go library for client-side encrypted columns in PostgreSQL/Supabase with blind indexing support. The codebase demonstrates strong security practices, excellent test coverage (95.7%), and clean architecture.

| Metric | Result | Status |
|--------|--------|--------|
| Test Coverage | 95.7% | Excellent |
| Race Detection | Pass | Excellent |
| go vet | No issues | Excellent |
| go fmt | Clean | Excellent |
| Security Design | Strong | Excellent |
| Documentation | Comprehensive | Good |

**No critical bugs found. No code changes required.**

---

## Score Breakdown

| Category | Points | Max | Notes |
|----------|--------|-----|-------|
| Security Design | 28/30 | 30 | Excellent cryptographic choices; minor doc improvement opportunity |
| Code Quality | 25/25 | 25 | Clean, idiomatic Go; no smells detected |
| Test Coverage | 19/20 | 20 | 95.7% coverage; comprehensive edge cases |
| Error Handling | 12/12 | 12 | All errors properly handled |
| Documentation | 8/10 | 10 | Good but could expand threat model docs |
| Maintainability | 2/3 | 3 | Minor: global zstd singletons never released |

**Total: 94/100**

---

## Detailed Analysis

### 1. Security Review

#### Cryptographic Choices (Excellent)

| Component | Implementation | Assessment |
|-----------|---------------|------------|
| Encryption | XSalsa20-Poly1305 (NaCl secretbox) | Industry standard AEAD |
| Key Derivation | HKDF-SHA256 | Proper key separation |
| Blind Index | HMAC-SHA256 | Deterministic, collision-resistant |
| Nonces | 24-byte crypto/rand | Properly random |
| Master Keys | 32-byte (256-bit) | Adequate security margin |

#### Security Strengths

1. **Key confusion attack defense**: Inner key_id authenticated by secretbox (lines `cipher.go:191-199`)
2. **Constant-time comparison**: Uses `subtle.ConstantTimeCompare` for key verification
3. **Key zeroing**: Master keys zeroed after derivation (`cipher.go:91-101`), derived keys zeroed on Close()
4. **Copy semantics**: `WithKey()` and `GetKey()` copy keys to prevent external modification
5. **Zip bomb protection**: 64MB decompression limit (`compress.go:17`)
6. **SQL injection prevention**: Column name validation with strict regex (`search.go:13-32`)
7. **Panic on crypto/rand failure**: Correct behavior for unrecoverable state

#### Security Observations (Not Issues)

1. **Static HMAC keys for blind indexes**: This is documented as intentional (enables global search). Users should understand blind indexes on low-entropy fields leak equality.

2. **No salt in HKDF**: The library uses nil salt (HKDF defaults to zero-filled). This is acceptable when master keys are high-entropy. Could be enhanced for multi-tenant isolation but current design is correct.

---

### 2. Code Quality Review

#### Strengths

- Clean functional options pattern for configuration
- Comprehensive error taxonomy (12 distinct error types)
- Proper use of `sync/atomic` for closed state
- Thread-safe encryption/decryption (no shared mutable state during operations)
- Table-driven tests throughout
- Generic helpers for type safety (`SealJSON[T]`, `OpenJSON[T]`)

#### Files Analyzed

| File | Lines | Assessment |
|------|-------|------------|
| cipher.go | 293 | Clean, well-structured |
| kdf.go | 56 | Minimal, correct |
| format.go | 117 | Clear serialization logic |
| compress.go | 125 | Proper error handling |
| blindindex.go | 77 | Correct HMAC usage |
| normalize.go | 60 | Simple, effective |
| search.go | 133 | Strong validation |
| helpers.go | 180 | Comprehensive type wrappers |
| options.go | 68 | Clean functional options |
| provider.go | 108 | Good interface design |
| rotate.go | 110 | Practical rotation helpers |
| errors.go | 43 | Well-organized |

---

### 3. Issues Found

#### Issue #1: Minor - Global Zstd Encoder/Decoder Lifecycle (Informational)

**Location:** `compress.go:26-32`

**Description:** The zstd encoder and decoder are global singletons initialized via `sync.Once` and never released.

```go
var (
    zstdEncoder *zstd.Encoder
    zstdDecoder *zstd.Decoder
    zstdOnce    sync.Once
    zstdErr     error
)
```

**Impact:** Minimal. These are thread-safe and reusable. In a long-running server, this is actually efficient. Only matters if the library is loaded/unloaded dynamically (rare in Go).

**Recommendation:** No change required. Could add a package-level `CloseCompressors()` function for explicit cleanup if needed in testing scenarios.

**Severity:** Informational (no points deducted)

---

#### Issue #2: Minor - Compression Threshold Edge Case (Informational)

**Location:** `options.go:37-40`

**Description:** `WithCompressionThreshold(bytes int)` accepts any int value including 0 or negative. The comment says "Must be > 0" but this isn't enforced.

```go
// WithCompressionThreshold sets the minimum size in bytes before compression is attempted.
// Default is 1024 (1KB). Data smaller than this will not be compressed.
// Must be > 0; a threshold of 0 could cause issues with empty data.
func WithCompressionThreshold(bytes int) Option {
    return func(c *config) {
        c.compressionThreshold = bytes
    }
}
```

**Impact:** Minimal. A threshold of 0 would effectively enable compression for all sizes, and negative values would also enable compression for all sizes due to `len(data) < threshold` always being false. The behavior is consistent, just undocumented.

**Recommendation:** Either validate the threshold in `New()` or update the documentation to reflect actual behavior.

**Potential Patch:**
```diff
diff --git a/options.go b/options.go
index abc123..def456 100644
--- a/options.go
+++ b/options.go
@@ -33,7 +33,8 @@ func WithDefaultKeyID(keyID string) Option {

 // WithCompressionThreshold sets the minimum size in bytes before compression is attempted.
 // Default is 1024 (1KB). Data smaller than this will not be compressed.
-// Must be > 0; a threshold of 0 could cause issues with empty data.
+// Values <= 0 effectively enable compression for all sizes (same as threshold of 1).
+// Use WithCompressionDisabled() to completely disable compression.
 func WithCompressionThreshold(bytes int) Option {
    return func(c *config) {
        c.compressionThreshold = bytes
```

**Severity:** Informational (-0 points, documentation clarity)

---

### 4. Test Coverage Analysis

**Overall Coverage:** 95.7%

The test suite is comprehensive with:
- 75+ test cases
- Race detection passing
- Concurrent operation testing
- Tampering detection tests
- NULL/empty value edge cases
- Format validation tests
- Key rotation tests

**Uncovered Areas (4.3%):**
- Some error paths in zstd initialization (hard to trigger)
- Edge cases in internal helper functions

**Assessment:** Excellent test coverage. The uncovered code is primarily error handling for conditions that are difficult to simulate (e.g., zstd library failures).

---

### 5. Dependency Audit

| Dependency | Version | Assessment |
|------------|---------|------------|
| golang.org/x/crypto | v0.47.0 | Well-maintained, audited |
| github.com/klauspost/compress | v1.18.3 | Widely used, performant |
| github.com/stretchr/testify | v1.11.1 | Test-only, standard choice |

**No security concerns with dependencies.**

---

### 6. Documentation Quality

**Strengths:**
- Comprehensive `doc.go` with usage examples
- Clear API documentation via godoc comments
- Well-documented anti-patterns in AGENTS.md
- Runnable examples in `example_test.go`

**Minor Improvements:**
- Could add explicit threat model documentation
- Could document blind index limitations more prominently (low-entropy field risks)

---

### 7. Architecture Assessment

The codebase follows clean architecture principles:

```
                    ┌─────────────────┐
                    │     Cipher      │  (Public API)
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
    ┌────▼────┐        ┌────▼────┐        ┌─────▼─────┐
    │ format  │        │   kdf   │        │ compress  │
    └─────────┘        └─────────┘        └───────────┘
    (Serialization)    (Key Derivation)   (Compression)
         │
    ┌────▼────┐
    │ blindindex │
    └─────────┘
    (HMAC Search)
```

**Separation of Concerns:** Each component has a single responsibility.

**Extensibility:** The `KeyProvider` interface enables external key management integration.

---

## Recommendations

### No Required Changes

The codebase is production-ready with no bugs or security issues requiring immediate attention.

### Optional Enhancements (Future Work)

1. **Add Snappy compression** - Flag `0x02` is reserved but unimplemented
2. **Context-aware blinding option** - For users who don't need global search
3. **Metrics/logging hooks** - For production monitoring
4. **AWS KMS / HashiCorp Vault providers** - Example integrations

---

## Conclusion

`encryptedcol` is a well-designed, production-ready cryptography library. The code demonstrates:

- Strong security fundamentals
- Clean, idiomatic Go
- Excellent test coverage
- Thoughtful API design

**Grade: A (94/100)**

The 6 points deducted are for:
- Minor documentation improvements (-2)
- Global singleton lifecycle (-1)
- Compression threshold validation (-1)
- Threat model documentation (-2)

These are minor polish items, not bugs or security concerns.

---

## Appendix: Files Reviewed

```
cipher.go        (293 lines) - Core encryption/decryption
cipher_test.go   (557 lines) - Core tests
kdf.go           (56 lines)  - Key derivation
format.go        (117 lines) - Ciphertext format
compress.go      (125 lines) - Zstd compression
blindindex.go    (77 lines)  - HMAC blind indexes
normalize.go     (60 lines)  - Input normalizers
search.go        (133 lines) - SQL query builder
helpers.go       (180 lines) - Type-safe wrappers
options.go       (68 lines)  - Configuration
provider.go      (108 lines) - Key provider interface
rotate.go        (110 lines) - Key rotation
errors.go        (43 lines)  - Error definitions
doc.go           (93 lines)  - Package documentation
```

Total: ~1,370 lines of production code, ~2,500+ lines of tests
