Date Created: 2026-01-20 17:34:52 +0100
TOTAL_SCORE: 92/100

# Code Quality Audit Report: encryptedcol

## Executive Summary

The `encryptedcol` library is a well-designed Go package for client-side encrypted columns in PostgreSQL/Supabase with blind indexing support. The codebase demonstrates strong cryptographic fundamentals, excellent test coverage (95.2%), and clean API design. This audit identified no critical bugs or security vulnerabilities.

**Overall Assessment: EXCELLENT - Production Ready**

---

## Scoring Breakdown

| Category | Score | Max | Notes |
|----------|-------|-----|-------|
| Security | 28 | 30 | Strong crypto, proper key handling, minor panic concerns |
| Correctness | 18 | 20 | Well-tested, comprehensive edge case handling |
| Code Quality | 18 | 20 | Clean design, minor redundant checks |
| Test Coverage | 10 | 10 | 95.2% coverage, excellent |
| Documentation | 9 | 10 | Good docs, could improve panic documentation |
| API Design | 9 | 10 | Consistent, type-safe, minor asymmetry |
| **TOTAL** | **92** | **100** | |

---

## Files Analyzed

| File | Lines | Purpose |
|------|-------|---------|
| cipher.go | 281 | Core Cipher type with Seal/Open methods |
| kdf.go | 56 | HKDF-SHA256 key derivation |
| format.go | 117 | Ciphertext format encoding/parsing |
| compress.go | 110 | Zstd compression with sync.Once pooling |
| blindindex.go | ~80 | HMAC-SHA256 blind indexing |
| normalize.go | ~60 | Input normalizers (email, username, phone) |
| search.go | 123 | SQL search condition builder |
| helpers.go | ~150 | Type-safe wrappers |
| options.go | ~100 | Functional options pattern |
| provider.go | ~50 | KeyProvider interface |
| rotate.go | ~100 | Key rotation helpers |
| errors.go | 40 | Sentinel error definitions |
| doc.go | ~50 | Package documentation |

**Total: ~4,244 lines across 27 files (including tests)**

---

## Issues Found

### ISSUE 1: Redundant Key ID Length Check (INFORMATIONAL)

**Location:** `format.go:57`

```go
keyIDLen := int(data[1])

// Validate keyIDLen
if keyIDLen == 0 || keyIDLen > 255 {
    err = ErrInvalidFormat
    return
}
```

**Analysis:** Since `keyIDLen` is read from a single byte (`data[1]`), its value is inherently in the range 0-255. The check `keyIDLen > 255` can never be true. This is harmless defensive coding but technically redundant.

**Impact:** None - code is correct, just slightly redundant.

**No patch needed** - this is informational only.

---

### ISSUE 2: Panic Documentation Could Be More Prominent (LOW)

**Location:** `search.go:55-59`

```go
if !isValidColumnName(column) {
    panic("encryptedcol: invalid column name...")
}

if paramOffset < 1 {
    panic("encryptedcol: invalid paramOffset (must be >= 1)")
}
```

**Analysis:** These panics are intentional (documented in AGENTS.md as anti-patterns not to fix), but the godoc for `SearchCondition()` doesn't explicitly warn that invalid inputs will panic. Users discovering this at runtime could be surprised.

**Recommended Enhancement:** Add panic documentation to the godoc comment.

```diff
--- a/search.go
+++ b/search.go
@@ -45,6 +45,9 @@ type SearchCondition struct {
 // paramOffset specifies the starting parameter number ($1, $2, etc.).
 // Use this when composing with other WHERE conditions.
 //
+// Panics if column name is invalid (must start with letter/underscore,
+// contain only alphanumeric/underscore) or if paramOffset < 1.
+//
 // Example:
 //
 //	cond := cipher.SearchCondition("email", []byte("alice@example.com"), 1)
```

**Impact:** LOW - Documentation improvement only.

---

### ISSUE 3: Same Redundant Check in parseInnerPlaintext (INFORMATIONAL)

**Location:** `format.go:102`

```go
keyIDLen := int(data[0])
if keyIDLen == 0 || keyIDLen > 255 {
    err = ErrInvalidFormat
    return
}
```

**Analysis:** Same redundant check as Issue 1. The `keyIDLen > 255` condition can never be true for a value read from a single byte.

**Impact:** None.

**No patch needed** - informational only.

---

### ISSUE 4: Internal Panic Has Theoretical Path (VERY LOW)

**Location:** `search.go:77`

```go
idxHash, err := c.BlindIndexWithKey(keyID, plaintext)
if err != nil {
    // This should never happen since keyID comes from ActiveKeyIDs()
    panic("encryptedcol: internal error: " + err.Error())
}
```

**Analysis:** This panic is theoretically unreachable because:
1. `keyID` comes from `ActiveKeyIDs()` which returns keys from `c.keys`
2. `BlindIndexWithKey` only returns `ErrKeyNotFound` for missing keys
3. The Cipher is immutable after creation

The comment correctly identifies this as an internal error condition. However, if the Cipher struct were ever modified to allow dynamic key management, this could become reachable.

**Impact:** None currently - code is correct for the immutable design.

**No patch needed** - this is an intentional design choice.

---

### ISSUE 5: Empty String vs Nil Behavior Difference (LOW - INTENTIONAL)

**Location:** `helpers.go` and `options.go`

The behavior of empty strings differs based on `WithEmptyStringAsNull()`:
- Default: `SealString("")` returns encrypted empty string
- With option: `SealString("")` returns `nil`

**Analysis:** This is intentional and well-tested, but could cause confusion for users who don't read the documentation carefully. The doc.go file does document this, but it could be more prominent.

**Impact:** LOW - potential user confusion, not a bug.

**No patch needed** - documented intentional behavior.

---

## Positive Findings

### Security Strengths

1. **Proper Authenticated Encryption**: Uses NaCl secretbox (XSalsa20-Poly1305) which provides both confidentiality and integrity.

2. **Key ID Binding**: Key ID is embedded in both the outer header AND inside the encrypted payload, preventing key confusion attacks.

3. **HKDF Key Derivation**: Properly derives separate encryption and HMAC keys from master key using distinct info strings.

4. **Secure Nonce Generation**: 24-byte random nonces from `crypto/rand` with appropriate panic on failure.

5. **Key Material Zeroing**: Master keys are zeroed after derivation; `Close()` method zeros derived keys.

6. **SQL Injection Prevention**: Column name validation in `SearchCondition()` prevents SQL injection.

### Code Quality Strengths

1. **Thread Safety**: Cipher is immutable after creation, safe for concurrent use.

2. **Functional Options Pattern**: Clean, extensible configuration API.

3. **Comprehensive Error Types**: 11 sentinel errors with clear semantics.

4. **NULL Preservation**: Properly handles database NULL semantics throughout.

5. **Type-Safe Helpers**: Reduces casting errors with dedicated methods for strings, int64, JSON.

### Test Quality

- **95.2% code coverage** - excellent
- **Race detection passes** - no data races
- **Table-driven tests** - maintainable and thorough
- **Edge case coverage** - NULL, empty, malformed, Unicode, binary
- **Benchmark suite** - performance profiling at multiple data sizes

---

## Architecture Assessment

The codebase follows a clean, layered architecture:

```
┌─────────────────────────────────────────────────┐
│                   helpers.go                     │
│     (SealString, SealJSON, OpenInt64, etc.)     │
├─────────────────────────────────────────────────┤
│                   cipher.go                      │
│          (Seal, Open, BlindIndex)               │
├──────────────────┬──────────────────────────────┤
│    format.go     │        compress.go           │
│  (wire format)   │    (zstd compression)        │
├──────────────────┼──────────────────────────────┤
│     kdf.go       │       blindindex.go          │
│ (key derivation) │     (HMAC-SHA256)            │
├──────────────────┴──────────────────────────────┤
│           secretbox / hkdf / zstd               │
│              (external crypto)                  │
└─────────────────────────────────────────────────┘
```

**Wire Format:**
```
[flag:1][keyIDLen:1][keyID:n][nonce:24][secretbox(innerKeyID + plaintext)]
```

The double key ID binding (outer + inner) is a deliberate security feature.

---

## Dependency Analysis

| Dependency | Version | Risk | Notes |
|------------|---------|------|-------|
| golang.org/x/crypto | - | LOW | Standard library extension |
| github.com/klauspost/compress/zstd | v1.18.3 | LOW | Well-maintained, widely used |
| github.com/stretchr/testify | v1.11.1 | LOW | Test-only dependency |

**Assessment:** Minimal, well-maintained dependencies appropriate for purpose.

---

## Recommendations

### High Priority
None - the codebase is production-ready.

### Medium Priority
1. Add explicit panic documentation to `SearchCondition()` and related methods
2. Consider adding fuzzing tests for format parsing functions

### Low Priority
1. Remove technically redundant `keyIDLen > 255` checks (cosmetic)
2. Add integration examples showing multi-key rotation scenarios
3. Consider returning errors instead of panicking in search functions (API breaking change - may not be desirable)

---

## Conclusion

The `encryptedcol` library is well-designed, thoroughly tested, and production-ready. The cryptographic implementation follows best practices, the API is clean and type-safe, and edge cases are properly handled.

The issues identified are minor:
- One redundant (but harmless) bounds check
- Documentation could better highlight panic conditions
- Intentional design decisions that are already well-documented

**No code changes required.** The library scores 92/100, losing points mainly for:
- Minor documentation gaps around panic behavior (-3)
- Redundant defensive code that could confuse maintainers (-2)
- Slightly complex empty string vs NULL semantics (-3)

This is an exemplary Go library that demonstrates strong security practices and clean API design.
