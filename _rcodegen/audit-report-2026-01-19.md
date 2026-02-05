# Security & Code Quality Audit Report

**Package:** encryptedcol
**Date:** 2026-01-19
**Auditor:** Claude Opus 4.5
**Scope:** Full codebase review for security concerns, code quality, and potential bugs

---

## Executive Summary

The `encryptedcol` library is a well-designed Go package for client-side encryption with blind indexing. The cryptographic choices are sound, and the code follows security best practices in most areas. Test coverage is excellent (95.1%).

**Overall Assessment:** Production-ready with minor recommendations.

---

## Cryptographic Design Review

### Strengths

| Component | Implementation | Assessment |
|-----------|----------------|------------|
| Encryption | XSalsa20-Poly1305 (NaCl secretbox) | Excellent - authenticated encryption, 24-byte nonces |
| Key Derivation | HKDF-SHA256 | Excellent - proper context separation for encryption/HMAC keys |
| Blind Indexing | HMAC-SHA256 (32-byte output) | Good - appropriate for high-entropy fields |
| Nonce Generation | crypto/rand | Excellent - proper entropy source |
| Key Zeroization | Close() zeros keys | Good - defense in depth |

### Design Decisions (Intentional - Do Not Change)

1. **Panic on crypto/rand failure** - Correct. An error would be more dangerous if ignored.
2. **Key ID in header AND payload** - Correct. Prevents key confusion attacks.
3. **Static HMAC keys for blind indexing** - Intentional trade-off for global searchability. Documented limitation.

---

## Security Findings

### No Critical Issues Found

### Low-Severity Observations

#### 1. Key Material in Memory After Use

**Location:** `cipher.go:45-55` (derived keys)

**Observation:** Derived encryption and HMAC keys remain in memory until `Close()` is called. The `derivedKeys` struct fields are not individually zeroized.

**Risk:** Low. Go's garbage collector will eventually reclaim memory, but exact timing is unpredictable.

**Recommendation:** Consider zeroizing individual key arrays in `Close()`:
```go
func (c *Cipher) Close() {
    for _, keys := range c.keys {
        for i := range keys.encryption {
            keys.encryption[i] = 0
        }
        for i := range keys.hmac {
            keys.hmac[i] = 0
        }
    }
    c.keys = nil
}
```

**Priority:** Optional enhancement. Current implementation is acceptable.

#### 2. Error Messages Don't Leak Sensitive Information

**Assessment:** All error messages are generic and do not leak information about:
- Key existence
- Plaintext length
- Internal state

This is correct behavior.

---

## Code Quality Findings

### Positive Observations

1. **Proper error handling throughout** - Errors are wrapped appropriately with sentinel errors
2. **Constant-time comparisons via libraries** - Uses `secretbox` which handles this internally
3. **No raw crypto primitives** - Uses well-audited `x/crypto` packages
4. **Buffer pooling** - Efficient memory management for compression
5. **Thread safety** - Cipher is safe for concurrent use after initialization

### Minor Issues

#### 1. Unused Error Return in `BlindIndex` Methods

**Location:** `blindindex.go:15-20`

**Code:**
```go
func (c *Cipher) BlindIndex(plaintext []byte) []byte {
    result, _ := c.BlindIndexWithKey(c.defaultKeyID, plaintext)
    return result
}
```

**Issue:** Error is discarded. While `BlindIndexWithKey` only returns errors for invalid keyID (which can't happen here since `defaultKeyID` is validated at construction), this pattern could mask future bugs.

**Recommendation:** Add a defensive check:
```go
func (c *Cipher) BlindIndex(plaintext []byte) []byte {
    result, err := c.BlindIndexWithKey(c.defaultKeyID, plaintext)
    if err != nil {
        panic("encryptedcol: internal error: " + err.Error())
    }
    return result
}
```

**Priority:** Low. Current code is safe due to construction-time validation.

#### 2. Consistent Null Handling Pattern

**Assessment:** The library correctly distinguishes between `nil` (SQL NULL) and empty slice throughout. This is well-implemented and consistent across:
- `Seal`/`Open` methods
- Helper methods (`SealString`, `OpenJSON`, etc.)
- Rotation methods

No issues found.

---

## Test Coverage Analysis

**Current Coverage:** 95.1%

### Well-Tested Areas
- Core encryption/decryption round-trips
- Multi-key operations
- Error paths (invalid format, wrong key, tampering)
- Null preservation
- Compression behavior
- Rotation workflows
- SQL generation

### Uncovered Code (Intentionally Skipped)
- `crypto/rand` panic path (not testable without mocking globals)
- `sync.Once` initialization errors in compression (not triggerable)
- Internal `WithKey` nil-config path (unreachable)

These are appropriate to skip.

---

## SQL Injection Analysis

**Location:** `search.go`

### Safeguards Present

1. **Column name validation** - `isValidColumnName()` restricts to `[a-zA-Z_][a-zA-Z0-9_]*`
2. **Parameterized queries** - All values use `$N` placeholders
3. **No string interpolation of user data** - Column names are validated, values are parameterized

### Assessment

SQL generation is safe when used as designed. Column names must be developer-controlled (not user input). The validation function correctly rejects:
- Empty strings
- Leading digits (PostgreSQL requirement)
- Special characters

---

## API Design Review

### Strengths

1. **Functional options pattern** - Clean configuration API
2. **Type-safe helpers** - Reduces misuse (`SealString`, `OpenJSON`, etc.)
3. **`SealedValue` struct** - Bundles related values clearly
4. **Clear error types** - Sentinel errors enable precise error handling

### Minor Suggestions

None. API is well-designed.

---

## Dependency Analysis

| Dependency | Version Risk | Security |
|------------|--------------|----------|
| `golang.org/x/crypto/nacl/secretbox` | Low | Well-maintained, widely audited |
| `golang.org/x/crypto/hkdf` | Low | Standard library quality |
| `github.com/klauspost/compress/zstd` | Low | Mature, widely used |
| `github.com/stretchr/testify` | Test only | N/A |

No concerning dependencies.

---

## Recommendations Summary

### Should Implement

| # | Item | Priority | Effort |
|---|------|----------|--------|
| 1 | Add defensive panic in `BlindIndex()` | Low | 5 min |
| 2 | Enhanced key zeroization in `Close()` | Low | 10 min |

### Already Good (No Action Needed)

- Cryptographic design
- Error handling
- SQL injection prevention
- Test coverage
- Thread safety
- API design

---

## Conclusion

The `encryptedcol` library demonstrates strong security practices and clean Go idioms. The cryptographic primitives are correctly used, error handling is consistent, and the API is well-designed for safe usage.

The library is suitable for production use. The identified recommendations are minor enhancements rather than critical fixes.

**Rating:** ★★★★☆ (4/5) - Excellent with room for minor hardening
