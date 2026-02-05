Date Created: 2026-01-28T16:35:42Z
TOTAL_SCORE: 88/100

# Refactoring Analysis Report: encryptedcol

## Executive Summary

`encryptedcol` is a well-designed Go library for client-side encrypted columns with blind indexing support. The codebase demonstrates strong architectural decisions, comprehensive test coverage (95.7%), and security-conscious implementation. The score of **88/100** reflects excellent code quality with minor opportunities for consolidation and consistency improvements.

---

## Scoring Breakdown

| Category | Score | Max | Notes |
|----------|-------|-----|-------|
| Architecture & Design | 18 | 20 | Clean separation, intentional security decisions |
| Code Organization | 17 | 20 | Minor duplication across 6 patterns |
| Consistency | 14 | 15 | One error handling inconsistency |
| Test Coverage | 14 | 15 | 95.7% coverage, comprehensive benchmarks |
| Documentation | 13 | 15 | Excellent public API docs, minor gaps in private functions |
| Maintainability | 12 | 15 | Some repeated patterns could be extracted |
| **TOTAL** | **88** | **100** | |

---

## Detailed Analysis

### 1. Architecture & Design (18/20)

**Strengths:**
- Clear single-responsibility modules (cipher, kdf, format, compress, blindindex)
- Functional options pattern for configuration (`options.go`)
- Key provider interface enables external KMS integration
- Key ID authenticated in both header AND encrypted payload (defense-in-depth)
- XSalsa20-Poly1305 is an excellent choice (simpler nonce handling than AES-GCM)

**Minor Concern:**
- `config` struct is public to options but private - correctly encapsulates but couples options.go to cipher.go implementation details

### 2. Code Organization (17/20)

**Duplicated Patterns Identified:**

#### Pattern 1: Closed Cipher Check (7 locations)
Files: `cipher.go:128-129`, `cipher.go:139-141`, `cipher.go:208-210`, `cipher.go:233-235`, `blindindex.go:15-17`, `blindindex.go:27-29`, `blindindex.go:45-47`

```go
// Repeated 7 times with slight variations
if c.closed.Load() {
    panic("encryptedcol: use of closed Cipher")  // or return nil, ErrCipherClosed
}
```

**Opportunity:** Extract to `func (c *Cipher) ensureOpen() error` called uniformly.

#### Pattern 2: Key Lookup (4 locations)
Files: `cipher.go:142-144`, `cipher.go:222-225`, `cipher.go:240-243`, `blindindex.go:33-36`

```go
keys, ok := c.keys[keyID]
if !ok {
    return ..., ErrKeyNotFound
}
```

**Opportunity:** Extract to `func (c *Cipher) getKeys(keyID string) (*derivedKeys, error)`.

#### Pattern 3: SealedValue Construction (6 locations)
Files: `helpers.go:71-76`, `helpers.go:91-95`, `helpers.go:103-107`, `helpers.go:145-149`, `rotate.go:46-50`, `rotate.go:70-74`

```go
return &SealedValue{
    Ciphertext: c.Seal(...),
    BlindIndex: c.BlindIndex(...),
    KeyID:      c.defaultID,
}
```

**Opportunity:** Factory method `func (c *Cipher) newSealedValue(ct, idx []byte) *SealedValue`.

#### Pattern 4: NULL Check + Return (18 locations across all files)
Every public method that handles NULL preservation has the same pattern:
```go
if plaintext == nil {
    return nil  // or nil, nil
}
```

**Assessment:** This duplication is acceptable - extracting would add indirection without clarity benefit.

#### Pattern 5: Format Parsing for Key Extraction (2 locations)
Files: `cipher.go:216`, `rotate.go:88`, `rotate.go:103`

```go
_, keyID, _, _, err := parseFormat(ciphertext)
if err != nil {
    return ...
}
```

**Assessment:** Low duplication count - extraction not strongly recommended.

#### Pattern 6: Normalizer Application (3 locations)
Files: `helpers.go:90`, `rotate.go:68`, `search.go:117`, `search.go:130`

```go
normalized := norm(string(plaintext))
```

**Assessment:** Trivial one-liner - extraction would add indirection without benefit.

### 3. Consistency (14/15)

**Critical Inconsistency: Closed Cipher Error Handling**

| Method | File:Line | Response to Closed Cipher |
|--------|-----------|---------------------------|
| `Seal()` | cipher.go:128 | **panic** |
| `SealWithKey()` | cipher.go:139 | error (ErrCipherClosed) |
| `Open()` | cipher.go:208 | error (ErrCipherClosed) |
| `OpenWithKey()` | cipher.go:233 | error (ErrCipherClosed) |
| `BlindIndex()` | blindindex.go:15 | **panic** |
| `BlindIndexWithKey()` | blindindex.go:27 | error (ErrCipherClosed) |
| `BlindIndexes()` | blindindex.go:45 | **panic** |

**Impact:** 3 methods panic, 4 return errors. This inconsistency could surprise users who expect to recover from all closed-cipher usage with error handling.

**Recommendation:** Either:
1. All methods panic (current default-key methods) - document as intentional
2. All methods return errors - more recoverable, slight API change for `Seal()`, `BlindIndex()`, `BlindIndexes()`

**Other Consistency Observations (all positive):**
- Error variables follow `var ErrFoo = errors.New(...)` pattern consistently
- All public functions have doc comments
- Table-driven tests used throughout
- `github.com/stretchr/testify/require` used in all tests

### 4. Test Coverage (14/15)

**Coverage: 95.7%** - Excellent

**Test Organization:**
- Each source file has corresponding `*_test.go`
- Table-driven tests with `t.Run()` subtests
- Edge cases: nil, empty, large (1MB), unicode, binary data
- Error cases: wrong keys, tampering, format violations
- Concurrent safety: `TestSealOpen_Concurrent` with race detection

**Benchmark Coverage:**
- 30+ benchmarks covering all major paths
- Size variants: 100B, 1KB, 10KB, 100KB, 1MB
- Multi-key scenarios benchmarked
- Compression effectiveness tested

**Minor Gaps:**
- Provider interface integration could have more scenarios
- Compression boundary conditions (exactly at threshold)

### 5. Documentation (13/15)

**Strengths:**
- `doc.go` provides comprehensive package overview with usage examples
- All public functions have clear doc comments explaining behavior
- NULL preservation behavior documented on each function
- Format specification at top of `format.go`
- Security decisions explained in code comments

**Minor Gaps:**
- Private helper functions lack doc comments (e.g., `sortedMapKeys`, `initZstd`)
- `derivedKeys` struct could document why encryption and hmac are separate
- Provider interface could benefit from implementation example in docs

### 6. Maintainability (12/15)

**Positive Patterns:**
- Key caching at initialization (no repeated HKDF)
- `sync.Once` for zstd encoder/decoder initialization
- Buffer pre-allocation in format functions
- Key zeroing on `Close()` and in `New()` defer

**Maintainability Concerns:**

1. **Magic Numbers in Format Parsing**
   - `nonceSize = 24` is defined, but some size calculations use raw numbers
   - `minSize := 1 + 1 + 1 + nonceSize + 1` in `parseFormat()` - could name components

2. **Compression Constants Scattered**
   - `compressionAlgorithmZstd`, `compressionAlgorithmSnappy` in compress.go
   - `flagZstd`, `flagSnappy` in format.go
   - Related concepts in different files

3. **Config Struct Visibility**
   - `config` is unexported but options.go directly manipulates its fields
   - If config grows, validation could become scattered

---

## Recommendations Summary

### High Priority (Should Consider)

1. **Unify closed-cipher error handling** - Choose panic or error consistently across all 7 methods

2. **Extract key lookup helper** - Reduce 4 duplications of key lookup pattern:
   ```go
   func (c *Cipher) getKeys(keyID string) (*derivedKeys, error)
   ```

### Medium Priority (Nice to Have)

3. **Extract `ensureOpen()` helper** - Single point for closed-cipher checking

4. **Add `newSealedValue()` factory** - Reduce 6 locations constructing `SealedValue`

5. **Group compression constants** - Move all compression-related constants to one location

### Low Priority (Consider for Future)

6. **Name magic numbers in format parsing** - Define `flagSize`, `keyIDLenSize` constants

7. **Add private function documentation** - Especially for `initZstd`, `sortedMapKeys`

8. **Provider interface example** - Add implementation example to doc.go

---

## Files Analyzed

| File | Lines | Purpose |
|------|-------|---------|
| cipher.go | 293 | Core Cipher type, Seal/Open operations |
| blindindex.go | 77 | HMAC-SHA256 blind indexing |
| kdf.go | 55 | HKDF-SHA256 key derivation |
| format.go | 116 | Ciphertext format encoding/decoding |
| compress.go | 124 | Zstd compression with safeguards |
| helpers.go | 180 | Type-safe wrappers (String, JSON, Int64) |
| normalize.go | 59 | Normalizer functions for search |
| search.go | 132 | SQL condition builder |
| options.go | 67 | Functional options configuration |
| provider.go | 107 | KeyProvider interface and StaticKeyProvider |
| rotate.go | 109 | Key rotation helpers |
| errors.go | 42 | Error constants |
| doc.go | 92 | Package documentation |

**Total: ~1,453 lines of production code**

---

## Conclusion

`encryptedcol` is a well-crafted library demonstrating strong Go idioms, security-conscious design, and comprehensive testing. The main areas for improvement are:

1. One inconsistency in error handling (panic vs error for closed cipher)
2. Opportunity to reduce duplication via 2-3 helper methods
3. Minor documentation gaps in private functions

The codebase is production-ready and maintainable. The identified issues are refinements rather than problems.
