Date Created: 2026-01-26T18:18:59-08:00
TOTAL_SCORE: 94/100

# encryptedcol Code Analysis Report

## Executive Summary

`encryptedcol` is a high-quality, production-ready Go library for client-side encrypted columns in PostgreSQL/Supabase with blind indexing support. The codebase demonstrates strong security practices, comprehensive test coverage (95.7%), and clean architecture. No critical bugs were found. A few minor improvements are recommended.

---

## Scoring Breakdown

| Category | Score | Max | Notes |
|----------|-------|-----|-------|
| Security | 28/30 | 30 | Excellent crypto practices, minor edge case |
| Correctness | 25/25 | 25 | All tests pass, comprehensive coverage |
| Code Quality | 18/20 | 20 | Clean, well-organized, minor style nits |
| Documentation | 12/12 | 12 | Excellent inline docs and AGENTS.md |
| Test Coverage | 11/13 | 13 | 95.7% coverage, comprehensive scenarios |
| **TOTAL** | **94/100** | 100 | |

---

## Issues Found

### Issue #1: Potential Memory Leak in zstd Initialization Error Path (LOW)

**File:** `compress.go:35-48`

**Description:** If `zstd.NewReader(nil)` fails after the encoder is created, the encoder is closed but the error leaves the decoder as nil. However, subsequent calls to `initZstd()` will return the cached error without re-attempting initialization, which is correct behavior. The issue is that the closed encoder reference is retained.

**Current Code:**
```go
zstdOnce.Do(func() {
    zstdEncoder, zstdErr = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
    if zstdErr != nil {
        return
    }
    zstdDecoder, zstdErr = zstd.NewReader(nil)
    if zstdErr != nil {
        // Clean up encoder if decoder creation fails
        zstdEncoder.Close()
        zstdEncoder = nil  // Good: sets to nil
    }
})
```

**Assessment:** This is correctly handled - the encoder is closed and set to nil. No patch needed.

**Severity:** Non-issue upon closer inspection.

---

### Issue #2: Missing Closed Check in `SearchCondition` Methods (LOW)

**File:** `search.go:56-99`

**Description:** The `SearchCondition`, `SearchConditionString`, `SearchConditionStringNormalized`, and `SearchConditionNormalized` methods do not check `c.closed.Load()` before proceeding. While these methods call `BlindIndexWithKey` which does check for closure, the panic happens mid-operation rather than at the start.

**Current Code:**
```go
func (c *Cipher) SearchCondition(column string, plaintext []byte, paramOffset int) *SearchCondition {
    if !isValidColumnName(column) {
        panic("encryptedcol: invalid column name...")
    }
    // ... no closed check here
```

**Suggested Patch:**
```diff
--- a/search.go
+++ b/search.go
@@ -53,6 +53,9 @@ func (c *Cipher) SearchCondition(column string, plaintext []byte, paramOffset in
 //	cond := cipher.SearchCondition("email", []byte("alice@example.com"), 1)
 //	query := fmt.Sprintf("SELECT * FROM users WHERE %s", cond.SQL)
 //	rows, _ := db.Query(query, cond.Args...)
 func (c *Cipher) SearchCondition(column string, plaintext []byte, paramOffset int) *SearchCondition {
+	if c.closed.Load() {
+		panic("encryptedcol: use of closed Cipher")
+	}
 	if !isValidColumnName(column) {
 		panic("encryptedcol: invalid column name (must start with letter/underscore, contain only alphanumeric/underscore)")
 	}
```

**Severity:** Low - The underlying `BlindIndexWithKey` already checks closure, but early detection provides better error messages.

---

### Issue #3: `DefaultKeyID()` and `ActiveKeyIDs()` Missing Closed Checks (LOW)

**File:** `cipher.go:260-267`

**Description:** The accessor methods `DefaultKeyID()` and `ActiveKeyIDs()` do not check if the cipher is closed. While these methods don't perform cryptographic operations, using them after Close() could lead to confusing behavior (returning stale data from a closed cipher).

**Current Code:**
```go
func (c *Cipher) DefaultKeyID() string {
    return c.defaultID
}

func (c *Cipher) ActiveKeyIDs() []string {
    return sortedMapKeys(c.keys)
}
```

**Suggested Patch:**
```diff
--- a/cipher.go
+++ b/cipher.go
@@ -258,11 +258,17 @@ func (c *Cipher) OpenWithKey(keyID string, ciphertext []byte) ([]byte, error) {

 // DefaultKeyID returns the current default key identifier.
 func (c *Cipher) DefaultKeyID() string {
+	if c.closed.Load() {
+		panic("encryptedcol: use of closed Cipher")
+	}
 	return c.defaultID
 }

 // ActiveKeyIDs returns all registered key identifiers, sorted alphabetically.
 func (c *Cipher) ActiveKeyIDs() []string {
+	if c.closed.Load() {
+		panic("encryptedcol: use of closed Cipher")
+	}
 	return sortedMapKeys(c.keys)
 }
```

**Severity:** Low - Informational methods, but consistency with other methods would be beneficial.

---

### Issue #4: `WasNull` Method Missing Closed Check (VERY LOW)

**File:** `helpers.go:178-180`

**Description:** The `WasNull` method doesn't check closure state. This is purely a nil check and doesn't access cipher state, but for API consistency it could include the check.

**Current Code:**
```go
func (c *Cipher) WasNull(ciphertext []byte) bool {
    return ciphertext == nil
}
```

**Assessment:** This method doesn't actually use any cipher state, just checks if input is nil. Adding a closed check would be overly pedantic. No patch recommended.

**Severity:** Non-issue - method is stateless.

---

### Issue #5: No Validation of `compressionThreshold` in `WithCompressionThreshold` (LOW)

**File:** `options.go:37-41`

**Description:** The comment mentions "Must be > 0; a threshold of 0 could cause issues with empty data" but there's no validation. A threshold of 0 or negative would be silently accepted.

**Current Code:**
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

**Suggested Patch:**
```diff
--- a/options.go
+++ b/options.go
@@ -35,6 +35,9 @@ func WithDefaultKeyID(keyID string) Option {
 // Must be > 0; a threshold of 0 could cause issues with empty data.
 func WithCompressionThreshold(bytes int) Option {
 	return func(c *config) {
+		if bytes < 1 {
+			bytes = 1 // Ensure minimum threshold of 1 byte
+		}
 		c.compressionThreshold = bytes
 	}
 }
```

**Alternative:** Return an error at `New()` time if threshold is invalid.

**Severity:** Low - Edge case, current code would just not compress anything if threshold <= 0.

---

### Issue #6: `ExtractKeyID` and `NeedsRotation` Missing Closed Checks (LOW)

**File:** `rotate.go:77-109`

**Description:** The `NeedsRotation` and `ExtractKeyID` methods parse ciphertext format without checking if the cipher is closed. These methods only read ciphertext format and compare against `c.defaultID`, so they don't access zeroed key material, but for consistency they should check closure.

**Current Code:**
```go
func (c *Cipher) NeedsRotation(ciphertext []byte) bool {
    if ciphertext == nil {
        return false
    }
    // ... no closed check
```

**Suggested Patch:**
```diff
--- a/rotate.go
+++ b/rotate.go
@@ -80,6 +80,9 @@ func (c *Cipher) NeedsRotation(ciphertext []byte) bool {
 	if ciphertext == nil {
 		return false
 	}
+	if c.closed.Load() {
+		panic("encryptedcol: use of closed Cipher")
+	}

 	_, keyID, _, _, err := parseFormat(ciphertext)
 	if err != nil {
@@ -95,6 +98,9 @@ func (c *Cipher) ExtractKeyID(ciphertext []byte) (string, error) {
 	if ciphertext == nil {
 		return "", nil
 	}
+	if c.closed.Load() {
+		return "", ErrCipherClosed
+	}

 	_, keyID, _, _, err := parseFormat(ciphertext)
 	if err != nil {
```

**Severity:** Low - For API consistency.

---

## Code Quality Observations

### Strengths

1. **Excellent Security Design**
   - XSalsa20-Poly1305 with 24-byte random nonces
   - HKDF-SHA256 key derivation with distinct info strings
   - Inner key_id binding prevents key confusion attacks
   - Constant-time comparison for key verification
   - Master keys zeroed immediately after derivation
   - Proper panic on crypto/rand failure

2. **Comprehensive Test Coverage (95.7%)**
   - Table-driven tests throughout
   - Race detection passes
   - Edge cases well covered
   - Concurrent usage tested

3. **Clean Architecture**
   - Clear separation of concerns
   - Functional options pattern
   - Well-defined error types
   - KeyProvider interface for external KMS integration

4. **Defensive Programming**
   - NULL preservation throughout
   - Format validation with bounds checking
   - Zip bomb protection (64MB limit)
   - Column name validation for SQL injection prevention

5. **Documentation**
   - Excellent inline documentation
   - AGENTS.md with anti-patterns to avoid
   - Package-level examples

### Minor Style Observations

1. **Consistent panic vs error handling** - Most methods panic on closed cipher, but some use errors. This is acceptable as documented behavior.

2. **Generic JSON helpers** - `SealJSON` and `OpenJSON` are package-level generics while other helpers are methods. This is intentional for type safety.

3. **Sort stability** - `ActiveKeyIDs()` sorts alphabetically which is stable and predictable.

---

## Security Assessment

### Cryptographic Primitives ✓
- XSalsa20-Poly1305 (NaCl secretbox) - Well-established AEAD
- HKDF-SHA256 - Standard key derivation
- HMAC-SHA256 - Standard MAC for blind indexes
- crypto/rand - System entropy source

### Key Management ✓
- Keys derived at init, cached immutably
- Master keys zeroed after derivation
- Close() zeros derived keys
- Deep copies prevent external modification

### Format Security ✓
- Double key_id binding (outer + authenticated inner)
- Flag byte for compression algorithm
- Bounds checking on all parsing
- Minimum size validation

### Known Limitations (Documented)
- Static HMAC keys enable rainbow table attacks on low-entropy fields (intentional for global search)
- No context-aware blinding (by design)

---

## Recommendations

### Must Fix (None)
No critical issues found.

### Should Consider
1. Add closed checks to `SearchCondition*` methods for consistency
2. Add closed checks to `DefaultKeyID()` and `ActiveKeyIDs()`
3. Validate `compressionThreshold` > 0 in options

### Nice to Have
1. Add closed checks to `NeedsRotation` and `ExtractKeyID`
2. Consider adding a `IsClosed()` method for external checking

---

## Test Execution Results

```
go test -race ./...
ok      github.com/ai8future/encryptedcol    coverage: 95.7% of statements

go vet ./...
(no issues)

gofmt -d *.go
(no formatting issues)
```

All 100+ tests pass with race detection enabled.

---

## Conclusion

`encryptedcol` is a well-designed, production-ready cryptographic library. The code demonstrates strong security practices and comprehensive testing. The issues identified are minor consistency improvements rather than bugs. The intentional design decisions documented in AGENTS.md (static HMAC keys, panic on crypto/rand failure, inner key_id redundancy) are correctly implemented and should not be changed.

**Final Grade: 94/100** - Excellent quality, minor polish opportunities.
