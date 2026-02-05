Date Created: 2026-01-28 12:36:54 UTC
TOTAL_SCORE: 87/100

# encryptedcol Security & Code Quality Audit Report

## Executive Summary

The encryptedcol library is a well-designed Go cryptographic library for client-side encrypted columns in PostgreSQL/Supabase. The codebase demonstrates strong cryptographic fundamentals with XSalsa20-Poly1305 (NaCl secretbox), proper key derivation via HKDF-SHA256, and thoughtful security decisions like inner key ID authentication to prevent key confusion attacks.

**Overall Assessment:** Production-ready with several medium-priority issues that should be addressed.

### Score Breakdown
- **Security Design:** 23/25 (Strong crypto choices, minor decompression timing concern)
- **Error Handling:** 20/25 (Inconsistent panic vs error behavior)
- **API Consistency:** 18/20 (Some methods panic, others return errors)
- **Code Quality:** 15/15 (Clean, idiomatic Go)
- **Test Coverage:** 11/15 (Good but some edge cases missing)

---

## Issues Identified

### CRITICAL: None Found

The library has no critical security vulnerabilities. The cryptographic implementation is sound.

---

### HIGH SEVERITY ISSUES

#### Issue #1: Inconsistent Error Handling for Closed Cipher

**Files:** `cipher.go` (lines 128-129, 139-140), `blindindex.go` (lines 15-16, 27-28, 45-46)

**Severity:** HIGH

**Description:**
The library has inconsistent behavior when methods are called on a closed Cipher:

| Method | Behavior on Closed Cipher |
|--------|---------------------------|
| `Seal()` | **Panics** |
| `SealWithKey()` | Returns `ErrCipherClosed` |
| `Open()` | Returns `ErrCipherClosed` |
| `OpenWithKey()` | Returns `ErrCipherClosed` |
| `BlindIndex()` | **Panics** |
| `BlindIndexes()` | **Panics** |
| `BlindIndexWithKey()` | Returns `ErrCipherClosed` |

**Impact:** Code that handles one method's error correctly will crash when the same usage pattern is applied to another method. This violates the principle of least surprise and makes the library harder to use safely.

**Suggested Fix:**
Standardize all methods to return `ErrCipherClosed` instead of panicking.

```diff
--- a/cipher.go
+++ b/cipher.go
@@ -125,8 +125,8 @@ func New(opts ...Option) (*Cipher, error) {
 // The ciphertext format is:
 // [flag:1][keyIDLen:1][keyID:n][nonce:24][secretbox(innerKeyID + plaintext)]
-func (c *Cipher) Seal(plaintext []byte) []byte {
+func (c *Cipher) Seal(plaintext []byte) ([]byte, error) {
 	if c.closed.Load() {
-		panic("encryptedcol: use of closed Cipher")
+		return nil, ErrCipherClosed
 	}
 	if plaintext == nil {
-		return nil // NULL preservation
+		return nil, nil // NULL preservation
 	}
-	return c.sealWithKeyID(c.defaultID, plaintext)
+	return c.sealWithKeyID(c.defaultID, plaintext), nil
 }
```

```diff
--- a/blindindex.go
+++ b/blindindex.go
@@ -12,10 +12,10 @@ import (
 // This allows database lookups without exposing the plaintext.
-func (c *Cipher) BlindIndex(plaintext []byte) []byte {
+func (c *Cipher) BlindIndex(plaintext []byte) ([]byte, error) {
 	if c.closed.Load() {
-		panic("encryptedcol: use of closed Cipher")
+		return nil, ErrCipherClosed
 	}
 	if plaintext == nil {
-		return nil
+		return nil, nil
 	}
-	return c.computeHMAC(c.defaultID, plaintext)
+	return c.computeHMAC(c.defaultID, plaintext), nil
 }

@@ -42,10 +42,10 @@ func (c *Cipher) BlindIndexWithKey(keyID string, plaintext []byte) ([]byte, erro
 // BlindIndexes computes HMAC blind indexes for all active key versions.
-func (c *Cipher) BlindIndexes(plaintext []byte) map[string][]byte {
+func (c *Cipher) BlindIndexes(plaintext []byte) (map[string][]byte, error) {
 	if c.closed.Load() {
-		panic("encryptedcol: use of closed Cipher")
+		return nil, ErrCipherClosed
 	}
 	if plaintext == nil {
-		return nil
+		return nil, nil
 	}

 	indexes := make(map[string][]byte, len(c.keys))
 	for keyID := range c.keys {
 		indexes[keyID] = c.computeHMAC(keyID, plaintext)
 	}
-	return indexes
+	return indexes, nil
 }
```

**Note:** This is a breaking API change. Consider:
1. A new major version (v2)
2. Deprecating the old methods and adding new `*Safe` variants
3. Documenting the panic behavior prominently

---

#### Issue #2: Decompression Size Check Timing

**File:** `compress.go` (lines 68-74)

**Severity:** HIGH (defense-in-depth concern)

**Description:**
The decompression bomb protection check happens AFTER the full decompression:

```go
func decompressZstd(data []byte) ([]byte, error) {
    _, decoder, err := initZstd()
    if err != nil {
        return nil, err
    }
    result, err := decoder.DecodeAll(data, nil)  // Allocates and decompresses FIRST
    if err != nil {
        return nil, ErrDecompressionFailed
    }
    if len(result) > maxDecompressedSize {  // Check AFTER allocation
        return nil, ErrDecompressionFailed
    }
    return result, nil
}
```

**Impact:** While the zstd library has internal safeguards, a malicious ciphertext could potentially cause significant memory allocation before the explicit check kicks in.

**Suggested Fix:**
Use zstd decoder options to set memory limits at initialization:

```diff
--- a/compress.go
+++ b/compress.go
@@ -34,7 +34,10 @@ func initZstd() (*zstd.Encoder, *zstd.Decoder, error) {
 		if zstdErr != nil {
 			return
 		}
-		zstdDecoder, zstdErr = zstd.NewReader(nil)
+		zstdDecoder, zstdErr = zstd.NewReader(nil,
+			zstd.WithDecoderMaxMemory(uint64(maxDecompressedSize)),
+			zstd.WithDecoderConcurrency(1),  // Limit parallel decompressions
+		)
 		if zstdErr != nil {
 			// Clean up encoder if decoder creation fails
 			zstdEncoder.Close()
```

---

### MEDIUM SEVERITY ISSUES

#### Issue #3: StaticKeyProvider.Close() Doesn't Clear defaultID

**File:** `provider.go` (lines 100-107)

**Severity:** MEDIUM

**Description:**
The `Close()` method zeros the key material but leaves the `defaultID` string in memory:

```go
func (p *StaticKeyProvider) Close() {
    for _, key := range p.keys {
        for i := range key {
            key[i] = 0
        }
    }
    p.keys = nil
    // defaultID is NOT zeroed!
}
```

**Impact:** While `defaultID` is not sensitive cryptographic material (it's just an identifier), this inconsistency could:
1. Leak information about key naming conventions
2. Indicate incomplete security hygiene

**Suggested Fix:**

```diff
--- a/provider.go
+++ b/provider.go
@@ -104,4 +104,5 @@ func (p *StaticKeyProvider) Close() {
 		}
 	}
 	p.keys = nil
+	p.defaultID = ""
 }
```

---

#### Issue #4: NewWithProvider() Doesn't Zero Partial Keys on Error

**File:** `provider.go` (lines 22-51)

**Severity:** MEDIUM

**Description:**
If key retrieval fails partway through the loop, already-fetched keys are not zeroed:

```go
keys := make(map[string][]byte)
for _, keyID := range activeIDs {
    key, err := provider.GetKey(keyID)
    if err != nil {
        return nil, err  // <-- Fetched keys not zeroed!
    }
    keys[keyID] = key
}
```

**Impact:** On transient errors, key material from successful fetches remains in memory and could be exposed via heap inspection.

**Suggested Fix:**

```diff
--- a/provider.go
+++ b/provider.go
@@ -28,6 +28,11 @@ func NewWithProvider(provider KeyProvider) (*Cipher, error) {
 	for _, keyID := range activeIDs {
 		key, err := provider.GetKey(keyID)
 		if err != nil {
+			// Zero out any keys fetched so far
+			for _, k := range keys {
+				for i := range k {
+					k[i] = 0
+				}
+			}
 			return nil, err
 		}
 		keys[keyID] = key
```

---

#### Issue #5: NeedsRotation() Silently Returns false on Format Errors

**File:** `rotate.go` (lines 83-94)

**Severity:** MEDIUM

**Description:**
The function returns `false` when it can't parse the ciphertext format:

```go
func (c *Cipher) NeedsRotation(ciphertext []byte) bool {
    _, keyID, _, _, err := parseFormat(ciphertext)
    if err != nil {
        return false  // Silent failure
    }
    return keyID != c.defaultID
}
```

**Impact:**
- Corrupted ciphertext won't be flagged for rotation
- No way to distinguish "doesn't need rotation" from "can't determine"
- The documentation already notes this behavior (line 81-82), but API consumers may miss it

**Suggested Fix:**
Add a variant that returns errors:

```diff
--- a/rotate.go
+++ b/rotate.go
@@ -93,3 +93,18 @@ func (c *Cipher) NeedsRotation(ciphertext []byte) bool {

 	return keyID != c.defaultID
 }
+
+// NeedsRotationErr is like NeedsRotation but returns an error for invalid ciphertext.
+// Use this when you need to distinguish between "no rotation needed" and "can't parse".
+func (c *Cipher) NeedsRotationErr(ciphertext []byte) (bool, error) {
+	if ciphertext == nil {
+		return false, nil
+	}
+
+	_, keyID, _, _, err := parseFormat(ciphertext)
+	if err != nil {
+		return false, err
+	}
+
+	return keyID != c.defaultID, nil
+}
```

---

### LOW SEVERITY ISSUES

#### Issue #6: SearchCondition Panics on Invalid User Input

**File:** `search.go` (lines 57-62, 76-77)

**Severity:** LOW

**Description:**
The function panics on invalid input instead of returning errors:

```go
func (c *Cipher) SearchCondition(column string, plaintext []byte, paramOffset int) *SearchCondition {
    if !isValidColumnName(column) {
        panic(...)  // User input - should return error
    }
    if paramOffset < 1 || paramOffset > maxParamNumber {
        panic(...)  // User input - should return error
    }
```

**Impact:** SQL builders are typically used in request handlers. A panic from invalid column name could crash the entire server instead of returning an error response.

**Suggested Fix:**
Add error-returning variants:

```diff
--- a/search.go
+++ b/search.go
@@ -100,3 +100,45 @@ func (c *Cipher) SearchCondition(column string, plaintext []byte, paramOffset in
 	}
 }

+// SearchConditionErr is like SearchCondition but returns an error instead of panicking.
+// Use this when the column name comes from user input.
+func (c *Cipher) SearchConditionErr(column string, plaintext []byte, paramOffset int) (*SearchCondition, error) {
+	if !isValidColumnName(column) {
+		return nil, errors.New("encryptedcol: invalid column name")
+	}
+
+	if paramOffset < 1 || paramOffset > maxParamNumber {
+		return nil, fmt.Errorf("encryptedcol: invalid paramOffset (must be 1-%d)", maxParamNumber)
+	}
+
+	if plaintext == nil {
+		return &SearchCondition{
+			SQL:  "FALSE",
+			Args: nil,
+		}, nil
+	}
+
+	ids := c.ActiveKeyIDs()
+
+	maxParam := paramOffset + (len(ids) * 2) - 1
+	if maxParam > maxParamNumber {
+		return nil, fmt.Errorf("encryptedcol: too many keys (%d) would exceed PostgreSQL parameter limit", len(ids))
+	}
+
+	parts := make([]string, 0, len(ids))
+	args := make([]interface{}, 0, len(ids)*2)
+
+	for _, keyID := range ids {
+		idxHash, err := c.BlindIndexWithKey(keyID, plaintext)
+		if err != nil {
+			return nil, fmt.Errorf("encryptedcol: internal error: %w", err)
+		}
+
+		part := fmt.Sprintf("(key_id = $%d AND %s_idx = $%d)", paramOffset, column, paramOffset+1)
+		parts = append(parts, part)
+		args = append(args, keyID, idxHash)
+		paramOffset += 2
+	}
+
+	return &SearchCondition{
+		SQL:  strings.Join(parts, " OR "),
+		Args: args,
+	}, nil
+}
```

---

#### Issue #7: WithCompressionThreshold() Accepts Invalid Values

**File:** `options.go` (lines 37-41)

**Severity:** LOW

**Description:**
No validation on threshold value:

```go
func WithCompressionThreshold(bytes int) Option {
    return func(c *config) {
        c.compressionThreshold = bytes  // Could be 0 or negative!
    }
}
```

**Impact:** A threshold of 0 would cause all data to be compressed. A negative threshold would never trigger compression (behavior depends on comparison). The documentation on line 36 mentions "Must be > 0" but it's not enforced.

**Suggested Fix:**

```diff
--- a/options.go
+++ b/options.go
@@ -35,6 +35,9 @@ func WithDefaultKeyID(keyID string) Option {
 // Must be > 0; a threshold of 0 could cause issues with empty data.
 func WithCompressionThreshold(bytes int) Option {
 	return func(c *config) {
+		if bytes <= 0 {
+			bytes = defaultCompressionThreshold
+		}
 		c.compressionThreshold = bytes
 	}
 }
```

---

### INFORMATIONAL

#### Issue #8: Integer Overflow Theoretical Risk in SearchCondition

**File:** `search.go` (line 75)

**Severity:** INFO (theoretical only)

**Description:**
```go
maxParam := paramOffset + (len(ids) * 2) - 1
```

If `paramOffset` were extremely large (near max int), this could theoretically overflow before the bounds check. However, this is not exploitable in practice because:
1. `paramOffset` is already validated to be 1-65535
2. `len(ids)` is bounded by the number of keys
3. The sum cannot exceed int limits under these constraints

**Recommendation:** Add a comment explaining why this is safe:

```diff
--- a/search.go
+++ b/search.go
@@ -72,6 +72,8 @@ func (c *Cipher) SearchCondition(column string, plaintext []byte, paramOffset in

 	ids := c.ActiveKeyIDs()

+	// Safe: paramOffset is 1-65535, len(ids)*2 is bounded by key count,
+	// so maxParam cannot overflow int even on 32-bit systems
 	maxParam := paramOffset + (len(ids) * 2) - 1
```

---

#### Issue #9: Key ID Size Constraint Documentation

**File:** `cipher.go` (line 78-83)

**Severity:** INFO

**Description:**
The 255-byte limit on key IDs is enforced but not prominently documented.

**Recommendation:** Add documentation to `WithKey()`:

```diff
--- a/options.go
+++ b/options.go
@@ -6,6 +6,7 @@ type Option func(*config)
 // WithKey registers a master key with the given key ID.
 // The master key must be exactly 32 bytes.
+// The key ID must be 1-255 bytes (limited by wire format).
 // Multiple keys can be registered for key rotation support.
```

---

## Test Coverage Gaps Identified

1. **Compression threshold edge cases:** No tests for negative/zero threshold values
2. **Closed cipher consistency:** Tests exist but don't verify the inconsistent behavior
3. **Provider error cleanup:** No test for key zeroing on partial provider failure

---

## Positive Observations

1. **Strong cryptographic foundations:** XSalsa20-Poly1305 is a solid choice, with proper nonce handling
2. **Defense in depth:** Inner key ID authentication prevents key confusion attacks
3. **Memory safety:** Key material is zeroed after use in most places
4. **Thread safety:** Proper use of `sync.Once` and `atomic.Bool`
5. **Comprehensive test suite:** Table-driven tests with good coverage
6. **Clean API design:** Functional options pattern, NULL preservation
7. **SQL injection prevention:** Column name validation in `SearchCondition`

---

## Summary Table

| Issue | File | Severity | Category | Breaking Change? |
|-------|------|----------|----------|------------------|
| Inconsistent closed cipher behavior | cipher.go, blindindex.go | HIGH | API consistency | Yes (if fixed) |
| Decompression check timing | compress.go | HIGH | Memory safety | No |
| Provider.Close() incomplete | provider.go | MEDIUM | Crypto hygiene | No |
| Provider error key cleanup | provider.go | MEDIUM | Key handling | No |
| NeedsRotation() silent failure | rotate.go | MEDIUM | Error handling | No (add variant) |
| SearchCondition panics | search.go | LOW | API design | No (add variant) |
| Threshold validation | options.go | LOW | Input validation | No |
| Integer overflow comment | search.go | INFO | Documentation | No |
| Key ID docs | options.go | INFO | Documentation | No |

---

## Recommendations

### Immediate (before next release)
1. Add `zstd.WithDecoderMaxMemory()` to decompression initialization
2. Clear `defaultID` in `StaticKeyProvider.Close()`
3. Zero partial keys on `NewWithProvider()` error

### Short-term (next minor version)
1. Add `SearchConditionErr()` variant
2. Add `NeedsRotationErr()` variant
3. Validate compression threshold

### Long-term (next major version)
1. Standardize panic vs error behavior across API
2. Consider making `Seal()` return error for consistency

---

*Report generated by Claude Opus 4.5 code audit*
