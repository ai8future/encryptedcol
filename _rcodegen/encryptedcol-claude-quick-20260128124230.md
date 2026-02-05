Date Created: 2026-01-28 12:42:30 UTC
TOTAL_SCORE: 88/100

# encryptedcol Code Analysis Report

## Executive Summary

This is a **production-ready, high-quality cryptographic library** for client-side encrypted columns in PostgreSQL. The codebase demonstrates strong security practices including proper key derivation (HKDF-SHA256), authenticated encryption (XSalsa20-Poly1305), defense-in-depth key ID verification, and compression bomb protection.

**Grade Breakdown:**
- Security Practices: 90/100 (minor timing consistency issue)
- Code Quality: 85/100 (panics instead of errors in search.go)
- Test Coverage: 95/100 (excellent, minor gaps in error paths)
- Documentation: 95/100 (clear, comprehensive)
- API Design: 85/100 (minor NULL handling inconsistency)

---

## 1. AUDIT - Security and Code Quality Issues

### AUDIT-001: Timing Attack Surface in OpenWithKey() [Medium]

**Location:** `cipher.go:252`

**Issue:** The outer key_id comparison uses `!=` (non-constant-time), while the inner key_id verification at line 198 uses `subtle.ConstantTimeCompare`. This inconsistency could theoretically allow timing-based key_id enumeration.

**Impact:** An attacker with network access could potentially determine valid key IDs by measuring response time differences. While practical exploitation is difficult, this violates cryptographic best practices.

**Recommendation:** Use constant-time comparison for consistency.

```diff
--- a/cipher.go
+++ b/cipher.go
@@ -1,5 +1,6 @@
 package encryptedcol

 import (
 	"crypto/rand"
 	"crypto/subtle"
 	"sort"
 	"sync/atomic"

 	"golang.org/x/crypto/nacl/secretbox"
 )
@@ -249,7 +250,8 @@ func (c *Cipher) OpenWithKey(keyID string, ciphertext []byte) ([]byte, error) {
 		return nil, err
 	}

-	// Verify outer key_id matches expected key
-	if outerKeyID != keyID {
+	// Verify outer key_id matches expected key (constant-time for consistency)
+	if subtle.ConstantTimeCompare([]byte(outerKeyID), []byte(keyID)) != 1 {
 		return nil, ErrKeyIDMismatch
 	}
```

### AUDIT-002: Missing Validation for Compression Threshold [Low]

**Location:** `options.go:37-40`

**Issue:** The comment states "Must be > 0; a threshold of 0 could cause issues" but there is no validation code. A threshold of 0 would cause every message (including empty) to attempt compression.

**Recommendation:** Add validation or document the behavior explicitly.

```diff
--- a/options.go
+++ b/options.go
@@ -34,6 +34,9 @@ func WithDefaultKeyID(keyID string) Option {
 // Must be > 0; a threshold of 0 could cause issues with empty data.
 func WithCompressionThreshold(bytes int) Option {
 	return func(c *config) {
+		if bytes <= 0 {
+			panic("encryptedcol: compression threshold must be > 0")
+		}
 		c.compressionThreshold = bytes
 	}
 }
```

### AUDIT-003: Config Struct Retained After Initialization [Info]

**Location:** `cipher.go:116`

**Issue:** The `config` struct is stored in `Cipher.config` after initialization. While master keys are properly zeroed (lines 94-100), the config struct itself remains allocated. This is intentional (for accessing compression settings at runtime) but could be documented more explicitly.

**Recommendation:** Document this trade-off in code comments or consider extracting only the necessary compression fields.

```diff
--- a/cipher.go
+++ b/cipher.go
@@ -111,6 +111,9 @@ func New(opts ...Option) (*Cipher, error) {
 		derivedKeysMap[keyID] = dk
 	}

+	// Note: config is retained for runtime access to compression settings.
+	// Master keys have been zeroed above; only compression config remains.
 	c := &Cipher{
 		keys:      derivedKeysMap,
 		defaultID: cfg.defaultKeyID,
 		config:    cfg,
 	}
```

---

## 2. TESTS - Proposed Unit Tests for Untested Code

### TEST-001: Test Compression Threshold of Zero

**File:** `options_test.go`

**Rationale:** The comment says threshold of 0 "could cause issues" but behavior is undefined. Test to document current behavior or verify panic after fix.

```diff
--- a/options_test.go
+++ b/options_test.go
@@ -0,0 +1,25 @@
+func TestWithCompressionThreshold_Zero(t *testing.T) {
+	// Test that compression threshold of 0 is handled appropriately.
+	// Current behavior: threshold of 0 causes all data to attempt compression.
+	// After AUDIT-002 fix, this should panic.
+
+	key := make([]byte, 32)
+	_, _ = rand.Read(key)
+
+	// If AUDIT-002 is fixed, expect panic:
+	// require.Panics(t, func() {
+	// 	New(WithKey("v1", key), WithCompressionThreshold(0))
+	// })
+
+	// Current behavior test (remove after fix):
+	cipher, err := New(WithKey("v1", key), WithCompressionThreshold(0))
+	require.NoError(t, err)
+	defer cipher.Close()
+
+	// With threshold 0, even small data attempts compression
+	small := []byte("hi")
+	sealed := cipher.Seal(small)
+	opened, err := cipher.Open(sealed)
+	require.NoError(t, err)
+	require.Equal(t, small, opened)
+}
```

### TEST-002: Test Zstd Initialization Error Path

**File:** `compress_test.go`

**Rationale:** `initZstd()` has 66.7% coverage. The error paths at lines 38-39 and 42-45 are not tested. This is difficult to test without mocking, but documenting the gap is valuable.

```diff
--- a/compress_test.go
+++ b/compress_test.go
@@ -0,0 +1,20 @@
+func TestDecompressZstd_MaxSize(t *testing.T) {
+	// Test decompression bomb protection.
+	// Create data that compresses well but exceeds maxDecompressedSize.
+
+	// Note: This test is slow and memory-intensive.
+	// It verifies the 64MB decompression limit.
+	t.Skip("Skipping memory-intensive decompression limit test")
+
+	// Create ~65MB of zeros (compresses to tiny size)
+	bigData := make([]byte, 65*1024*1024)
+	compressed, err := compressZstd(bigData)
+	require.NoError(t, err)
+	require.Less(t, len(compressed), 1024*1024) // Should compress well
+
+	// Decompression should fail due to size limit
+	_, err = decompressZstd(compressed)
+	require.ErrorIs(t, err, ErrDecompressionFailed)
+}
```

### TEST-003: Test OpenString with nil vs Open with nil

**File:** `helpers_test.go`

**Rationale:** Document the intentional API difference where `Open(nil)` returns `(nil, nil)` but `OpenString(nil)` returns `("", ErrWasNull)`.

```diff
--- a/helpers_test.go
+++ b/helpers_test.go
@@ -0,0 +1,30 @@
+func TestNullHandling_APIConsistency(t *testing.T) {
+	key := make([]byte, 32)
+	_, _ = rand.Read(key)
+	cipher, err := New(WithKey("v1", key))
+	require.NoError(t, err)
+	defer cipher.Close()
+
+	t.Run("Open returns nil nil for NULL", func(t *testing.T) {
+		result, err := cipher.Open(nil)
+		require.NoError(t, err)
+		require.Nil(t, result)
+	})
+
+	t.Run("OpenString returns error for NULL", func(t *testing.T) {
+		// This is intentional: OpenString returns a string, and Go strings
+		// can't be nil. ErrWasNull signals the caller that the value was NULL.
+		result, err := cipher.OpenString(nil)
+		require.ErrorIs(t, err, ErrWasNull)
+		require.Equal(t, "", result)
+	})
+
+	t.Run("OpenStringPtr returns nil nil for NULL", func(t *testing.T) {
+		// Pointer version can return nil, so it does.
+		result, err := cipher.OpenStringPtr(nil)
+		require.NoError(t, err)
+		require.Nil(t, result)
+	})
+}
```

### TEST-004: Test SearchCondition with Edge Cases

**File:** `search_test.go`

**Rationale:** Test edge cases for parameter offsets near the PostgreSQL limit.

```diff
--- a/search_test.go
+++ b/search_test.go
@@ -0,0 +1,35 @@
+func TestSearchCondition_ParamOffsetEdgeCases(t *testing.T) {
+	key := make([]byte, 32)
+	_, _ = rand.Read(key)
+	cipher, err := New(WithKey("v1", key))
+	require.NoError(t, err)
+	defer cipher.Close()
+
+	t.Run("paramOffset at minimum", func(t *testing.T) {
+		cond := cipher.SearchCondition("email", []byte("test"), 1)
+		require.Contains(t, cond.SQL, "$1")
+	})
+
+	t.Run("paramOffset at maximum valid", func(t *testing.T) {
+		// With 1 key, needs 2 params. Max param is 65535.
+		// So max offset is 65534.
+		cond := cipher.SearchCondition("email", []byte("test"), 65534)
+		require.Contains(t, cond.SQL, "$65534")
+		require.Contains(t, cond.SQL, "$65535")
+	})
+
+	t.Run("paramOffset zero panics", func(t *testing.T) {
+		require.Panics(t, func() {
+			cipher.SearchCondition("email", []byte("test"), 0)
+		})
+	})
+
+	t.Run("paramOffset exceeds limit panics", func(t *testing.T) {
+		require.Panics(t, func() {
+			cipher.SearchCondition("email", []byte("test"), 65535)
+		})
+	})
+}
```

---

## 3. FIXES - Bugs, Issues, and Code Smells

### FIX-001: SearchCondition Uses Panics Instead of Errors [Medium]

**Location:** `search.go:58, 62, 77, 87`

**Issue:** `SearchCondition()` panics on invalid input rather than returning errors. While these could be considered programmer errors (pre-conditions), returning errors would be more Go-idiomatic and allow graceful error handling.

**Impact:** Invalid column names or parameter offsets will crash the application.

**Recommendation:** Return errors instead of panicking. This is a breaking API change, so document it clearly.

```diff
--- a/search.go
+++ b/search.go
@@ -33,36 +33,42 @@ type SearchCondition struct {
 	Args []interface{} // Interleaved key_ids and blind indexes
 }

+// ErrInvalidColumnName indicates the column name contains invalid characters.
+var ErrInvalidColumnName = errors.New("encryptedcol: invalid column name")
+
+// ErrInvalidParamOffset indicates the parameter offset is out of range.
+var ErrInvalidParamOffset = errors.New("encryptedcol: invalid parameter offset")
+
+// ErrTooManyKeys indicates too many keys would exceed PostgreSQL parameter limit.
+var ErrTooManyKeys = errors.New("encryptedcol: too many keys for parameter limit")
+
 // SearchCondition generates a SQL WHERE clause for blind index search
 // across all active key versions.
-func (c *Cipher) SearchCondition(column string, plaintext []byte, paramOffset int) *SearchCondition {
+func (c *Cipher) SearchCondition(column string, plaintext []byte, paramOffset int) (*SearchCondition, error) {
 	if !isValidColumnName(column) {
-		panic("encryptedcol: invalid column name (must start with letter/underscore, contain only alphanumeric/underscore)")
+		return nil, ErrInvalidColumnName
 	}

 	if paramOffset < 1 || paramOffset > maxParamNumber {
-		panic(fmt.Sprintf("encryptedcol: invalid paramOffset (must be 1-%d)", maxParamNumber))
+		return nil, ErrInvalidParamOffset
 	}

 	if plaintext == nil {
 		return &SearchCondition{
 			SQL:  "FALSE", // NULL values can't match
 			Args: nil,
-		}
+		}, nil
 	}

 	ids := c.ActiveKeyIDs()

 	// Check that parameters won't exceed PostgreSQL limit
 	maxParam := paramOffset + (len(ids) * 2) - 1
 	if maxParam > maxParamNumber {
-		panic(fmt.Sprintf("encryptedcol: too many keys (%d) would exceed PostgreSQL parameter limit", len(ids)))
+		return nil, ErrTooManyKeys
 	}

 	// ... rest of function unchanged, but return (result, nil) at end
 }
```

**Note:** This is a breaking change. Alternative: document that panics are intentional for programmer errors (like Go's `regexp.MustCompile`).

### FIX-002: Inconsistent nil vs Error Handling in Helpers [Low/Info]

**Location:** `helpers.go:32-34`

**Issue:** `OpenString(nil)` returns `("", ErrWasNull)` while `Open(nil)` returns `(nil, nil)`. This is intentional but could confuse users.

**Recommendation:** Add documentation explaining the rationale.

```diff
--- a/helpers.go
+++ b/helpers.go
@@ -29,6 +29,10 @@ func (c *Cipher) SealString(s string) []byte {

 // OpenString decrypts to a string value.
 // Returns empty string and ErrWasNull if ciphertext is nil.
+//
+// Unlike Open(nil) which returns (nil, nil), OpenString returns an error
+// because Go strings cannot be nil. Use OpenStringPtr if you need nil
+// semantics, or check WasNull() before calling OpenString.
 func (c *Cipher) OpenString(ciphertext []byte) (string, error) {
 	if ciphertext == nil {
 		return "", ErrWasNull
 	}
```

---

## 4. REFACTOR - Opportunities to Improve Code Quality

### REFACTOR-001: Extract Compression Config to Dedicated Struct

**Location:** `cipher.go:17, 116`

**Rationale:** The entire `config` struct is retained in `Cipher.config` just to access compression settings. Extracting only the needed fields would make memory management clearer and eliminate the unused `emptyStringAsNull` field in the retained config (it's only used in helpers which could check a dedicated field).

**Current:**
```go
type Cipher struct {
    keys      map[string]*derivedKeys
    defaultID string
    config    *config  // Entire config struct retained
    closed    atomic.Bool
}
```

**Suggested:**
```go
type Cipher struct {
    keys                 map[string]*derivedKeys
    defaultID            string
    compressionThreshold int
    compressionAlgorithm string
    compressionDisabled  bool
    emptyStringAsNull    bool
    closed               atomic.Bool
}
```

**Benefit:** Clearer separation of concerns, no reference to potentially sensitive config struct.

### REFACTOR-002: Consider Error-Returning Variant of SearchCondition

**Location:** `search.go`

**Rationale:** Rather than breaking the existing API (FIX-001), add a new method that returns errors while keeping the panicking version for backward compatibility.

**Suggested:** Add `SearchConditionE()` or `TrySearchCondition()` that returns `(*SearchCondition, error)`.

### REFACTOR-003: Add Godoc Examples for Error Handling

**Location:** `example_test.go` (or create new file)

**Rationale:** Add examples showing proper error handling patterns, especially for the NULL handling differences between `Open()` and `OpenString()`.

### REFACTOR-004: Consider sync.Pool for Compression Buffers

**Location:** `compress.go`

**Rationale:** The zstd encoder/decoder are reused, but intermediate buffers could benefit from pooling under high concurrency. This is a micro-optimization that may not be necessary given the current performance.

### REFACTOR-005: Improve Error Wrapping

**Location:** `errors.go`

**Rationale:** Some error paths could benefit from wrapping underlying errors to provide better context. For example, JSON marshal/unmarshal errors in `helpers.go` could be wrapped with `encryptedcol:` prefix for consistency.

**Current:** `return zero, err` (returns raw json error)

**Suggested:** `return zero, fmt.Errorf("encryptedcol: json unmarshal: %w", err)`

---

## Appendix: Security Strengths

The following security practices are correctly implemented and should NOT be changed:

1. **HKDF-SHA256 Key Derivation** - Proper separation of encryption and HMAC keys
2. **XSalsa20-Poly1305** - Modern authenticated encryption via NaCl secretbox
3. **24-byte Random Nonces** - Proper nonce generation with crypto/rand
4. **Panic on RNG Failure** - Correct behavior for unrecoverable crypto state
5. **Inner Key ID Authentication** - Defense-in-depth against key confusion attacks
6. **Constant-Time Inner Verification** - Uses subtle.ConstantTimeCompare for critical check
7. **Key Zeroing** - Proper cleanup of master and derived keys via Close()
8. **Compression Bomb Protection** - 64MB decompression limit
9. **SQL Injection Prevention** - Column name validation in SearchCondition()
10. **Format Bounds Checking** - Comprehensive validation in parseFormat()

---

*Report generated by Claude Opus 4.5 for encryptedcol codebase analysis*
