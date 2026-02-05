# encryptedcol - Quick Analysis Report

**Date Created:** 2026-01-21 22:47 PST
**Date Updated:** 2026-01-26 (Review complete: all actionable fixes implemented)

---

## 1. AUDIT - Security and Code Quality Issues

### ~~AUDIT-1: Thread-Safety Issue in Zstd Initialization~~ IMPLEMENTED 2026-01-22
**Severity:** MEDIUM
**File:** `compress.go:21-39`

**Issue:** If encoder creation fails in `initZstd()`, the decoder is never created but `sync.Once` has already fired. Subsequent calls will return a nil decoder.

**PATCH-READY DIFF:**
```diff
--- a/compress.go
+++ b/compress.go
@@ -27,6 +27,10 @@ func initZstd() (*zstd.Encoder, *zstd.Decoder, error) {
 		if zstdErr != nil {
 			return
 		}
 		zstdDecoder, zstdErr = zstd.NewReader(nil)
+		if zstdErr != nil {
+			zstdEncoder.Close()
+			zstdEncoder = nil
+		}
 	})
 	return zstdEncoder, zstdDecoder, zstdErr
 }
```

---

### ~~AUDIT-2: Panic on Invalid Column Names in search.go~~ INTENTIONAL DESIGN
**Severity:** MEDIUM → NOT A BUG
**File:** `search.go:53-60`
**Status:** Intentional design per AGENTS.md

**Assessment:** The panic is intentional for SQL injection prevention. Invalid column names and paramOffset values are programmer errors (static at call site), not runtime errors. This is documented in AGENTS.md as an anti-pattern that should NOT be changed. Breaking the API would also break backwards compatibility for all users.

---

### AUDIT-3: Missing Error Variable in Error Tests
**Severity:** LOW
**File:** `errors_test.go`
**Status:** TEST SUGGESTION (excluded from fix scope)

**Note:** This is a test enhancement, not a code bug. Excluded per rcodegen:fix instructions to avoid test suggestions.

---

### ~~AUDIT-4: Nil Check Order in SealWithKey~~ IMPLEMENTED 2026-01-22
**Severity:** LOW
**File:** `cipher.go:130-137`

**Issue:** When `plaintext == nil`, the function returns before validating `keyID`. This hides invalid keyID errors when nil is passed.

**PATCH-READY DIFF:**
```diff
--- a/cipher.go
+++ b/cipher.go
@@ -127,11 +127,11 @@ func (c *Cipher) Seal(plaintext []byte) []byte {

 // SealWithKey encrypts plaintext using a specific key ID.
 func (c *Cipher) SealWithKey(keyID string, plaintext []byte) ([]byte, error) {
-	if plaintext == nil {
-		return nil, nil // NULL preservation
-	}
 	if _, ok := c.keys[keyID]; !ok {
 		return nil, ErrKeyNotFound
 	}
+	if plaintext == nil {
+		return nil, nil // NULL preservation
+	}

 	return c.sealInternal(keyID, plaintext), nil
 }
```

---

### ~~AUDIT-5: Potential Negative Savings Calculation~~ NOT A BUG
**Severity:** LOW → NOT A BUG
**File:** `compress.go:97-104`
**Status:** Current code handles this correctly

**Assessment:** When `compressedSize >= originalSize`, the savings calculation produces a value <= 0, which is less than `minCompressionSavings` (0.10). The existing check `if savings < minCompressionSavings` correctly handles this case. Adding an explicit early check would be marginally clearer but is not a bug fix.

---

## 2. TESTS - Proposed Unit Tests for Untested Code

### TEST-1: Verify Close() Actually Zeros Key Material
**Severity:** MEDIUM
**File:** `cipher_test.go`

**Issue:** Current `TestClose` only verifies keys become nil, not that they're zeroed.

**PATCH-READY DIFF:**
```diff
--- a/cipher_test.go
+++ b/cipher_test.go
@@ -319,6 +319,32 @@ func TestClose(t *testing.T) {
 	require.Nil(t, cipher.keys)
 }

+func TestClose_KeysZeroed(t *testing.T) {
+	cipher, err := New(WithKey("v1", testKey("v1")))
+	require.NoError(t, err)
+
+	// Get references to the derived keys before close
+	var encKeys [][]byte
+	var hmacKeys [][]byte
+	for _, dk := range cipher.keys {
+		encCopy := make([]byte, len(dk.encryption))
+		hmacCopy := make([]byte, len(dk.hmac))
+		copy(encCopy, dk.encryption[:])
+		copy(hmacCopy, dk.hmac[:])
+		encKeys = append(encKeys, encCopy)
+		hmacKeys = append(hmacKeys, hmacCopy)
+	}
+
+	cipher.Close()
+
+	// Verify all captured key bytes are now zero
+	for i, dk := range cipher.keys {
+		require.NotEqual(t, encKeys[i], dk.encryption[:], "encryption key not zeroed")
+		require.NotEqual(t, hmacKeys[i], dk.hmac[:], "hmac key not zeroed")
+	}
+}
+
 func testKey(id string) []byte {
```

---

### TEST-2: SearchCondition Boundary Test for paramOffset=1
**Severity:** LOW
**File:** `search_test.go`

**Issue:** No test for the exact boundary value `paramOffset=1`.

**PATCH-READY DIFF:**
```diff
--- a/search_test.go
+++ b/search_test.go
@@ -40,6 +40,22 @@ func TestSearchCondition(t *testing.T) {
 	require.Equal(t, 2, len(cond.Args))
 }

+func TestSearchCondition_ParamOffsetBoundary(t *testing.T) {
+	cipher, err := New(WithKey("v1", testKey("v1")))
+	require.NoError(t, err)
+	defer cipher.Close()
+
+	// Test exact boundary: paramOffset = 1 (minimum valid value)
+	cond := cipher.SearchCondition("email", []byte("test@example.com"), 1)
+	require.NotNil(t, cond)
+	require.Contains(t, cond.SQL, "$1")
+	require.Contains(t, cond.SQL, "$2")
+
+	// Verify the SQL uses correct parameter numbers
+	require.Equal(t, "email_idx = $1 AND email_blind = $2", cond.SQL)
+	require.Equal(t, 2, len(cond.Args))
+}
+
 func TestSearchCondition_InvalidColumn(t *testing.T) {
```

---

### TEST-3: Type-Safe Assertions in search_test.go
**Severity:** LOW
**File:** `search_test.go:77-80`

**Issue:** Type assertions could panic if implementation changes. Use require for safety.

**PATCH-READY DIFF:**
```diff
--- a/search_test.go
+++ b/search_test.go
@@ -74,9 +74,13 @@ func TestSearchConditionString(t *testing.T) {
 	cond1 := cipher.SearchCondition("email", []byte("test@example.com"), 1)
 	cond2 := cipher.SearchConditionString("email", "test@example.com", 1)

-	require.Equal(t, cond1.SQL, cond2.SQL)
-	require.Equal(t, cond1.Args[0], cond2.Args[0])
-	require.True(t, bytes.Equal(cond1.Args[1].([]byte), cond2.Args[1].([]byte)))
+	require.Equal(t, cond1.SQL, cond2.SQL, "SQL should match")
+	require.Equal(t, cond1.Args[0], cond2.Args[0], "first arg should match")
+
+	idx1, ok := cond1.Args[1].([]byte)
+	require.True(t, ok, "cond1.Args[1] should be []byte")
+	idx2, ok := cond2.Args[1].([]byte)
+	require.True(t, ok, "cond2.Args[1] should be []byte")
+	require.True(t, bytes.Equal(idx1, idx2), "blind indexes should match")
 }
```

---

### TEST-4: Normalizer Edge Case - Extremely Long Phone Numbers
**Severity:** LOW
**File:** `normalize_test.go`

**Issue:** No test for very long phone numbers.

**PATCH-READY DIFF:**
```diff
--- a/normalize_test.go
+++ b/normalize_test.go
@@ -174,6 +174,20 @@ func TestNormalizePhone_UnicodeDigits(t *testing.T) {
 	}
 }

+func TestNormalizePhone_ExtremelyLong(t *testing.T) {
+	tests := []struct {
+		name  string
+		input string
+	}{
+		{"100 digits", strings.Repeat("5", 100)},
+		{"1000 digits", strings.Repeat("5", 1000)},
+	}
+	for _, tt := range tests {
+		t.Run(tt.name, func(t *testing.T) {
+			result := NormalizePhone(tt.input)
+			require.Equal(t, tt.input, result)
+		})
+	}
+}
+
 func TestNormalizeNone(t *testing.T) {
```

---

### TEST-5: Concurrent Zstd Initialization Test
**Severity:** MEDIUM
**File:** `compress_test.go`

**Issue:** No test verifying `sync.Once` correctness under concurrent initialization.

**Note:** This test requires exposing internal state for reset. As a design recommendation rather than immediate patch:

```go
// compress_internal_test.go (new file, same package)
package encryptedcol

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// resetZstdState resets global zstd state for testing
func resetZstdState() {
	zstdOnce = sync.Once{}
	zstdEncoder = nil
	zstdDecoder = nil
	zstdErr = nil
}

func TestInitZstd_ConcurrentSafety(t *testing.T) {
	resetZstdState()
	defer resetZstdState()

	var wg sync.WaitGroup
	results := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			enc, dec, err := initZstd()
			if err != nil {
				results <- err
				return
			}
			if enc == nil || dec == nil {
				results <- fmt.Errorf("nil encoder or decoder")
				return
			}
			results <- nil
		}()
	}

	wg.Wait()
	close(results)

	for err := range results {
		require.NoError(t, err)
	}
}
```

---

## 3. FIXES - Bugs, Issues, and Code Smells

### FIX-1: Incomplete Error Variable Coverage in errors_test.go
**Severity:** LOW
**File:** `errors_test.go`

**Issue:** Not all exported errors are tested in `TestErrors_Identity`.

*See AUDIT-3 for patch.*

---

### FIX-2: Fragile Type Assertions in Tests
**Severity:** LOW
**File:** `search_test.go:77-80`

**Issue:** Direct type assertions without checking could panic.

*See TEST-3 for patch.*

---

### ~~FIX-3: Nil Check Order Hides Errors~~ IMPLEMENTED 2026-01-22
**Severity:** LOW
**File:** `cipher.go:130-137`

**Issue:** Invalid keyID error hidden when plaintext is nil.

*See AUDIT-4 for patch.*

---

### FIX-4: Missing strings Import in normalize_test.go for New Test
**Severity:** LOW
**File:** `normalize_test.go`

**Note:** If TEST-4 is added, ensure `strings` is imported:

**PATCH-READY DIFF:**
```diff
--- a/normalize_test.go
+++ b/normalize_test.go
@@ -3,6 +3,7 @@ package encryptedcol
 import (
 	"testing"
+	"strings"

 	"github.com/stretchr/testify/require"
 )
```

---

### ~~FIX-5: Zstd Decoder Not Cleaned Up on Failure~~ IMPLEMENTED 2026-01-22
**Severity:** MEDIUM
**File:** `compress.go:21-39`

**Issue:** If decoder creation fails after encoder succeeds, encoder is leaked.

*See AUDIT-1 for patch.*

---

## 4. REFACTOR - Code Quality Improvements

### REFACTOR-1: Extract Compression to Testable Component
**File:** `compress.go`

**Current State:** Global variables with `sync.Once` make testing difficult.

**Recommendation:** Encapsulate compression state in a struct that can be injected into `Cipher`:

```go
type Compressor struct {
    encoder *zstd.Encoder
    decoder *zstd.Decoder
    once    sync.Once
    err     error
}

func NewCompressor() *Compressor {
    return &Compressor{}
}

func (c *Compressor) Compress(data []byte) ([]byte, byte, error) {
    // Implementation
}

func (c *Compressor) Decompress(data []byte, flag byte) ([]byte, error) {
    // Implementation
}
```

**Benefits:**
- Testable in isolation
- Mockable for unit tests
- No global state

---

### REFACTOR-2: Consistent Error Handling Pattern in search.go
**File:** `search.go`

**Current State:** Uses `panic()` for validation errors.

**Recommendation:** Consider a builder pattern that validates at build time:

```go
type SearchBuilder struct {
    cipher *Cipher
    errors []error
}

func (c *Cipher) Search() *SearchBuilder {
    return &SearchBuilder{cipher: c}
}

func (sb *SearchBuilder) Column(name string) *SearchBuilder {
    if !isValidColumnName(name) {
        sb.errors = append(sb.errors, fmt.Errorf("invalid column: %q", name))
    }
    return sb
}

func (sb *SearchBuilder) Build() (*SearchCondition, error) {
    if len(sb.errors) > 0 {
        return nil, errors.Join(sb.errors...)
    }
    // Build condition
}
```

---

### REFACTOR-3: Extract Format Validation Functions
**File:** `format.go`

**Current State:** All validation is inline in `parseFormat()`.

**Recommendation:** Extract validation for clarity and reusability:

```go
func validateFormatLength(data []byte) error {
    minLen := 1 + 1 + 1 + nonceSize + 1 // flag + keyIDLen + minKeyID + nonce + minData
    if len(data) < minLen {
        return ErrInvalidFormat
    }
    return nil
}

func validateKeyIDLength(keyIDLen int) error {
    if keyIDLen == 0 || keyIDLen > 255 {
        return ErrInvalidFormat
    }
    return nil
}
```

---

### REFACTOR-4: Add Context Support for Long Operations
**File:** `cipher.go`, `rotate.go`

**Current State:** No context.Context support for cancellation.

**Recommendation:** Add context-aware variants for operations that may process large datasets:

```go
func (c *Cipher) SealWithContext(ctx context.Context, plaintext []byte) ([]byte, error) {
    select {
    case <-ctx.Done():
        return nil, ctx.Err()
    default:
        return c.Seal(plaintext), nil
    }
}
```

**Benefits:**
- Graceful cancellation
- Timeout support
- Standard Go patterns

---

### REFACTOR-5: Document Panic Behavior Prominently
**File:** `search.go`, `doc.go`

**Current State:** Panics are used for validation but not prominently documented.

**Recommendation:** If keeping panics (to avoid breaking API), add prominent documentation:

```go
// SearchCondition creates a SQL condition for searching encrypted columns.
//
// IMPORTANT: This function panics if column name is invalid (SQL injection prevention)
// or if paramOffset < 1. Callers should validate inputs before calling.
//
// Valid column names must start with a letter or underscore and contain only
// alphanumeric characters and underscores.
func (c *Cipher) SearchCondition(column string, plaintext []byte, paramOffset int) *SearchCondition {
```

---

## Summary

| Category | Critical | High | Medium | Low | Total | Done |
|----------|----------|------|--------|-----|-------|------|
| AUDIT    | 0        | 0    | 2      | 3   | 5     | 3 (AUDIT-1, AUDIT-4 done; AUDIT-2, AUDIT-5 not bugs) |
| TESTS    | 0        | 0    | 2      | 3   | 5     | - (excluded) |
| FIXES    | 0        | 0    | 1      | 4   | 5     | 2 (FIX-3, FIX-5) |
| REFACTOR | -        | -    | -      | -   | 5     | - (excluded) |

**Status Notes:**
- AUDIT-1/FIX-5: Zstd cleanup on decoder failure - **DONE**
- AUDIT-2: SearchCondition panic - **INTENTIONAL DESIGN** (not a bug)
- AUDIT-4/FIX-3: SealWithKey nil check order - **DONE**
- AUDIT-5: Negative savings - **NOT A BUG** (existing code handles correctly)

**Overall Assessment:** Production-ready code with excellent cryptographic practices. All actionable fixes implemented.
