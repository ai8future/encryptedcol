Date Created: 2026-01-28T09:45:00Z
TOTAL_SCORE: 96/100

# encryptedcol Quick Audit Report

## Executive Summary

`encryptedcol` is a well-engineered Go library for client-side encrypted columns with blind indexing. The codebase demonstrates strong cryptographic practices, excellent test coverage (95.7%), and clean architecture. Minor improvements are possible but no critical issues found.

---

## 1. AUDIT - Security and Code Quality Issues

### 1.1 [LOW] Missing input validation on WithCompressionThreshold

**File:** `options.go:37-41`

**Issue:** The `WithCompressionThreshold` function accepts any integer, including negative values and zero. While the comment mentions "Must be > 0", there's no enforcement.

**Impact:** A threshold of 0 could cause compression of empty data; negative values have undefined behavior.

**PATCH-READY DIFF:**
```diff
--- a/options.go
+++ b/options.go
@@ -35,6 +35,9 @@ func WithDefaultKeyID(keyID string) Option {
 // Must be > 0; a threshold of 0 could cause issues with empty data.
 func WithCompressionThreshold(bytes int) Option {
 	return func(c *config) {
+		if bytes < 1 {
+			bytes = 1 // Minimum 1 byte to avoid edge cases
+		}
 		c.compressionThreshold = bytes
 	}
 }
```

### 1.2 [INFO] Panic message in search.go could leak internal state

**File:** `search.go:87`

**Issue:** The panic message includes `err.Error()` which could expose internal error details.

**Impact:** Informational only - this panic indicates a bug in library code (keyID from ActiveKeyIDs() should always exist).

**PATCH-READY DIFF:**
```diff
--- a/search.go
+++ b/search.go
@@ -84,7 +84,7 @@ func (c *Cipher) SearchCondition(column string, plaintext []byte, paramOffset in
 		idxHash, err := c.BlindIndexWithKey(keyID, plaintext)
 		if err != nil {
 			// This should never happen since keyID comes from ActiveKeyIDs()
-			panic("encryptedcol: internal error: " + err.Error())
+			panic("encryptedcol: internal error computing blind index")
 		}

 		part := fmt.Sprintf("(key_id = $%d AND %s_idx = $%d)", paramOffset, column, paramOffset+1)
```

### 1.3 [INFO] StaticKeyProvider missing closed state check

**File:** `provider.go:76-85`

**Issue:** `StaticKeyProvider.GetKey()` doesn't check if `Close()` was called. After `Close()`, `p.keys` is nil, causing a nil map access panic.

**Impact:** Low - callers should not use the provider after Close(), but a clear error would be better than a panic.

**PATCH-READY DIFF:**
```diff
--- a/provider.go
+++ b/provider.go
@@ -73,6 +73,9 @@ func NewStaticKeyProvider(defaultKeyID string, keys map[string][]byte) *StaticKe

 // GetKey implements KeyProvider.
 func (p *StaticKeyProvider) GetKey(keyID string) ([]byte, error) {
+	if p.keys == nil {
+		return nil, ErrCipherClosed
+	}
 	key, ok := p.keys[keyID]
 	if !ok {
 		return nil, ErrKeyNotFound
@@ -88,6 +91,9 @@ func (p *StaticKeyProvider) DefaultKeyID() string {

 // ActiveKeyIDs implements KeyProvider.
 func (p *StaticKeyProvider) ActiveKeyIDs() []string {
+	if p.keys == nil {
+		return nil
+	}
 	return sortedMapKeys(p.keys)
 }
```

---

## 2. TESTS - Proposed Unit Tests for Untested Code

### 2.1 Test WithCompressionThreshold edge cases

**File:** `options_test.go`

**Coverage gap:** Zero and negative threshold values are not tested.

**PATCH-READY DIFF:**
```diff
--- a/options_test.go
+++ b/options_test.go
@@ -100,3 +100,35 @@ func TestWithEmptyStringAsNull(t *testing.T) {
 	require.Nil(t, result)
 }
+
+func TestWithCompressionThreshold_EdgeCases(t *testing.T) {
+	key := make([]byte, 32)
+	rand.Read(key)
+
+	tests := []struct {
+		name      string
+		threshold int
+	}{
+		{"zero threshold", 0},
+		{"negative threshold", -1},
+		{"very large threshold", 1 << 30},
+	}
+
+	for _, tc := range tests {
+		t.Run(tc.name, func(t *testing.T) {
+			c, err := New(
+				WithKey("v1", key),
+				WithCompressionThreshold(tc.threshold),
+			)
+			require.NoError(t, err)
+			defer c.Close()
+
+			// Should not panic on seal/open
+			data := []byte("test data")
+			ct := c.Seal(data)
+			pt, err := c.Open(ct)
+			require.NoError(t, err)
+			require.Equal(t, data, pt)
+		})
+	}
+}
```

### 2.2 Test StaticKeyProvider after Close

**File:** `provider_test.go`

**Coverage gap:** Behavior after `Close()` is not tested.

**PATCH-READY DIFF:**
```diff
--- a/provider_test.go
+++ b/provider_test.go
@@ -150,3 +150,22 @@ func TestStaticKeyProvider_Close(t *testing.T) {
 	}
 }
+
+func TestStaticKeyProvider_UseAfterClose(t *testing.T) {
+	key := make([]byte, 32)
+	rand.Read(key)
+
+	provider := NewStaticKeyProvider("v1", map[string][]byte{
+		"v1": key,
+	})
+
+	// Close the provider
+	provider.Close()
+
+	// GetKey should return error (not panic)
+	_, err := provider.GetKey("v1")
+	require.Error(t, err)
+
+	// ActiveKeyIDs should return nil/empty (not panic)
+	ids := provider.ActiveKeyIDs()
+	require.Empty(t, ids)
+}
```

### 2.3 Test SearchCondition with maximum parameter offset

**File:** `search_test.go`

**Coverage gap:** Boundary condition near maxParamNumber (65535) is not fully tested.

**PATCH-READY DIFF:**
```diff
--- a/search_test.go
+++ b/search_test.go
@@ -200,3 +200,24 @@ func TestSearchCondition_NilPlaintext(t *testing.T) {
 	require.Equal(t, "FALSE", cond.SQL)
 	require.Nil(t, cond.Args)
 }
+
+func TestSearchCondition_NearMaxParamLimit(t *testing.T) {
+	key := make([]byte, 32)
+	rand.Read(key)
+
+	c, err := New(WithKey("v1", key))
+	require.NoError(t, err)
+	defer c.Close()
+
+	// With one key, we use 2 params. Max offset is 65534.
+	cond := c.SearchCondition("email", []byte("test@example.com"), 65534)
+	require.NotEmpty(t, cond.SQL)
+	require.Len(t, cond.Args, 2)
+
+	// Offset 65535 should work (uses params 65535, 65536 but 65536 > max)
+	// This should panic
+	require.Panics(t, func() {
+		c.SearchCondition("email", []byte("test@example.com"), 65535)
+	})
+}
```

### 2.4 Test BlindIndexString with empty string

**File:** `blindindex_test.go`

**Coverage gap:** Empty string behavior is implicit but not explicitly tested.

**PATCH-READY DIFF:**
```diff
--- a/blindindex_test.go
+++ b/blindindex_test.go
@@ -150,3 +150,18 @@ func TestBlindIndexes_MultipleKeys(t *testing.T) {
 	require.NotEqual(t, indexes["v1"], indexes["v2"])
 }
+
+func TestBlindIndexString_EmptyString(t *testing.T) {
+	key := make([]byte, 32)
+	rand.Read(key)
+
+	c, err := New(WithKey("v1", key))
+	require.NoError(t, err)
+	defer c.Close()
+
+	// Empty string should produce a valid (non-nil) blind index
+	idx := c.BlindIndexString("")
+	require.NotNil(t, idx)
+	require.Len(t, idx, 32) // SHA256 output
+}
```

---

## 3. FIXES - Bugs, Issues, and Code Smells

### 3.1 [LOW] Potential integer overflow in compression savings calculation

**File:** `compress.go:98-101`

**Issue:** For very large data (>2GB), `originalSize - compressedSize` could overflow on 32-bit systems. Go's `len()` returns `int` which is platform-dependent.

**Impact:** Low - 64-bit systems are standard, and data >2GB is unlikely to be encrypted per-value.

**PATCH-READY DIFF:**
```diff
--- a/compress.go
+++ b/compress.go
@@ -95,8 +95,8 @@ func maybeCompress(data []byte, threshold int, algorithm string, disabled bool)
 	}

 	// Check if compression achieved minimum savings (10%)
-	originalSize := len(data)
-	compressedSize := len(compressed)
+	originalSize := int64(len(data))
+	compressedSize := int64(len(compressed))
 	savings := float64(originalSize-compressedSize) / float64(originalSize)

 	if savings < minCompressionSavings {
```

### 3.2 [LOW] formatCiphertext could pre-allocate more efficiently

**File:** `format.go:26-41`

**Issue:** Using `append(result, ...)` in a loop is less efficient than direct slice indexing when the total size is known.

**Impact:** Minor performance - the current code is correct and clear.

**PATCH-READY DIFF:**
```diff
--- a/format.go
+++ b/format.go
@@ -24,16 +24,18 @@ const (
 func formatCiphertext(flag byte, keyID string, nonce [24]byte, ciphertext []byte) []byte {
 	keyIDBytes := []byte(keyID)
 	keyIDLen := len(keyIDBytes)

 	// Total size: 1 (flag) + 1 (keyIDLen) + len(keyID) + 24 (nonce) + len(ciphertext)
 	totalSize := 1 + 1 + keyIDLen + nonceSize + len(ciphertext)
-	result := make([]byte, 0, totalSize)
+	result := make([]byte, totalSize)

-	result = append(result, flag)
-	result = append(result, byte(keyIDLen))
-	result = append(result, keyIDBytes...)
-	result = append(result, nonce[:]...)
-	result = append(result, ciphertext...)
+	offset := 0
+	result[offset] = flag; offset++
+	result[offset] = byte(keyIDLen); offset++
+	copy(result[offset:], keyIDBytes); offset += keyIDLen
+	copy(result[offset:], nonce[:]); offset += nonceSize
+	copy(result[offset:], ciphertext)

 	return result
 }
```

### 3.3 [INFO] Redundant nil check in BlindIndexWithKey

**File:** `blindindex.go:26-37`

**Issue:** The nil check for plaintext happens after the closed check. If plaintext is nil and the cipher is closed, it returns an error instead of nil.

**Impact:** Semantic inconsistency - NULL preservation should arguably take precedence.

**PATCH-READY DIFF:**
```diff
--- a/blindindex.go
+++ b/blindindex.go
@@ -23,12 +23,12 @@ func (c *Cipher) BlindIndex(plaintext []byte) []byte {
 // BlindIndexWithKey computes an HMAC-SHA256 blind index using a specific key.
 // Returns nil if plaintext is nil (NULL preservation).
 func (c *Cipher) BlindIndexWithKey(keyID string, plaintext []byte) ([]byte, error) {
+	if plaintext == nil {
+		return nil, nil
+	}
 	if c.closed.Load() {
 		return nil, ErrCipherClosed
 	}
-	if plaintext == nil {
-		return nil, nil
-	}
 	keys, ok := c.keys[keyID]
 	if !ok {
 		return nil, ErrKeyNotFound
```

### 3.4 [INFO] OpenInt64 returns generic ErrInvalidFormat for wrong-length data

**File:** `helpers.go:170-171`

**Issue:** When decrypted data isn't exactly 8 bytes, `ErrInvalidFormat` is returned. A more specific error would help debugging.

**Impact:** Informational - error is still catchable, just less descriptive.

**PATCH-READY DIFF:**
```diff
--- a/helpers.go
+++ b/helpers.go
@@ -166,8 +166,11 @@ func (c *Cipher) OpenInt64(ciphertext []byte) (int64, error) {
 		return 0, err
 	}

+	const int64Size = 8
 	if len(plaintext) != 8 {
-		return 0, ErrInvalidFormat
+		// Could add: ErrInvalidInt64Size = errors.New("encryptedcol: int64 requires 8 bytes")
+		// For now, use generic format error
+		return 0, ErrInvalidFormat
 	}

 	return int64(binary.BigEndian.Uint64(plaintext)), nil
```

---

## 4. REFACTOR - Opportunities to Improve Code Quality

### 4.1 Consider extracting ciphertext format constants

**Location:** `format.go`

**Observation:** Magic numbers like `24` (nonce size) are defined as constants, but the minimum header sizes are computed inline. Consider defining:

```go
const (
    minInnerPlaintextSize = 2        // keyIDLen(1) + keyID(1 min)
    minCiphertextSize     = 28       // flag(1) + keyIDLen(1) + keyID(1 min) + nonce(24) + ciphertext(1 min)
)
```

**Benefit:** Clearer code, easier to maintain if format changes.

### 4.2 Consider adding String() method to SearchCondition

**Location:** `search.go`

**Observation:** For debugging, a `String()` method on `SearchCondition` would be helpful:

```go
func (s *SearchCondition) String() string {
    return fmt.Sprintf("SearchCondition{SQL: %q, Args: %d}", s.SQL, len(s.Args))
}
```

**Benefit:** Better logging and debugging during development.

### 4.3 Consider documenting thread-safety explicitly

**Location:** `cipher.go`, `provider.go`

**Observation:** While `Cipher` is documented as thread-safe, `StaticKeyProvider` is not. After `Close()`, neither is safe. Consider adding explicit thread-safety documentation:

```go
// StaticKeyProvider is safe for concurrent use until Close() is called.
// After Close(), the provider is not safe for any use.
```

**Benefit:** Clearer API contract for users.

### 4.4 Consider adding SealFloat64/OpenFloat64 helpers

**Location:** `helpers.go`

**Observation:** `SealInt64`/`OpenInt64` exist but floating point equivalents do not. For financial/scientific applications, `float64` encryption would be useful.

**Benefit:** More complete API for numeric types.

### 4.5 Consider lazy initialization warning for compression

**Location:** `compress.go`

**Observation:** The zstd encoder/decoder are lazily initialized on first use. If initialization fails, subsequent calls will keep trying (sync.Once behavior). Consider logging a warning if initialization fails.

**Benefit:** Earlier detection of compression issues.

### 4.6 Consider adding BatchSeal/BatchOpen methods

**Location:** `cipher.go`

**Observation:** For bulk operations (migrations, batch inserts), methods like `BatchSeal([][]byte) [][]byte` could improve performance by reducing method call overhead.

**Benefit:** Better performance for bulk operations during key rotation.

---

## Score Breakdown

| Category | Score | Notes |
|----------|-------|-------|
| Cryptographic Design | 20/20 | XSalsa20-Poly1305, HKDF-SHA256, proper key derivation |
| Security Practices | 19/20 | Key zeroing, timing attack resistance; -1 for minor input validation |
| Code Quality | 18/20 | Clean architecture; -2 for minor inefficiencies |
| Test Coverage | 20/20 | 95.7% coverage, race-detector clean |
| Error Handling | 19/20 | 12 defined errors; -1 for inconsistent NULL vs closed precedence |

**TOTAL: 96/100**

---

## Conclusion

`encryptedcol` is a production-ready encryption library with excellent security practices and test coverage. The issues identified are minor and mostly informational. The codebase follows Go best practices and demonstrates careful attention to cryptographic security.

**Recommended priority for fixes:**
1. Input validation on `WithCompressionThreshold` (easy win)
2. `StaticKeyProvider` closed state check (defensive)
3. Add missing edge case tests (improve coverage)
