Date Created: 2026-01-20 17:41:00 PST
TOTAL_SCORE: 87/100

# encryptedcol Code Analysis Report

## Executive Summary

**encryptedcol** is a well-engineered Go library for client-side encrypted database columns with blind indexing. The codebase demonstrates strong cryptographic fundamentals, excellent test coverage (95.2%), and thoughtful API design. Deductions are primarily for error handling patterns (panics in public API) and minor edge cases.

| Category | Score | Notes |
|----------|-------|-------|
| Cryptography | 95/100 | Excellent primitive choices (XSalsa20-Poly1305, HKDF-SHA256) |
| Error Handling | 75/100 | Panics in public API should be errors |
| Test Coverage | 98/100 | 95.2% statements, 277 tests, passes race detection |
| Code Quality | 85/100 | Well-written with minor compression pattern issue |
| Security | 88/100 | Strong overall, some panic/validation concerns |
| Documentation | 82/100 | Good, but security limitations could be clearer |
| API Design | 90/100 | Well-designed functional options, minor type-safety gaps |

---

## 1. AUDIT - Security and Code Quality Issues

### AUDIT-1: Panic on User-Provided Input in SearchCondition (MEDIUM)

**File:** `search.go:54-59`

**Issue:** The `SearchCondition` method panics on invalid column names or parameter offsets. While panics are appropriate for unrecoverable crypto errors (like `crypto/rand` failure), panicking on user-controllable input breaks error handling contracts. If an application passes user-provided or dynamically-generated column names without prior validation, this creates a denial-of-service vector.

**Current Code:**
```go
func (c *Cipher) SearchCondition(column string, plaintext []byte, paramOffset int) *SearchCondition {
    if !isValidColumnName(column) {
        panic("encryptedcol: invalid column name (must start with letter/underscore, contain only alphanumeric/underscore): " + column)
    }

    if paramOffset < 1 {
        panic("encryptedcol: invalid paramOffset (must be >= 1)")
    }
```

**PATCH-READY DIFF:**
```diff
--- a/search.go
+++ b/search.go
@@ -31,14 +31,14 @@ type SearchCondition struct {
 	Args []interface{} // Interleaved key_ids and blind indexes
 }

-// SearchCondition generates a SQL WHERE clause for blind index search
+// SearchCondition generates a SQL WHERE clause for blind index search.
+// Returns error if column name is invalid or paramOffset < 1.
 // across all active key versions.
 //
 // The generated SQL uses OR conditions for each key version:
 //
 //	(key_id = $1 AND {column}_idx = $2) OR (key_id = $3 AND {column}_idx = $4)
-//
-// paramOffset specifies the starting parameter number ($1, $2, etc.).
+// paramOffset specifies the starting parameter number ($1, $2, etc.) and must be >= 1.
 // Use this when composing with other WHERE conditions.
 //
 // Example:
@@ -46,15 +46,16 @@ type SearchCondition struct {
 //	cond := cipher.SearchCondition("email", []byte("alice@example.com"), 1)
 //	query := fmt.Sprintf("SELECT * FROM users WHERE %s", cond.SQL)
 //	rows, _ := db.Query(query, cond.Args...)
-func (c *Cipher) SearchCondition(column string, plaintext []byte, paramOffset int) *SearchCondition {
+func (c *Cipher) SearchCondition(column string, plaintext []byte, paramOffset int) (*SearchCondition, error) {
 	if !isValidColumnName(column) {
-		panic("encryptedcol: invalid column name (must start with letter/underscore, contain only alphanumeric/underscore): " + column)
+		return nil, fmt.Errorf("encryptedcol: invalid column name %q (must start with letter/underscore, contain only alphanumeric/underscore)", column)
 	}

 	if paramOffset < 1 {
-		panic("encryptedcol: invalid paramOffset (must be >= 1)")
+		return nil, fmt.Errorf("encryptedcol: invalid paramOffset %d (must be >= 1)", paramOffset)
 	}

 	if plaintext == nil {
 		return &SearchCondition{
 			SQL:  "FALSE", // NULL values can't match
 			Args: nil,
-		}
+		}, nil
 	}

 	ids := c.ActiveKeyIDs()
@@ -72,18 +73,18 @@ func (c *Cipher) SearchCondition(column string, plaintext []byte, paramOffset in
 	for _, keyID := range ids {
 		idxHash, err := c.BlindIndexWithKey(keyID, plaintext)
 		if err != nil {
-			// This should never happen since keyID comes from ActiveKeyIDs()
-			panic("encryptedcol: internal error: " + err.Error())
+			return nil, fmt.Errorf("encryptedcol: internal error computing blind index: %w", err)
 		}

 		part := fmt.Sprintf("(key_id = $%d AND %s_idx = $%d)", paramOffset, column, paramOffset+1)
 		parts = append(parts, part)
 		args = append(args, keyID, idxHash)
 		paramOffset += 2
 	}

 	return &SearchCondition{
 		SQL:  strings.Join(parts, " OR "),
 		Args: args,
-	}
+	}, nil
 }
```

**Note:** This change would require updating `SearchConditionString`, `SearchConditionStringNormalized`, and `SearchConditionNormalized` to also return errors, plus all callers. This is a breaking API change.

---

### AUDIT-2: Use-After-Close Not Guarded (MEDIUM)

**File:** `cipher.go:260-270`

**Issue:** After calling `Close()`, the `c.keys` map is set to nil. Subsequent calls to `Seal()` or `Open()` will cause a nil pointer dereference panic when accessing `c.keys[keyID]`. A more graceful failure (either a specific error or a clear panic message) would improve debuggability.

**Current Code:**
```go
func (c *Cipher) Close() {
    for _, dk := range c.keys {
        for i := range dk.encryption {
            dk.encryption[i] = 0
        }
        for i := range dk.hmac {
            dk.hmac[i] = 0
        }
    }
    c.keys = nil
}
```

**PATCH-READY DIFF:**
```diff
--- a/cipher.go
+++ b/cipher.go
@@ -119,6 +119,9 @@ func New(opts ...Option) (*Cipher, error) {
 // [flag:1][keyIDLen:1][keyID:n][nonce:24][secretbox(innerKeyID + plaintext)]
 func (c *Cipher) Seal(plaintext []byte) []byte {
+	if c.keys == nil {
+		panic("encryptedcol: Cipher.Seal called after Close()")
+	}
 	if plaintext == nil {
 		return nil // NULL preservation
 	}
@@ -193,6 +196,9 @@ func (c *Cipher) decryptAndVerify(keys *derivedKeys, encrypted []byte, nonce *[2
 // Open decrypts ciphertext, auto-detecting the key from embedded key_id.
 // Returns nil, nil if ciphertext is nil (NULL preservation).
 func (c *Cipher) Open(ciphertext []byte) ([]byte, error) {
+	if c.keys == nil {
+		return nil, ErrCipherClosed
+	}
 	if ciphertext == nil {
 		return nil, nil // NULL preservation
 	}
```

Also add to `errors.go`:
```diff
--- a/errors.go
+++ b/errors.go
@@ -15,6 +15,9 @@ var (

 	// ErrWasNull indicates the ciphertext was nil (representing SQL NULL).
 	ErrWasNull = errors.New("encryptedcol: value was NULL")
+
+	// ErrCipherClosed indicates the Cipher was used after Close() was called.
+	ErrCipherClosed = errors.New("encryptedcol: cipher already closed")
 )
```

---

### AUDIT-3: Compression Initialization Race Condition Edge Case (LOW)

**File:** `compress.go:29-39`

**Issue:** If `zstd.NewWriter` succeeds but `zstd.NewReader` fails, `zstdEncoder` is non-nil while `zstdErr` is set. Subsequent calls via `compressZstd()` will succeed (returning the encoder), but `decompressZstd()` will return the error. The state is inconsistent. In practice, `zstd.NewReader(nil)` is unlikely to fail, but this is poor defensive programming.

**Current Code:**
```go
func initZstd() (*zstd.Encoder, *zstd.Decoder, error) {
    zstdOnce.Do(func() {
        zstdEncoder, zstdErr = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
        if zstdErr != nil {
            return
        }
        zstdDecoder, zstdErr = zstd.NewReader(nil)
    })
    return zstdEncoder, zstdDecoder, zstdErr
}
```

**PATCH-READY DIFF:**
```diff
--- a/compress.go
+++ b/compress.go
@@ -28,13 +28,21 @@ var (

 // initZstd initializes the zstd encoder and decoder once.
 func initZstd() (*zstd.Encoder, *zstd.Decoder, error) {
 	zstdOnce.Do(func() {
-		zstdEncoder, zstdErr = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
-		if zstdErr != nil {
+		enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
+		if err != nil {
+			zstdErr = err
 			return
 		}
-		zstdDecoder, zstdErr = zstd.NewReader(nil)
+		dec, err := zstd.NewReader(nil)
+		if err != nil {
+			zstdErr = err
+			return
+		}
+		// Only assign if both succeeded
+		zstdEncoder = enc
+		zstdDecoder = dec
 	})
 	return zstdEncoder, zstdDecoder, zstdErr
 }
```

---

## 2. TESTS - Proposed Unit Tests for Untested Code

### TEST-1: Close() and Subsequent Operations

**File:** New test in `cipher_test.go`

**Gap:** Tests verify `Close()` works but don't verify behavior of operations after `Close()`.

**PATCH-READY DIFF:**
```diff
--- a/cipher_test.go
+++ b/cipher_test.go
@@ -xxx,6 +xxx,36 @@ func TestClose(t *testing.T) {
 	// existing test...
 }

+func TestClosePreventsFurtherOperations(t *testing.T) {
+	key := make([]byte, 32)
+	rand.Read(key)
+
+	cipher, err := New(WithKey("v1", key))
+	require.NoError(t, err)
+
+	// Seal works before Close
+	ciphertext := cipher.Seal([]byte("test"))
+	require.NotNil(t, ciphertext)
+
+	cipher.Close()
+
+	// After Close, Seal should panic with clear message (or return error if API changed)
+	require.Panics(t, func() {
+		cipher.Seal([]byte("test"))
+	}, "Seal after Close should panic")
+
+	// After Close, Open should return error (or panic with clear message)
+	// Depending on chosen approach from AUDIT-2
+}
+
+func TestConcurrentClose(t *testing.T) {
+	key := make([]byte, 32)
+	rand.Read(key)
+
+	cipher, err := New(WithKey("v1", key))
+	require.NoError(t, err)
+
+	var wg sync.WaitGroup
+	for i := 0; i < 10; i++ {
+		wg.Add(1)
+		go func() {
+			defer wg.Done()
+			cipher.Close() // Should not panic even with concurrent calls
+		}()
+	}
+	wg.Wait()
+}
```

---

### TEST-2: Corrupted Zstd Data Decompression

**File:** New test in `compress_test.go`

**Gap:** No test for decompressing data marked as zstd but containing invalid/corrupted zstd data.

**PATCH-READY DIFF:**
```diff
--- a/compress_test.go
+++ b/compress_test.go
@@ -xxx,6 +xxx,28 @@ func TestDecompress(t *testing.T) {
 	// existing tests...
 }

+func TestDecompressCorruptedZstdData(t *testing.T) {
+	// Data marked as zstd-compressed but contains garbage
+	corruptedData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
+
+	result, err := decompress(corruptedData, flagZstd)
+	require.Error(t, err)
+	require.Nil(t, result)
+	require.ErrorIs(t, err, ErrDecompressionFailed)
+}
+
+func TestDecompressTruncatedZstdData(t *testing.T) {
+	// First compress valid data, then truncate it
+	original := bytes.Repeat([]byte("test data for compression"), 100)
+	compressed, err := compressZstd(original)
+	require.NoError(t, err)
+
+	// Truncate to half
+	truncated := compressed[:len(compressed)/2]
+
+	result, err := decompress(truncated, flagZstd)
+	require.Error(t, err)
+	require.ErrorIs(t, err, ErrDecompressionFailed)
+}
```

---

### TEST-3: SearchCondition Edge Cases

**File:** New tests in `search_test.go`

**Gap:** Panic paths and edge cases need more coverage.

**PATCH-READY DIFF:**
```diff
--- a/search_test.go
+++ b/search_test.go
@@ -xxx,6 +xxx,58 @@ func TestSearchCondition(t *testing.T) {
 	// existing tests...
 }

+func TestSearchConditionInvalidColumnName(t *testing.T) {
+	key := make([]byte, 32)
+	rand.Read(key)
+	cipher, _ := New(WithKey("v1", key))
+
+	tests := []struct {
+		name   string
+		column string
+	}{
+		{"empty", ""},
+		{"starts with number", "1column"},
+		{"contains space", "my column"},
+		{"contains hyphen", "my-column"},
+		{"contains semicolon", "column;DROP TABLE"},
+		{"SQL injection attempt", "email OR 1=1--"},
+	}
+
+	for _, tt := range tests {
+		t.Run(tt.name, func(t *testing.T) {
+			// Current behavior: panics
+			// After AUDIT-1 fix: should return error
+			require.Panics(t, func() {
+				cipher.SearchCondition(tt.column, []byte("test"), 1)
+			})
+		})
+	}
+}
+
+func TestSearchConditionInvalidParamOffset(t *testing.T) {
+	key := make([]byte, 32)
+	rand.Read(key)
+	cipher, _ := New(WithKey("v1", key))
+
+	tests := []struct {
+		name   string
+		offset int
+	}{
+		{"zero", 0},
+		{"negative", -1},
+		{"very negative", -100},
+	}
+
+	for _, tt := range tests {
+		t.Run(tt.name, func(t *testing.T) {
+			require.Panics(t, func() {
+				cipher.SearchCondition("email", []byte("test"), tt.offset)
+			})
+		})
+	}
+}
+
+func TestSearchConditionMaxKeyIDLength(t *testing.T) {
+	// Test with maximum allowed key ID length (255 bytes)
+	key := make([]byte, 32)
+	rand.Read(key)
+	longKeyID := strings.Repeat("a", 255)
+
+	cipher, err := New(WithKey(longKeyID, key))
+	require.NoError(t, err)
+
+	cond := cipher.SearchCondition("email", []byte("test@example.com"), 1)
+	require.NotNil(t, cond)
+	require.Contains(t, cond.SQL, longKeyID)
+}
```

---

### TEST-4: KeyProvider Integration Failure

**File:** New test in `provider_test.go`

**Gap:** Test behavior when KeyProvider returns nil or unexpected values.

**PATCH-READY DIFF:**
```diff
--- a/provider_test.go
+++ b/provider_test.go
@@ -xxx,6 +xxx,30 @@ func TestStaticKeyProvider(t *testing.T) {
 	// existing tests...
 }

+type nilReturningProvider struct{}
+
+func (p *nilReturningProvider) GetKey(keyID string) ([]byte, error) {
+	return nil, nil // Returns nil key without error
+}
+
+func (p *nilReturningProvider) DefaultKeyID() string {
+	return "v1"
+}
+
+func (p *nilReturningProvider) ActiveKeyIDs() []string {
+	return []string{"v1"}
+}
+
+func TestProviderReturningNilKey(t *testing.T) {
+	provider := &nilReturningProvider{}
+
+	// This tests how the library handles a misbehaving provider
+	// that returns nil without an error
+	_, err := NewFromProvider(provider)
+	// Should return an error indicating the key is invalid
+	require.Error(t, err)
+}
```

---

## 3. FIXES - Bugs, Issues, and Code Smells

### FIX-1: SealInt64 Cannot Represent NULL

**File:** `helpers.go:159-182`

**Issue:** `SealInt64` always returns a non-nil ciphertext (even for value 0), and `OpenInt64` returns `ErrWasNull` only for nil ciphertext. This means applications storing nullable int64 fields cannot distinguish between "NULL" and "0". Other helpers (`SealStringPtr`) handle this correctly.

**Current Code:**
```go
func (c *Cipher) SealInt64(n int64) []byte {
    buf := make([]byte, 8)
    binary.BigEndian.PutUint64(buf, uint64(n))
    return c.Seal(buf)
}

func (c *Cipher) OpenInt64(ciphertext []byte) (int64, error) {
    if ciphertext == nil {
        return 0, ErrWasNull
    }
    // ...
}
```

**PATCH-READY DIFF:**
```diff
--- a/helpers.go
+++ b/helpers.go
@@ -157,6 +157,22 @@ func SealJSONIndexed[T any](c *Cipher, data T) (*SealedValue, error) {
 	}, nil
 }

+// SealInt64Ptr encrypts an int64 pointer.
+// Returns nil if n is nil (NULL preservation).
+func (c *Cipher) SealInt64Ptr(n *int64) []byte {
+	if n == nil {
+		return nil
+	}
+	return c.SealInt64(*n)
+}
+
+// OpenInt64Ptr decrypts to an int64 pointer.
+// Returns nil if ciphertext is nil (NULL preservation).
+func (c *Cipher) OpenInt64Ptr(ciphertext []byte) (*int64, error) {
+	if ciphertext == nil {
+		return nil, nil
+	}
+	n, err := c.OpenInt64(ciphertext)
+	if err != nil {
+		return nil, err
+	}
+	return &n, nil
+}
+
 // SealInt64 encrypts an int64 value.
 func (c *Cipher) SealInt64(n int64) []byte {
```

---

### FIX-2: Silent Compression Failure Masking

**File:** `compress.go:77-80`

**Issue:** If compression fails, `maybeCompress` silently falls back to uncompressed data without any indication. This could mask environmental issues (corrupted zstd library, memory pressure) and cause unexpected behavior where large payloads are stored uncompressed.

**Current Code:**
```go
compressed, err := compressZstd(data)
if err != nil {
    // If compression fails, return uncompressed
    return data, flagNoCompression
}
```

**PATCH-READY DIFF:**
```diff
--- a/compress.go
+++ b/compress.go
@@ -63,6 +63,12 @@ func decompressZstd(data []byte) ([]byte, error) {
 	return result, nil
 }

+// CompressionErrorHandler is called when compression fails.
+// The default behavior is to silently fall back to uncompressed.
+// Applications can override this for logging or monitoring.
+var CompressionErrorHandler func(err error) = nil
+
 // maybeCompress compresses data if it exceeds the threshold and compression is beneficial.
 // Returns the (possibly compressed) data and the flag byte indicating compression status.
 func maybeCompress(data []byte, threshold int, algorithm string, disabled bool) ([]byte, byte) {
@@ -75,7 +81,10 @@ func maybeCompress(data []byte, threshold int, algorithm string, disabled bool)

 	compressed, err := compressZstd(data)
 	if err != nil {
-		// If compression fails, return uncompressed
+		// If compression fails, notify handler and return uncompressed
+		if CompressionErrorHandler != nil {
+			CompressionErrorHandler(err)
+		}
 		return data, flagNoCompression
 	}
```

---

### FIX-3: Unused Snappy Constant

**File:** `compress.go:18-19`

**Issue:** `compressionAlgorithmSnappy` is defined and `flagSnappy` is handled in `decompress()`, but snappy compression is never implemented. This is dead code that creates confusion.

**Current Code:**
```go
const (
    compressionAlgorithmZstd   = "zstd"
    compressionAlgorithmSnappy = "snappy"  // Never used
)
```

**PATCH-READY DIFF (Option A: Remove):**
```diff
--- a/compress.go
+++ b/compress.go
@@ -15,8 +15,7 @@ const (

 // Compression algorithm identifiers
 const (
 	compressionAlgorithmZstd   = "zstd"
-	compressionAlgorithmSnappy = "snappy"
+	// NOTE: snappy reserved (flagSnappy = 0x02) but not implemented
 )
```

---

## 4. REFACTOR - Opportunities to Improve Code Quality

### REFACTOR-1: Type-Safe Normalizer Binding (HIGH VALUE)

**Problem:** The current design relies solely on documentation to ensure the same normalizer is used for both writing and searching. This is error-prone.

**Suggestion:** Create a wrapper type that binds a normalizer to field operations:

```go
// SearchableField provides type-safe searchable encryption with a bound normalizer.
type SearchableField struct {
    cipher     *Cipher
    normalizer Normalizer
    column     string
}

func NewSearchableField(cipher *Cipher, column string, norm Normalizer) *SearchableField {
    return &SearchableField{cipher: cipher, normalizer: norm, column: column}
}

func (f *SearchableField) Seal(value string) *SealedValue {
    return f.cipher.SealStringIndexedNormalized(value, f.normalizer)
}

func (f *SearchableField) SearchCondition(value string, paramOffset int) *SearchCondition {
    return f.cipher.SearchConditionStringNormalized(f.column, value, paramOffset, f.normalizer)
}
```

**Benefits:**
- Impossible to use wrong normalizer at search time
- Column name validated once at construction
- More ergonomic API for common use case

---

### REFACTOR-2: Error Wrapping Consistency (MEDIUM)

**Problem:** Some errors are wrapped with context, others return raw sentinel errors. Inconsistent.

**Suggestion:** Standardize on wrapped errors with context:

```go
// Instead of:
return nil, ErrKeyNotFound

// Use:
return nil, fmt.Errorf("key %q: %w", keyID, ErrKeyNotFound)
```

---

### REFACTOR-3: Pool-Based Nonce Generation (LOW VALUE)

**Problem:** `generateNonce()` allocates a new `[24]byte` array on every call.

**Suggestion:** Use `sync.Pool` for nonce arrays in high-throughput scenarios:

```go
var noncePool = sync.Pool{
    New: func() interface{} {
        return new([24]byte)
    },
}

func generateNonce() [24]byte {
    nonce := noncePool.Get().(*[24]byte)
    if _, err := rand.Read(nonce[:]); err != nil {
        panic("crypto/rand failed: " + err.Error())
    }
    result := *nonce
    noncePool.Put(nonce)
    return result
}
```

**Note:** Micro-optimization; only valuable at very high throughput. Benchmark before implementing.

---

### REFACTOR-4: Extract Format Constants (LOW VALUE)

**Problem:** Magic numbers for format offsets are scattered through `format.go`.

**Suggestion:** Define named constants:

```go
const (
    offsetFlag       = 0
    offsetKeyIDLen   = 1
    offsetKeyIDStart = 2
    nonceSize        = 24
    minCiphertextLen = 1 + 1 + 1 + nonceSize + secretbox.Overhead + 1 // flag + keyIDLen + keyID(1) + nonce + overhead + innerKeyID(1)
)
```

---

### REFACTOR-5: Consolidate SearchCondition Methods (MEDIUM)

**Problem:** There are 4 `SearchCondition*` methods with similar logic and nearly identical documentation.

**Suggestion:** Consolidate into 2 methods using optional functional parameters or a builder pattern:

```go
// Instead of 4 methods:
// - SearchCondition
// - SearchConditionString
// - SearchConditionNormalized
// - SearchConditionStringNormalized

// Use 2 methods with options:
func (c *Cipher) SearchCondition(column string, plaintext []byte, paramOffset int, opts ...SearchOption) (*SearchCondition, error)
func (c *Cipher) SearchConditionString(column string, plaintext string, paramOffset int, opts ...SearchOption) (*SearchCondition, error)

// With option:
func WithNormalizer(norm Normalizer) SearchOption
```

---

## Appendix: Files Reviewed

- `cipher.go` - Core encryption/decryption
- `compress.go` - Zstd compression
- `search.go` - SQL search condition builder
- `helpers.go` - Type-safe convenience methods
- `format.go` - Ciphertext format encoding
- `kdf.go` - Key derivation
- `blindindex.go` - HMAC blind indexing
- `normalize.go` - Input normalizers
- `options.go` - Functional options
- `provider.go` - KeyProvider interface
- `errors.go` - Error definitions
- `rotate.go` - Key rotation helpers
- All corresponding `*_test.go` files

---

## Recommendations Priority

| Priority | Item | Impact |
|----------|------|--------|
| 1 | AUDIT-1: Replace panics with errors | Breaking API, but critical for production use |
| 2 | AUDIT-2: Guard use-after-Close | Prevents confusing crashes |
| 3 | FIX-1: Add SealInt64Ptr/OpenInt64Ptr | Enables nullable int64 fields |
| 4 | TEST-1: Close() behavior tests | Prevents regression |
| 5 | REFACTOR-1: Type-safe normalizer binding | Prevents common misuse |
| 6 | AUDIT-3: Fix initZstd race edge case | Defensive improvement |
| 7 | TEST-2-4: Additional edge case tests | Improves coverage |
| 8 | FIX-2: Compression error handler | Observability improvement |
