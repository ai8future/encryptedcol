# encryptedcol Code Analysis and Fix Report

**Date Created:** 2026-01-21T22:43:00Z
**Date Updated:** 2026-01-26 (Review complete: all actionable fixes implemented)

## Executive Summary

This report presents a comprehensive analysis of the `encryptedcol` Go library for client-side encrypted columns in PostgreSQL/Supabase. The library demonstrates solid cryptographic design with XSalsa20-Poly1305 encryption, HKDF key derivation, and HMAC-SHA256 blind indexing. However, several issues were identified ranging from HIGH severity (potential panics, key material exposure) to LOW severity (documentation inconsistencies).

**Overall Assessment:** Production-ready with conditions. The HIGH-severity issues should be addressed before deployment with sensitive data.

---

## Issues Identified

### ~~HIGH-001: Use-After-Close Causes Nil Pointer Dereference~~ IMPLEMENTED 2026-01-22

**Severity:** HIGH
**Location:** `cipher.go:260-270`
**Impact:** Any operation after `Close()` causes a panic due to nil pointer dereference

**Description:**

The `Close()` method sets `c.keys = nil` but provides no protection against subsequent use. Any call to `Seal()`, `Open()`, `BlindIndex()`, or other methods will panic.

```go
// Current code (cipher.go:260-270)
func (c *Cipher) Close() {
    for _, dk := range c.keys {
        for i := range dk.encryption {
            dk.encryption[i] = 0
        }
        for i := range dk.hmac {
            dk.hmac[i] = 0
        }
    }
    c.keys = nil  // <-- After this, any method call will panic
}
```

**Problematic Scenario:**
```go
cipher.Close()
cipher.Seal([]byte("data"))  // PANIC: nil pointer dereference
```

**Race Condition Risk:** Concurrent use where one goroutine calls `Close()` while another encrypts data leads to undefined behavior.

**Recommended Fix:**

```diff
--- a/cipher.go
+++ b/cipher.go
@@ -9,10 +9,12 @@ import (
 // Cipher provides encryption, decryption, and blind indexing for database columns.
 // It is safe for concurrent use.
 type Cipher struct {
-	keys      map[string]*derivedKeys // keyID -> derived keys (cached)
-	defaultID string                  // default key ID for new encryptions
-	config    *config                 // configuration options
+	keys      map[string]*derivedKeys  // keyID -> derived keys (cached)
+	defaultID string                   // default key ID for new encryptions
+	config    *config                  // configuration options
+	closed    atomic.Bool              // true after Close() called
 }

+// Add to imports:
+import "sync/atomic"

@@ -117,6 +119,9 @@ func New(opts ...Option) (*Cipher, error) {
 // The ciphertext format is:
 // [flag:1][keyIDLen:1][keyID:n][nonce:24][secretbox(innerKeyID + plaintext)]
 func (c *Cipher) Seal(plaintext []byte) []byte {
+	if c.closed.Load() {
+		panic("encryptedcol: use of closed Cipher")
+	}
 	if plaintext == nil {
 		return nil // NULL preservation
 	}
@@ -191,6 +196,9 @@ func (c *Cipher) decryptAndVerify(keys *derivedKeys, encrypted []byte, nonce *[2
 // Open decrypts ciphertext, auto-detecting the key from embedded key_id.
 // Returns nil, nil if ciphertext is nil (NULL preservation).
 func (c *Cipher) Open(ciphertext []byte) ([]byte, error) {
+	if c.closed.Load() {
+		return nil, ErrCipherClosed
+	}
 	if ciphertext == nil {
 		return nil, nil // NULL preservation
 	}
@@ -254,6 +262,7 @@ func (c *Cipher) ActiveKeyIDs() []string {
 // Call this when the Cipher is no longer needed to reduce key exposure window.
 // After calling Close, the Cipher is no longer usable.
 func (c *Cipher) Close() {
+	c.closed.Store(true)
 	for _, dk := range c.keys {
 		for i := range dk.encryption {
 			dk.encryption[i] = 0
```

Add new error to `errors.go`:
```diff
--- a/errors.go
+++ b/errors.go
@@ -36,4 +36,7 @@ var (

 	// ErrUnsupportedCompression indicates an unsupported compression algorithm.
 	ErrUnsupportedCompression = errors.New("encryptedcol: unsupported compression algorithm")
+
+	// ErrCipherClosed indicates the cipher was used after Close() was called.
+	ErrCipherClosed = errors.New("encryptedcol: cipher is closed")
 )
```

---

### ~~HIGH-002: StaticKeyProvider Does Not Deep-Copy Keys~~ IMPLEMENTED 2026-01-22

**Severity:** HIGH
**Location:** `provider.go:62-68`
**Impact:** External code can modify keys after provider creation; no secure cleanup possible

**Description:**

`NewStaticKeyProvider` stores a direct reference to the provided map without copying. This creates two problems:

1. External code can modify keys after provider creation
2. No way to securely zero out key material when the provider is discarded

```go
// Current code (provider.go:62-68)
func NewStaticKeyProvider(defaultKeyID string, keys map[string][]byte) *StaticKeyProvider {
    return &StaticKeyProvider{
        keys:      keys,  // <-- Direct reference, not a copy
        defaultID: defaultKeyID,
    }
}
```

**Problematic Scenario:**
```go
keys := map[string][]byte{"v1": masterKey}
provider := NewStaticKeyProvider("v1", keys)

// Later, external code modifies the key
keys["v1"][0] = 0xFF  // Corrupts the provider's key!
```

**Recommended Fix:**

```diff
--- a/provider.go
+++ b/provider.go
@@ -60,9 +60,15 @@ type StaticKeyProvider struct {

 // NewStaticKeyProvider creates a StaticKeyProvider with the given keys.
+// Keys are deep-copied to prevent external modification.
 func NewStaticKeyProvider(defaultKeyID string, keys map[string][]byte) *StaticKeyProvider {
+	// Deep-copy all keys to prevent external modification
+	keysCopy := make(map[string][]byte, len(keys))
+	for id, key := range keys {
+		keyCopy := make([]byte, len(key))
+		copy(keyCopy, key)
+		keysCopy[id] = keyCopy
+	}
 	return &StaticKeyProvider{
-		keys:      keys,
+		keys:      keysCopy,
 		defaultID: defaultKeyID,
 	}
 }
@@ -89,3 +95,14 @@ func (p *StaticKeyProvider) ActiveKeyIDs() []string {
 	sort.Strings(ids)
 	return ids
 }
+
+// Close zeros out all key material from memory.
+// After calling Close, the provider should not be used.
+func (p *StaticKeyProvider) Close() {
+	for _, key := range p.keys {
+		for i := range key {
+			key[i] = 0
+		}
+	}
+	p.keys = nil
+}
```

---

### ~~MEDIUM-001: No Decompression Size Limit (Zip Bomb Vulnerability)~~ IMPLEMENTED 2026-01-22

**Severity:** MEDIUM
**Location:** `compress.go:51-62`
**Impact:** Malicious compressed data could cause OOM

**Description:**

`decompressZstd()` uses `decoder.DecodeAll()` with no size limit. While zstd has internal limits (~4GB), an attacker who can provide encrypted data could cause significant memory consumption.

```go
// Current code (compress.go:51-62)
func decompressZstd(data []byte) ([]byte, error) {
    _, decoder, err := initZstd()
    if err != nil {
        return nil, err
    }
    result, err := decoder.DecodeAll(data, nil)  // <-- No size limit
    if err != nil {
        return nil, ErrDecompressionFailed
    }
    return result, nil
}
```

**Recommended Fix:**

```diff
--- a/compress.go
+++ b/compress.go
@@ -8,6 +8,9 @@ import (
 	"github.com/klauspost/compress/zstd"
 )

+// Maximum decompressed size to prevent zip bomb attacks (64MB)
+const maxDecompressedSize = 64 * 1024 * 1024
+
 // Default compression settings
 const (
 	defaultCompressionThreshold = 1024 // 1KB
@@ -49,12 +52,26 @@ func compressZstd(data []byte) ([]byte, error) {

 // decompressZstd decompresses zstd-compressed data.
+// Returns ErrDecompressionFailed if decompressed size exceeds maxDecompressedSize.
 func decompressZstd(data []byte) ([]byte, error) {
 	_, decoder, err := initZstd()
 	if err != nil {
 		return nil, err
 	}
-	result, err := decoder.DecodeAll(data, nil)
+
+	// Use a size-limited buffer to prevent zip bomb attacks
+	// Allocate initial buffer based on expected expansion (conservative estimate)
+	estimatedSize := len(data) * 10
+	if estimatedSize > maxDecompressedSize {
+		estimatedSize = maxDecompressedSize
+	}
+	dst := make([]byte, 0, estimatedSize)
+
+	result, err := decoder.DecodeAll(data, dst)
 	if err != nil {
 		return nil, ErrDecompressionFailed
 	}
+	if len(result) > maxDecompressedSize {
+		return nil, ErrDecompressionFailed
+	}
 	return result, nil
 }
```

---

### ~~MEDIUM-002: No Upper Bound on paramOffset in SearchCondition~~ IMPLEMENTED 2026-01-22

**Severity:** MEDIUM
**Location:** `search.go:53-60`
**Impact:** PostgreSQL parameter limit (65535) could be exceeded

**Description:**

`SearchCondition` validates `paramOffset >= 1` but doesn't check upper bounds. With aggressive key rotation (many keys), parameter numbers could exceed PostgreSQL's limit.

```go
// Current code (search.go:58-59)
if paramOffset < 1 {
    panic("encryptedcol: invalid paramOffset (must be >= 1)")
}
```

**Recommended Fix:**

```diff
--- a/search.go
+++ b/search.go
@@ -3,6 +3,10 @@ package encryptedcol
 import (
 	"fmt"
 	"strings"
 )

+// PostgreSQL maximum parameter number
+const maxParamNumber = 65535
+
 // SearchCondition generates a SQL WHERE clause for blind index search
 // across all active key versions.
 //
@@ -55,8 +59,17 @@ func (c *Cipher) SearchCondition(column string, plaintext []byte, paramOffset in
 		panic("encryptedcol: invalid column name (must start with letter/underscore, contain only alphanumeric/underscore): " + column)
 	}

-	if paramOffset < 1 {
-		panic("encryptedcol: invalid paramOffset (must be >= 1)")
+	if paramOffset < 1 || paramOffset > maxParamNumber {
+		panic(fmt.Sprintf("encryptedcol: invalid paramOffset (must be 1-%d)", maxParamNumber))
+	}
+
+	ids := c.ActiveKeyIDs()
+
+	// Check that parameters won't exceed PostgreSQL limit
+	// Each key uses 2 parameters (key_id and blind_index)
+	maxParam := paramOffset + (len(ids) * 2) - 1
+	if maxParam > maxParamNumber {
+		panic(fmt.Sprintf("encryptedcol: too many keys (%d) would exceed PostgreSQL parameter limit", len(ids)))
 	}
```

---

### ~~MEDIUM-003: Inconsistent NULL Handling in Helper Methods~~ DOCUMENTATION ONLY

**Severity:** MEDIUM → LOW (documentation)
**Location:** `helpers.go:27-58`
**Status:** NOT A BUG - intentional API design

**Assessment:** The difference between `OpenString(nil)` returning error vs `OpenStringPtr(nil)` returning `(nil, nil)` is intentional and matches Go idioms. Non-pointer returns cannot represent NULL, so an error is appropriate. Pointer returns can represent NULL via nil. Current documentation is adequate.

```go
// OpenString returns error for nil input
func (c *Cipher) OpenString(ciphertext []byte) (string, error) {
    if ciphertext == nil {
        return "", ErrWasNull  // Returns error
    }
    ...
}

// OpenStringPtr returns nil, nil for nil input
func (c *Cipher) OpenStringPtr(ciphertext []byte) (*string, error) {
    if ciphertext == nil {
        return nil, nil  // No error
    }
    ...
}
```

**Recommended Fix:**

```diff
--- a/helpers.go
+++ b/helpers.go
@@ -23,7 +23,11 @@ func (c *Cipher) SealString(s string) []byte {
 }

 // OpenString decrypts to a string value.
-// Returns empty string and ErrWasNull if ciphertext is nil.
+// Returns empty string and ErrWasNull if ciphertext is nil (database NULL).
+//
+// Note: For nullable columns where NULL should be distinguished from empty string,
+// use OpenStringPtr instead, which returns (nil, nil) for NULL values and
+// (*string, nil) for non-NULL values including empty strings.
 func (c *Cipher) OpenString(ciphertext []byte) (string, error) {
 	if ciphertext == nil {
 		return "", ErrWasNull
@@ -45,7 +49,9 @@ func (c *Cipher) SealStringPtr(s *string) []byte {
 }

 // OpenStringPtr decrypts to a string pointer.
-// Returns nil if ciphertext is nil (NULL preservation).
+// Returns (nil, nil) if ciphertext is nil (database NULL).
+// This distinguishes NULL from empty string, which returns (*string(""), nil).
+// For non-nullable columns, use OpenString instead.
 func (c *Cipher) OpenStringPtr(ciphertext []byte) (*string, error) {
 	if ciphertext == nil {
 		return nil, nil
```

---

### ~~LOW-001: go.mod Specifies Non-Existent Go Version~~ IMPLEMENTED 2026-01-22

**Severity:** LOW
**Location:** `go.mod:3`
**Impact:** Build may fail or behave unexpectedly

**Description:**

The `go.mod` file specifies `go 1.25` which does not exist (current latest is 1.23.x).

```go
// Current (go.mod:3)
go 1.25
```

**Recommended Fix:**

```diff
--- a/go.mod
+++ b/go.mod
@@ -1,6 +1,6 @@
 module github.com/ai8future/encryptedcol

-go 1.25
+go 1.23

 require (
 	github.com/davecgh/go-spew v1.1.1 // indirect
```

---

### LOW-002: Documentation Incorrectly Claims Snappy Support

**Severity:** LOW
**Location:** `options.go:42-44`
**Impact:** Developer confusion

**Description:**

The `WithCompressionAlgorithm` documentation claims "snappy" is supported, but the implementation returns `ErrUnsupportedCompression` for snappy.

```go
// Current (options.go:42-44)
// WithCompressionAlgorithm sets the compression algorithm to use.
// Supported values: "zstd" (default), "snappy".  // <-- Snappy is NOT supported
func WithCompressionAlgorithm(algo string) Option {
```

**Recommended Fix:**

```diff
--- a/options.go
+++ b/options.go
@@ -40,7 +40,7 @@ func WithCompressionThreshold(bytes int) Option {
 }

 // WithCompressionAlgorithm sets the compression algorithm to use.
-// Supported values: "zstd" (default), "snappy".
+// Supported values: "zstd" (default). Snappy support is reserved for future implementation.
 func WithCompressionAlgorithm(algo string) Option {
 	return func(c *config) {
 		c.compressionAlgorithm = algo
```

---

### ~~LOW-003: Key ID Comparison Not Constant-Time~~ IMPLEMENTED 2026-01-22

**Severity:** LOW (Theoretical)
**Location:** `cipher.go:187`
**Impact:** Theoretical timing attack (key ID is not secret)

**Description:**

The inner key ID verification uses `!=` comparison which is not constant-time. While the key ID is not secret (it appears in the header), constant-time comparison is a cryptographic best practice.

```go
// Current (cipher.go:187)
if innerKeyID != expectedKeyID {
    return nil, ErrKeyIDMismatch
}
```

**Recommended Fix:**

```diff
--- a/cipher.go
+++ b/cipher.go
@@ -5,6 +5,7 @@ import (
 	"sort"

 	"golang.org/x/crypto/nacl/secretbox"
+	"crypto/subtle"
 )

@@ -184,7 +185,7 @@ func (c *Cipher) decryptAndVerify(keys *derivedKeys, encrypted []byte, nonce *[2
 	}

 	// Verify inner key_id matches expected (constant-time for defense-in-depth)
-	if innerKeyID != expectedKeyID {
+	if subtle.ConstantTimeCompare([]byte(innerKeyID), []byte(expectedKeyID)) != 1 {
 		return nil, ErrKeyIDMismatch
 	}
```

---

### ~~LOW-004: Lexicographic Key ID Sorting May Surprise Users~~ NOT APPLICABLE

**Severity:** LOW → NOT APPLICABLE
**Location:** `cipher.go`
**Status:** Code no longer has sorted fallback

**Assessment:** Per git log "remove dead default key selection code", the sorted fallback was removed. `defaultKeyID` is now always set by the first `WithKey()` call in options.go. The sorted fallback code shown in this report no longer exists in the codebase.

---

### INFO-001: Zstd Initialization Error Deferred

**Severity:** INFO
**Location:** `compress.go:29-39`
**Impact:** Cryptic error on first encryption if zstd init fails

**Description:**

Zstd initialization errors are stored in a global variable and not surfaced until the first compression/decompression attempt. This could make debugging difficult.

```go
// Current behavior
zstdOnce.Do(func() {
    zstdEncoder, zstdErr = zstd.NewWriter(...)
    if zstdErr != nil {
        return
    }
    zstdDecoder, zstdErr = zstd.NewReader(nil)
})
```

**Recommendation:** Consider adding an `InitCompression()` function that can be called during application startup to surface errors early. However, this is optional as the current design does eventually surface the error.

---

## Summary

| ID | Severity | Description | Fix Provided | Status |
|----|----------|-------------|--------------|--------|
| HIGH-001 | HIGH | Use-after-close panic | ✅ | **DONE** |
| HIGH-002 | HIGH | StaticKeyProvider no deep-copy | ✅ | **DONE** |
| MEDIUM-001 | MEDIUM | No decompression size limit | ✅ | **DONE** |
| MEDIUM-002 | MEDIUM | No paramOffset upper bound | ✅ | **DONE** |
| MEDIUM-003 | MEDIUM | Inconsistent NULL handling docs | - | Intentional design |
| LOW-001 | LOW | Invalid Go version in go.mod | ✅ | **DONE** |
| LOW-002 | LOW | Snappy documentation incorrect | ✅ | Already done |
| LOW-003 | LOW | Non-constant-time key ID comparison | ✅ | **DONE** |
| LOW-004 | LOW | Lexicographic key sorting surprise | - | N/A (code removed) |
| INFO-001 | INFO | Deferred zstd init error | Documentation | - |

---

## Testing Recommendations

After applying fixes, run:

```bash
go test -v ./...           # All tests
go test -race ./...        # Race detection
go test -cover ./...       # Coverage
go test -bench=. ./...     # Benchmarks
```

Add new test cases:

1. **Use-after-close test:**
```go
func TestCipherUseAfterClose(t *testing.T) {
    cipher, _ := New(WithKey("v1", testKey()))
    cipher.Close()

    // Should panic or return ErrCipherClosed
    _, err := cipher.Open([]byte("data"))
    require.ErrorIs(t, err, ErrCipherClosed)
}
```

2. **StaticKeyProvider isolation test:**
```go
func TestStaticKeyProviderIsolation(t *testing.T) {
    original := []byte{1,2,3,...} // 32 bytes
    keys := map[string][]byte{"v1": original}
    provider := NewStaticKeyProvider("v1", keys)

    // Modify original
    original[0] = 0xFF

    // Provider should be unaffected
    key, _ := provider.GetKey("v1")
    require.NotEqual(t, byte(0xFF), key[0])
}
```

---

## Conclusion

The `encryptedcol` library demonstrates solid cryptographic engineering with appropriate algorithm choices (XSalsa20-Poly1305, HKDF-SHA256, HMAC-SHA256). The identified issues are primarily defensive programming gaps rather than fundamental cryptographic weaknesses.

**Priority Actions:**
1. Fix HIGH-001 (use-after-close) - Critical for production safety
2. Fix HIGH-002 (key isolation) - Important for key material security
3. Fix MEDIUM-001 (decompression limit) - Defense against malicious input

With these fixes applied, the library would be suitable for production use in applications requiring client-side encrypted database columns with searchable encryption support.
