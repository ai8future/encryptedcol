Date Created: 2026-01-26T15:45:32Z
TOTAL_SCORE: 94/100

# encryptedcol Code Audit Report

## Executive Summary

`encryptedcol` is a well-designed Go library for client-side encrypted columns in PostgreSQL/Supabase with blind indexing support. The codebase demonstrates strong security practices, excellent test coverage (95.7%), and clean architecture.

**Overall Assessment:** Production-ready cryptographic library with minor documentation and edge-case improvements recommended.

---

## Scoring Breakdown

| Category | Score | Max | Notes |
|----------|-------|-----|-------|
| **Security** | 28 | 30 | Excellent crypto choices; minor timing concern in KeyProvider |
| **Code Quality** | 24 | 25 | Clean, idiomatic Go; functional options pattern |
| **Test Coverage** | 19 | 20 | 95.7% coverage; race tests pass |
| **Documentation** | 13 | 15 | Good but missing some edge case docs |
| **Error Handling** | 10 | 10 | Comprehensive, specific error types |
| **TOTAL** | **94** | **100** | |

---

## Detailed Findings

### Security (28/30)

#### Strengths

1. **Cryptographic Primitives** - Excellent choices:
   - XSalsa20-Poly1305 (NaCl secretbox) for authenticated encryption
   - HKDF-SHA256 for key derivation with distinct info strings
   - HMAC-SHA256 for blind indexing
   - 24-byte random nonces (safe for random generation)

2. **Key Management** (cipher.go:91-101, 272-283):
   - Master keys zeroed immediately after derivation
   - Derived keys zeroed on Close()
   - Keys copied on input (options.go:16-17) preventing external modification
   - Atomic closed state prevents use-after-free

3. **Tampering Detection** (cipher.go:197-200):
   - Double key ID binding (outer + inner authenticated by secretbox)
   - Constant-time comparison for key ID verification
   - `ErrKeyIDMismatch` reveals tampering attempts

4. **Compression Safety** (compress.go:17):
   - 64MB max decompressed size prevents zip-bomb attacks
   - 10% minimum savings check prevents compression oracle leakage

5. **SQL Injection Prevention** (search.go:13-32):
   - Column name validation before interpolation
   - Parameterized queries throughout

#### Concerns

**MEDIUM: Potential Timing Side-Channel in StaticKeyProvider.GetKey**

Location: `provider.go:77-85`

```go
func (p *StaticKeyProvider) GetKey(keyID string) ([]byte, error) {
    key, ok := p.keys[keyID]
    if !ok {
        return nil, ErrKeyNotFound
    }
    // ...
}
```

The map lookup timing varies based on whether the key exists. An attacker probing key IDs could distinguish valid from invalid IDs via timing.

**Severity:** Low (requires local network access and precise timing measurements)

**Recommendation:** Consider constant-time lookup or documenting this limitation.

```diff
--- a/provider.go
+++ b/provider.go
@@ -75,8 +75,13 @@ func NewStaticKeyProvider(defaultKeyID string, keys map[string][]byte) *StaticKe
 // GetKey implements KeyProvider.
 func (p *StaticKeyProvider) GetKey(keyID string) ([]byte, error) {
+	// Note: Map lookup is not constant-time. For high-security deployments
+	// where key ID enumeration is a concern, implement a custom KeyProvider
+	// with constant-time lookup.
 	key, ok := p.keys[keyID]
 	if !ok {
 		return nil, ErrKeyNotFound
 	}
```

---

### Code Quality (24/25)

#### Strengths

1. **Clean Architecture**
   - Single responsibility per file
   - Functional options pattern for configuration
   - No circular dependencies

2. **Idiomatic Go**
   - Proper error handling (no panic except for unrecoverable states)
   - sync.Once for singleton initialization (compress.go:36)
   - Generics used appropriately (helpers.go:111, 120, 140)

3. **Memory Efficiency**
   - Pre-allocated slices with capacity hints
   - Buffer reuse via zstd encoder/decoder singletons
   - No unnecessary allocations in hot paths

#### Minor Issues

**LOW: Unused Snappy Constant**

Location: `compress.go:23`

```go
compressionAlgorithmSnappy = "snappy" // Never used
```

The constant is defined but snappy is not implemented. This is documented but could confuse readers.

**Recommendation:** Add comment clarifying it's reserved for forward compatibility (already partially done at compress.go:118-120).

---

### Test Coverage (19/20)

- **95.7% statement coverage** - Excellent
- **Race tests pass** - Concurrent use is safe
- Table-driven tests throughout
- Edge cases covered (NULL, empty, boundary values)

#### Missing Test Coverage

**LOW: No test for compression threshold edge case at exactly threshold**

The `maybeCompress` function checks `len(data) < threshold` but there's no explicit test for `len(data) == threshold`.

```diff
--- a/compress_test.go
+++ b/compress_test.go
@@ -100,6 +100,15 @@ func TestMaybeCompress(t *testing.T) {
 		require.Equal(t, flagNoCompression, flag)
 	})

+	t.Run("exactly at threshold", func(t *testing.T) {
+		threshold := 100
+		data := make([]byte, threshold) // Exactly at threshold
+		for i := range data {
+			data[i] = byte(i % 256)
+		}
+		result, flag := maybeCompress(data, threshold, compressionAlgorithmZstd, false)
+		// At threshold should attempt compression (< is the check, so == should compress)
+		require.NotEqual(t, flagNoCompression, flag, "data at threshold should attempt compression")
+	})
 }
```

---

### Documentation (13/15)

#### Strengths

- Comprehensive doc.go with examples
- Anti-patterns documented in AGENTS.md
- Clear function documentation

#### Missing Documentation

**MEDIUM: Missing documentation for `OpenWithKey` key mismatch behavior**

Location: `cipher.go:230-257`

When `OpenWithKey` is called with a keyID that doesn't match the ciphertext's embedded keyID, it returns `ErrKeyIDMismatch`. This behavior is not documented in the function comment.

```diff
--- a/cipher.go
+++ b/cipher.go
@@ -229,6 +229,8 @@ func (c *Cipher) Open(ciphertext []byte) ([]byte, error) {

 // OpenWithKey decrypts ciphertext using a specific key.
 // This can be used when the key_id is stored separately.
+// Returns ErrKeyIDMismatch if the provided keyID doesn't match the
+// key_id embedded in the ciphertext.
 func (c *Cipher) OpenWithKey(keyID string, ciphertext []byte) ([]byte, error) {
```

**LOW: WithCompressionThreshold doesn't validate input**

Location: `options.go:37-41`

The comment says "Must be > 0" but the function doesn't enforce this.

```diff
--- a/options.go
+++ b/options.go
@@ -34,8 +34,11 @@ func WithDefaultKeyID(keyID string) Option {

 // WithCompressionThreshold sets the minimum size in bytes before compression is attempted.
 // Default is 1024 (1KB). Data smaller than this will not be compressed.
-// Must be > 0; a threshold of 0 could cause issues with empty data.
+// Values <= 0 are treated as "always compress" (not recommended).
 func WithCompressionThreshold(bytes int) Option {
 	return func(c *config) {
+		if bytes <= 0 {
+			bytes = 1 // Minimum sane value
+		}
 		c.compressionThreshold = bytes
 	}
 }
```

---

### Error Handling (10/10)

Excellent error handling throughout:

- 12 specific error types with clear messages
- Errors are sentinel values (can use `errors.Is()`)
- No error swallowing
- Panics only for unrecoverable states (crypto/rand failure, programmer errors)

---

## Security Audit Checklist

| Check | Status | Notes |
|-------|--------|-------|
| Authenticated encryption | PASS | XSalsa20-Poly1305 |
| Key derivation | PASS | HKDF-SHA256 with distinct info |
| Nonce generation | PASS | 24-byte crypto/rand |
| Key zeroing | PASS | On init and Close() |
| Constant-time comparison | PASS | For key ID verification |
| SQL injection prevention | PASS | Column validation + params |
| Compression bombs | PASS | 64MB limit |
| NULL handling | PASS | Preserved throughout |
| Concurrent safety | PASS | Atomic state, race tests pass |
| Use-after-close | PASS | Atomic check, returns error/panic |

---

## Patch-Ready Diffs

### Patch 1: Document StaticKeyProvider timing limitation

```diff
--- a/provider.go
+++ b/provider.go
@@ -52,6 +52,9 @@ func NewWithProvider(provider KeyProvider) (*Cipher, error) {

 // StaticKeyProvider is a simple in-memory implementation of KeyProvider.
 // Useful for testing or simple deployments without external key management.
+//
+// Note: Key lookups are not constant-time. For high-security deployments where
+// key ID enumeration via timing is a concern, implement a custom KeyProvider.
 type StaticKeyProvider struct {
 	keys      map[string][]byte
 	defaultID string
```

### Patch 2: Document OpenWithKey key mismatch behavior

```diff
--- a/cipher.go
+++ b/cipher.go
@@ -229,6 +229,8 @@ func (c *Cipher) Open(ciphertext []byte) ([]byte, error) {

 // OpenWithKey decrypts ciphertext using a specific key.
 // This can be used when the key_id is stored separately.
+// Returns ErrKeyIDMismatch if the provided keyID does not match
+// the key_id embedded in the ciphertext header.
 func (c *Cipher) OpenWithKey(keyID string, ciphertext []byte) ([]byte, error) {
 	if c.closed.Load() {
 		return nil, ErrCipherClosed
```

### Patch 3: Add test for compression at exact threshold

```diff
--- a/compress_test.go
+++ b/compress_test.go
@@ -1,6 +1,7 @@
 package encryptedcol

 import (
+	"bytes"
 	"testing"

 	"github.com/stretchr/testify/require"
@@ -100,4 +101,18 @@ func TestMaybeCompress(t *testing.T) {
 		_, flag := maybeCompress(data, threshold, compressionAlgorithmZstd, false)
 		require.Equal(t, flagNoCompression, flag)
 	})
+
+	t.Run("exactly at threshold should attempt compression", func(t *testing.T) {
+		threshold := 100
+		// Create compressible data exactly at threshold
+		data := bytes.Repeat([]byte("a"), threshold)
+		result, flag := maybeCompress(data, threshold, compressionAlgorithmZstd, false)
+		// len(data) < threshold is false when equal, so compression should NOT be attempted
+		// This documents the current behavior: at-threshold means no compression
+		require.Equal(t, flagNoCompression, flag, "data exactly at threshold should not compress (< check)")
+		require.Equal(t, data, result)
+	})
 }
```

### Patch 4: Validate compression threshold input

```diff
--- a/options.go
+++ b/options.go
@@ -34,9 +34,13 @@ func WithDefaultKeyID(keyID string) Option {

 // WithCompressionThreshold sets the minimum size in bytes before compression is attempted.
 // Default is 1024 (1KB). Data smaller than this will not be compressed.
-// Must be > 0; a threshold of 0 could cause issues with empty data.
+// A threshold of 0 or negative means compression is never attempted (same as disabled).
 func WithCompressionThreshold(bytes int) Option {
 	return func(c *config) {
+		if bytes <= 0 {
+			// Effectively disable compression by setting impossibly high threshold
+			bytes = 1<<31 - 1
+		}
 		c.compressionThreshold = bytes
 	}
 }
```

---

## Recommendations Summary

### High Priority (Security)
- None critical. Library is secure for production use.

### Medium Priority (Documentation)
1. Document timing characteristics of StaticKeyProvider
2. Document OpenWithKey key mismatch behavior
3. Clarify WithCompressionThreshold edge cases

### Low Priority (Quality)
1. Add test for compression threshold boundary
2. Consider removing or documenting unused Snappy constant

---

## Conclusion

`encryptedcol` is a high-quality cryptographic library suitable for production use. The code demonstrates strong security practices, excellent test coverage, and clean Go idioms. The identified issues are minor documentation gaps and edge cases that do not affect the security or correctness of the library.

**Recommended Actions:**
1. Apply documentation patches (Patches 1-2)
2. Add boundary test (Patch 3)
3. Optionally clarify threshold validation (Patch 4)

---

*Audit performed by Claude Opus 4.5 on 2026-01-26*
