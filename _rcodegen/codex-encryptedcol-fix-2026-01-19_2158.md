Date Created: 2026-01-19 22:01:59 +0100
TOTAL_SCORE: 88/100

Overview
Quick scan of core cryptography paths, compression, search SQL builder, helpers, and options. Focused on correctness, concurrency, and API/documentation clarity. No code changes applied per instruction; patch-ready diffs below.

Score Rationale
- Strong crypto design (secretbox, HKDF, inner key ID binding) and solid tests for core paths.
- Deductions for a concurrency race around Close, a doc/API mismatch for compression algorithm support, and an unbounded decompression risk (DoS vector) that needs a design choice.

Findings (ordered by severity)
1) High: Close is not concurrency-safe despite "safe for concurrent use" claim.
- Evidence: `cipher.go:10` states concurrency-safe; `cipher.go:257` mutates and nils `c.keys` without synchronization while methods read from the map and key material.
- Impact: data races and potential panics or incorrect cryptographic operations if Close overlaps with Seal/Open/BlindIndex.
- Fix: add a RWMutex to Cipher, take read locks in operations, and write lock in Close so Close blocks until in-flight ops finish. (Patch A)

2) Low: WithCompressionAlgorithm docs claim snappy support, but snappy is rejected at runtime.
- Evidence: `options.go:42` says snappy supported, but `cipher.go:81-85` rejects any non-zstd algorithm.
- Impact: developer confusion and wasted integration time.
- Fix: clarify comment to indicate only zstd is supported and snappy is reserved. (Patch B)

Notes / Unresolved Risks
- Unbounded decompression: `compress.go` uses zstd DecodeAll without a size cap, so malicious ciphertext could trigger large allocations. Consider adding a configurable max decompressed size or decoder max window in a future version.
- SearchCondition panics on invalid column/paramOffset; acceptable if treated as programmer error, but a safe variant returning errors may be useful for inputs influenced by user data.

Patch-ready diffs (not applied)

Patch A: make Close concurrency-safe via RWMutex
```diff
diff --git a/cipher.go b/cipher.go
index 9c77a2b..7c4d3e1 100644
--- a/cipher.go
+++ b/cipher.go
@@
-import (
-	"crypto/rand"
-	"sort"
-
-	"golang.org/x/crypto/nacl/secretbox"
-)
+import (
+	"crypto/rand"
+	"sort"
+	"sync"
+
+	"golang.org/x/crypto/nacl/secretbox"
+)
@@
 type Cipher struct {
+	mu        sync.RWMutex
 	keys      map[string]*derivedKeys // keyID -> derived keys (cached)
 	defaultID string                  // default key ID for new encryptions
 	config    *config                 // configuration options
 }
@@
 func (c *Cipher) Seal(plaintext []byte) []byte {
 	if plaintext == nil {
 		return nil // NULL preservation
 	}
+	c.mu.RLock()
+	defer c.mu.RUnlock()
 	return c.sealWithKeyID(c.defaultID, plaintext)
 }
@@
 func (c *Cipher) SealWithKey(keyID string, plaintext []byte) ([]byte, error) {
 	if plaintext == nil {
 		return nil, nil // NULL preservation
 	}
+	c.mu.RLock()
+	defer c.mu.RUnlock()
 	if _, ok := c.keys[keyID]; !ok {
 		return nil, ErrKeyNotFound
 	}
 	return c.sealWithKeyID(keyID, plaintext), nil
 }
@@
 func (c *Cipher) Open(ciphertext []byte) ([]byte, error) {
 	if ciphertext == nil {
 		return nil, nil // NULL preservation
 	}
+	c.mu.RLock()
+	defer c.mu.RUnlock()
@@
 func (c *Cipher) OpenWithKey(keyID string, ciphertext []byte) ([]byte, error) {
 	if ciphertext == nil {
 		return nil, nil
 	}
+	c.mu.RLock()
+	defer c.mu.RUnlock()
@@
 func (c *Cipher) ActiveKeyIDs() []string {
+	c.mu.RLock()
+	defer c.mu.RUnlock()
 	ids := make([]string, 0, len(c.keys))
 	for id := range c.keys {
 		ids = append(ids, id)
 	}
 	sort.Strings(ids)
 	return ids
 }
@@
 func (c *Cipher) Close() {
+	c.mu.Lock()
+	defer c.mu.Unlock()
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

```diff
diff --git a/blindindex.go b/blindindex.go
index 86dd2f4..be01f8f 100644
--- a/blindindex.go
+++ b/blindindex.go
@@
 func (c *Cipher) BlindIndex(plaintext []byte) []byte {
 	if plaintext == nil {
 		return nil
 	}
+	c.mu.RLock()
+	defer c.mu.RUnlock()
 	return c.computeHMAC(c.defaultID, plaintext)
 }
@@
 func (c *Cipher) BlindIndexWithKey(keyID string, plaintext []byte) ([]byte, error) {
 	if plaintext == nil {
 		return nil, nil
 	}
+	c.mu.RLock()
+	defer c.mu.RUnlock()
 	keys, ok := c.keys[keyID]
 	if !ok {
 		return nil, ErrKeyNotFound
 	}
 	return computeHMACWithKey(&keys.hmac, plaintext), nil
 }
@@
 func (c *Cipher) BlindIndexes(plaintext []byte) map[string][]byte {
 	if plaintext == nil {
 		return nil
 	}
+	c.mu.RLock()
+	defer c.mu.RUnlock()
@@
 	indexes := make(map[string][]byte, len(c.keys))
 	for keyID := range c.keys {
 		indexes[keyID] = c.computeHMAC(keyID, plaintext)
 	}
 	return indexes
 }
```

Patch B: clarify supported compression algorithms
```diff
diff --git a/options.go b/options.go
index e164636..3c5a2a1 100644
--- a/options.go
+++ b/options.go
@@
 // WithCompressionAlgorithm sets the compression algorithm to use.
-// Supported values: "zstd" (default), "snappy".
+// Supported values: "zstd" (default). "snappy" is reserved but not implemented.
 func WithCompressionAlgorithm(algo string) Option {
 	return func(c *config) {
 		c.compressionAlgorithm = algo
 	}
 }
```

Suggested follow-up tests
- `go test -race ./...` (validates the Close concurrency fix)

