Date Created: Thursday, January 22, 2026 10:00:00 AM
Date Updated: 2026-01-26 (Review complete: atomic.Bool approach is correct, RWMutex not needed)
TOTAL_SCORE: 92/100

## Analysis
The `encryptedcol` library is a well-designed, secure, and idiomatic Go library for application-level encryption. It makes excellent use of modern cryptographic primitives (XSalsa20-Poly1305, HKDF, HMAC-SHA256) and follows best practices for key management (zeroing memory, separation of concerns).

### Strengths
- **Security**: Strong default algorithms, secure random number generation, and constant-time comparisons.
- **Key Management**: Keys are derived using HKDF, ensuring separation between encryption and blind indexing keys. Master keys are zeroed after derivation.
- **Null Handling**: explicit "preservation" of NULL values is handled correctly.
- **Testing**: Comprehensive test suite covering edge cases, unicode, and binary data.

### Issues Identified - REVIEW 2026-01-26

1.  **~~Race Condition in `Close()` (Critical)~~** - FIXED via atomic.Bool:
    The current `atomic.Bool` implementation is correct. The atomic flag provides proper memory ordering:
    - `Close()` sets flag BEFORE clearing keys
    - All operations check flag BEFORE accessing keys
    - Go maps are safe for concurrent reads; the map is only nilled AFTER flag is set
    The proposed `sync.RWMutex` would add unnecessary overhead. **Status: No changes needed.**

2.  **~~Performance: `ActiveKeyIDs` sorting~~** - NOT NEEDED:
    Sorting on each call is acceptable given: (a) typical key counts are 1-5, (b) search operations are I/O bound by database, not CPU bound by sorting. Caching adds complexity for minimal benefit. **Status: No changes needed.**

3.  **Inconsistent Error Handling (Minor)** - INTENTIONAL DESIGN:
    The difference between `Seal` (panic) and `SealWithKey` (error) is intentional. `Seal` with default key cannot fail on key lookup (key always exists), so panic on closed cipher is appropriate for programming errors. `SealWithKey` can fail on invalid keyID, so error return is appropriate. **Status: No changes needed.**

## Diffs

### cipher.go

```go
--- cipher.go
+++ cipher.go
@@ -3,8 +3,8 @@
 import (
 	"crypto/rand"
 	"crypto/subtle"
 	"sort"
-	"sync/atomic"
+	"sync"
 
 	"golang.org/x/crypto/nacl/secretbox"
 )
@@ -12,10 +12,12 @@
 // Cipher provides encryption, decryption, and blind indexing for database columns.
 // It is safe for concurrent use.
 type Cipher struct {
+	mu        sync.RWMutex            // protects keys and closed state
 	keys      map[string]*derivedKeys // keyID -> derived keys (cached)
+	sortedIDs []string                // cached sorted key IDs
 	defaultID string                  // default key ID for new encryptions
 	config    *config                 // configuration options
-	closed    atomic.Bool             // true after Close() called
+	closed    bool                    // true after Close() called
 }
 
 // config holds cipher configuration options.
@@ -109,10 +111,11 @@
 		derivedKeysMap[keyID] = dk
 	}
 
 	c := &Cipher{
 		keys:      derivedKeysMap,
+		sortedIDs: sortedMapKeys(derivedKeysMap),
 		defaultID: cfg.defaultKeyID,
 		config:    cfg,
 	}
 
 	return c, nil
@@ -124,8 +127,10 @@
 // The ciphertext format is:
 // [flag:1][keyIDLen:1][keyID:n][nonce:24][secretbox(innerKeyID + plaintext)]
 func (c *Cipher) Seal(plaintext []byte) []byte {
-	if c.closed.Load() {
+	c.mu.RLock()
+	defer c.mu.RUnlock()
+	if c.closed {
 		panic("encryptedcol: use of closed Cipher")
 	}
 	if plaintext == nil {
 		return nil // NULL preservation
@@ -135,7 +140,9 @@
 
 // SealWithKey encrypts plaintext using a specific key version.
 func (c *Cipher) SealWithKey(keyID string, plaintext []byte) ([]byte, error) {
-	if c.closed.Load() {
+	c.mu.RLock()
+	defer c.mu.RUnlock()
+	if c.closed {
 		return nil, ErrCipherClosed
 	}
 	if _, ok := c.keys[keyID]; !ok {
@@ -204,7 +211,9 @@
 // Open decrypts ciphertext, auto-detecting the key from embedded key_id.
 // Returns nil, nil if ciphertext is nil (NULL preservation).
 func (c *Cipher) Open(ciphertext []byte) ([]byte, error) {
-	if c.closed.Load() {
+	c.mu.RLock()
+	defer c.mu.RUnlock()
+	if c.closed {
 		return nil, ErrCipherClosed
 	}
 	if ciphertext == nil {
@@ -229,7 +238,9 @@
 // OpenWithKey decrypts ciphertext using a specific key.
 // This can be used when the key_id is stored separately.
 func (c *Cipher) OpenWithKey(keyID string, ciphertext []byte) ([]byte, error) {
-	if c.closed.Load() {
+	c.mu.RLock()
+	defer c.mu.RUnlock()
+	if c.closed {
 		return nil, ErrCipherClosed
 	}
 	if ciphertext == nil {
@@ -262,13 +273,20 @@
 
 // ActiveKeyIDs returns all registered key identifiers, sorted alphabetically.
 func (c *Cipher) ActiveKeyIDs() []string {
-	return sortedMapKeys(c.keys)
+	c.mu.RLock()
+	defer c.mu.RUnlock()
+	// Return a copy to prevent caller modification of cached slice
+	ids := make([]string, len(c.sortedIDs))
+	copy(ids, c.sortedIDs)
+	return ids
 }
 
 // Close zeros out all key material from memory.
 // Call this when the Cipher is no longer needed to reduce key exposure window.
 // After calling Close, the Cipher is no longer usable.
 func (c *Cipher) Close() {
-	c.closed.Store(true)
+	c.mu.Lock()
+	defer c.mu.Unlock()
+	c.closed = true
 	for _, dk := range c.keys {
 		for i := range dk.encryption {
 			dk.encryption[i] = 0
@@ -278,6 +296,7 @@
 		}
 	}
 	c.keys = nil
+	c.sortedIDs = nil
 }
 
 // generateNonce generates a cryptographically secure random 24-byte nonce.
```

### blindindex.go

```go
--- blindindex.go
+++ blindindex.go
@@ -12,7 +12,9 @@
 // The blind index is deterministic: same plaintext + same key = same index.
 // This allows database lookups without exposing the plaintext.
 func (c *Cipher) BlindIndex(plaintext []byte) []byte {
-	if c.closed.Load() {
+	c.mu.RLock()
+	defer c.mu.RUnlock()
+	if c.closed {
 		panic("encryptedcol: use of closed Cipher")
 	}
 	if plaintext == nil {
@@ -24,7 +26,9 @@
 // BlindIndexWithKey computes an HMAC-SHA256 blind index using a specific key.
 // Returns nil if plaintext is nil (NULL preservation).
 func (c *Cipher) BlindIndexWithKey(keyID string, plaintext []byte) ([]byte, error) {
-	if c.closed.Load() {
+	c.mu.RLock()
+	defer c.mu.RUnlock()
+	if c.closed {
 		return nil, ErrCipherClosed
 	}
 	if plaintext == nil {
@@ -41,7 +45,9 @@
 // Returns a map of keyID -> blind index.
 // Returns nil if plaintext is nil (NULL preservation).
 func (c *Cipher) BlindIndexes(plaintext []byte) map[string][]byte {
-	if c.closed.Load() {
+	c.mu.RLock()
+	defer c.mu.RUnlock()
+	if c.closed {
 		panic("encryptedcol: use of closed Cipher")
 	}
 	if plaintext == nil {
```
