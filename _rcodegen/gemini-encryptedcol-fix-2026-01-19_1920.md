Date Created: Monday, January 19, 2026 at 7:20 PM
TOTAL_SCORE: 85/100

# Codebase Audit Report

The `encryptedcol` library provides a robust and easy-to-use interface for application-level encryption with searchable blind indexes. It correctly utilizes `nacl/secretbox` (XSalsa20-Poly1305) for encryption and HMAC-SHA256 for blind indexing. The code is well-structured, thoroughly tested, and generally adheres to Go best practices.

However, two significant issues were identified that impact reliability and thread safety.

## 1. Concurrency Race Condition in `Close()`

**Severity:** High
**File:** `cipher.go`, `blindindex.go`

The `Cipher` struct claims to be safe for concurrent use. However, the `Close()` method modifies the `keys` map (setting it to `nil` and zeroing values) without any synchronization. If `Close()` is called while other goroutines are performing encryption (`Seal`) or decryption (`Open`), a race condition occurs. This can lead to panics (reading from a nil map) or, worse, using zeroed key material if the underlying key memory is cleared while being read.

**Fix:** Introduce a `sync.RWMutex` to protect access to the `keys` map. Readers (`Seal`, `Open`, `BlindIndex`) should acquire a read lock, and `Close` should acquire a write lock.

## 2. Non-Deterministic Default Key Selection

**Severity:** Medium
**File:** `cipher.go`

In `New()`, if multiple keys are provided but no `DefaultKeyID` is specified, the code iterates over the `cfg.keys` map to pick a default. Since map iteration order in Go is random, the selected default key is non-deterministic. This can cause the application to encrypt data with different keys on different restarts, potentially confusing key rotation logic or unexpected behavior.

**Fix:** When no default key is specified, sort the available key IDs lexically and select the first one to ensure deterministic behavior.

---

## Patch-Ready Diffs

### Fix 1 & 2: Thread Safety and Deterministic Key Selection

```diff
diff --git a/cipher.go b/cipher.go
index 1234567..89abcdef 100644
--- a/cipher.go
+++ b/cipher.go
@@ -3,6 +3,8 @@ package encryptedcol
 import (
 	"crypto/rand"
+	"sort"
+	"sync"
 
 	"golang.org/x/crypto/nacl/secretbox"
 )
@@ -10,6 +12,7 @@ import (
 // Cipher provides encryption, decryption, and blind indexing for database columns.
 // It is safe for concurrent use.
 type Cipher struct {
+	mu        sync.RWMutex            // protects keys map
 	keys      map[string]*derivedKeys // keyID -> derived keys (cached)
 	defaultID string                  // default key ID for new encryptions
 	config    *config                 // configuration options
@@ -56,8 +59,14 @@ func New(opts ...Option) (*Cipher, error) {
 
 	// If no default key ID specified, use the first key added
 	if cfg.defaultKeyID == "" {
+		// Sort keys to ensure deterministic selection
+		ids := make([]string, 0, len(cfg.keys))
 		for keyID := range cfg.keys {
-			cfg.defaultKeyID = keyID
-			break
+			ids = append(ids, keyID)
+		}
+		sort.Strings(ids)
+		if len(ids) > 0 {
+			cfg.defaultKeyID = ids[0]
 		}
 	}
 
@@ -126,6 +135,9 @@ func (c *Cipher) SealWithKey(keyID string, plaintext []byte) ([]byte, error) {
 	if plaintext == nil {
 		return nil, nil // NULL preservation
 	}
+	c.mu.RLock()
+	defer c.mu.RUnlock()
+
 	if _, ok := c.keys[keyID]; !ok {
 		return nil, ErrKeyNotFound
 	}
@@ -134,6 +146,9 @@ func (c *Cipher) SealWithKey(keyID string, plaintext []byte) ([]byte, error) {
 
 // sealWithKeyID performs the actual encryption.
 func (c *Cipher) sealWithKeyID(keyID string, plaintext []byte) []byte {
+	// Assumes caller holds read lock if called internally,
+	// but Seal calls this. Let's make Seal take the lock or lock here.
+	// To avoid deadlock if Seal calls SealWithKey, we should lock at the public method level.
 	keys := c.keys[keyID]
 
 	// Format inner plaintext with key_id for authentication
@@ -158,6 +173,9 @@ func (c *Cipher) Seal(plaintext []byte) []byte {
 	if plaintext == nil {
 		return nil // NULL preservation
 	}
+	c.mu.RLock()
+	defer c.mu.RUnlock()
+
 	return c.sealWithKeyID(c.defaultID, plaintext)
 }
 
@@ -171,6 +189,9 @@ func (c *Cipher) Open(ciphertext []byte) ([]byte, error) {
 		return nil, err
 	}
 
+	c.mu.RLock()
+	defer c.mu.RUnlock()
+
 	// Get the encryption key
 	keys, ok := c.keys[outerKeyID]
 	if !ok {
@@ -211,6 +232,9 @@ func (c *Cipher) OpenWithKey(keyID string, ciphertext []byte) ([]byte, error) {
 		return nil, nil
 	}
 
+	c.mu.RLock()
+	defer c.mu.RUnlock()
+
 	keys, ok := c.keys[keyID]
 	if !ok {
 		return nil, ErrKeyNotFound
@@ -250,6 +274,9 @@ func (c *Cipher) DefaultKeyID() string {
 
 // ActiveKeyIDs returns all registered key identifiers.
 func (c *Cipher) ActiveKeyIDs() []string {
+	c.mu.RLock()
+	defer c.mu.RUnlock()
+
 	ids := make([]string, 0, len(c.keys))
 	for id := range c.keys {
 		ids = append(ids, id)
@@ -261,6 +288,9 @@ func (c *Cipher) ActiveKeyIDs() []string {
 // Call this when the Cipher is no longer needed to reduce key exposure window.
 // After calling Close, the Cipher is no longer usable.
 func (c *Cipher) Close() {
+	c.mu.Lock()
+	defer c.mu.Unlock()
+
 	for _, dk := range c.keys {
 		for i := range dk.encryption {
 			dk.encryption[i] = 0
diff --git a/blindindex.go b/blindindex.go
index 4567890..abcdef1 100644
--- a/blindindex.go
+++ b/blindindex.go
@@ -23,6 +23,9 @@ func (c *Cipher) BlindIndex(plaintext []byte) []byte {
 	if plaintext == nil {
 		return nil
 	}
+	c.mu.RLock()
+	defer c.mu.RUnlock()
+
 	return c.computeHMAC(c.defaultID, plaintext)
 }
 
@@ -32,6 +35,9 @@ func (c *Cipher) BlindIndexWithKey(keyID string, plaintext []byte) ([]byte, error) {
 	if plaintext == nil {
 		return nil, nil
 	}
+	c.mu.RLock()
+	defer c.mu.RUnlock()
+
 	keys, ok := c.keys[keyID]
 	if !ok {
 		return nil, ErrKeyNotFound
@@ -47,6 +53,9 @@ func (c *Cipher) BlindIndexes(plaintext []byte) map[string][]byte {
 		return nil
 	}
 
+	c.mu.RLock()
+	defer c.mu.RUnlock()
+
 	indexes := make(map[string][]byte, len(c.keys))
 	for keyID := range c.keys {
 		indexes[keyID] = c.computeHMAC(keyID, plaintext)
@@ -62,6 +71,7 @@ func (c *Cipher) BlindIndexString(s string) []byte {
 
 // computeHMAC computes HMAC-SHA256 using the specified key's HMAC key.
 func (c *Cipher) computeHMAC(keyID string, data []byte) []byte {
+	// Assumes caller holds read lock
 	keys := c.keys[keyID]
 	return computeHMACWithKey(&keys.hmac, data)
 }
```

DO NOT EDIT CODE.
