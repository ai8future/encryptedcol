Date Created: Monday, January 19, 2026 at 07:05 PM
TOTAL_SCORE: 92/100

# EncryptedCol Security & Code Audit

## Executive Summary
The `encryptedcol` library is a high-quality, well-structured Go library for application-side encryption. It correctly employs modern cryptographic primitives (XSalsa20-Poly1305 via NaCl, HKDF-SHA256, HMAC-SHA256). The code is idiomatic, readable, and generally safe.

The primary finding is a **concurrency race condition** between the `Close()` method and encryption/decryption operations. While the documentation claims safety for concurrent use, `Close()` modifies the key map while other methods read it without synchronization.

## Security Analysis

### Strengths
1.  **Primitives:** Uses `golang.org/x/crypto/nacl/secretbox` which provides authenticated encryption (AEAD). This ensures confidentiality and integrity.
2.  **Key Derivation:** Correctly uses HKDF-SHA256 to derive separate encryption and HMAC keys from the master key, using distinct info strings (`infoEncryption`, `infoBlindIndex`). This prevents key reuse attacks.
3.  **Context Binding:** The "inner plaintext" format includes the `key_id` *before* encryption. This effectively binds the ciphertext to the specific key version, preventing key-substitution attacks where an attacker might swap the outer `key_id` metadata.
4.  **Blind Indexing:** Uses HMAC-SHA256, which is the standard approach for searchable encryption.
5.  **Nonce Generation:** Uses `crypto/rand` for 24-byte nonces, which is appropriate for XSalsa20.

### Risks & Warnings
1.  **Deterministic Encryption (Blind Index):** The blind index is deterministic. Users must be aware that this leaks equality patterns (frequency analysis). This is a trade-off for searchability but should be documented for low-entropy fields (e.g., boolean, small enums).
2.  **Compression Oracle:** Using `zstd` compression on secret data *can* lead to side-channel attacks (like CRIME/BREACH) if the attacker controls parts of the plaintext. For database columns, this is usually less of a risk than in web traffic, but still a consideration.
3.  **Concurrency Race:** As noted, `Close()` zeroes out keys. If called while another goroutine is using `Seal()` or `Open()`, it will cause a data race and potential panic or undefined behavior.

## Code Quality
- **Style:** Code follows Go idioms well.
- **Error Handling:** Generally good, though `Seal` swallows errors (returning nil or panicking on RNG failure). Panicking on `crypto/rand` failure is an acceptable design choice for this level of abstraction.
- **Performance:** `sync.Once` for zstd initialization is good. Key derivation is cached.

## Recommended Fixes (Patch-Ready Diffs)

### 1. Fix Concurrency Race in Cipher
Add a `sync.RWMutex` to the `Cipher` struct to ensure `Close()` does not race with `Seal/Open`.

```go
<<<<
// Cipher provides encryption, decryption, and blind indexing for database columns.
// It is safe for concurrent use.
type Cipher struct {
	keys      map[string]*derivedKeys // keyID -> derived keys (cached)
	defaultID string                  // default key ID for new encryptions
	config    *config                 // configuration options
}
====
// Cipher provides encryption, decryption, and blind indexing for database columns.
// It is safe for concurrent use.
type Cipher struct {
	mu        sync.RWMutex
	keys      map[string]*derivedKeys // keyID -> derived keys (cached)
	defaultID string                  // default key ID for new encryptions
	config    *config                 // configuration options
}
>>>>
```

```go
<<<<
// SealWithKey encrypts plaintext using a specific key version.
func (c *Cipher) SealWithKey(keyID string, plaintext []byte) ([]byte, error) {
	if plaintext == nil {
		return nil, nil // NULL preservation
	}
	if _, ok := c.keys[keyID]; !ok {
		return nil, ErrKeyNotFound
	}
	return c.sealWithKeyID(keyID, plaintext), nil
}

// sealWithKeyID performs the actual encryption.
func (c *Cipher) sealWithKeyID(keyID string, plaintext []byte) []byte {
	keys := c.keys[keyID]

	// Format inner plaintext with key_id for authentication
====
// SealWithKey encrypts plaintext using a specific key version.
func (c *Cipher) SealWithKey(keyID string, plaintext []byte) ([]byte, error) {
	if plaintext == nil {
		return nil, nil // NULL preservation
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if _, ok := c.keys[keyID]; !ok {
		return nil, ErrKeyNotFound
	}
	return c.sealWithKeyID(keyID, plaintext), nil
}

// sealWithKeyID performs the actual encryption.
// Caller must hold read lock.
func (c *Cipher) sealWithKeyID(keyID string, plaintext []byte) []byte {
	keys := c.keys[keyID]

	// Format inner plaintext with key_id for authentication
>>>>
```

```go
<<<<
// Seal encrypts plaintext using the default key.
// Returns ciphertext with embedded key_id, or nil if plaintext is nil (NULL preservation).
//
// The ciphertext format is:
// [flag:1][keyIDLen:1][keyID:n][nonce:24][secretbox(innerKeyID + plaintext)]
func (c *Cipher) Seal(plaintext []byte) []byte {
	if plaintext == nil {
		return nil // NULL preservation
	}
	return c.sealWithKeyID(c.defaultID, plaintext)
}
====
// Seal encrypts plaintext using the default key.
// Returns ciphertext with embedded key_id, or nil if plaintext is nil (NULL preservation).
//
// The ciphertext format is:
// [flag:1][keyIDLen:1][keyID:n][nonce:24][secretbox(innerKeyID + plaintext)]
func (c *Cipher) Seal(plaintext []byte) []byte {
	if plaintext == nil {
		return nil // NULL preservation
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sealWithKeyID(c.defaultID, plaintext)
}
>>>>
```

```go
<<<<
// Open decrypts ciphertext, auto-detecting the key from embedded key_id.
// Returns nil, nil if ciphertext is nil (NULL preservation).
func (c *Cipher) Open(ciphertext []byte) ([]byte, error) {
	if ciphertext == nil {
		return nil, nil // NULL preservation
	}

	// Parse outer format
	flag, outerKeyID, nonce, encrypted, err := parseFormat(ciphertext)
	if err != nil {
		return nil, err
	}

	// Get the encryption key
	keys, ok := c.keys[outerKeyID]
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Decrypt
====
// Open decrypts ciphertext, auto-detecting the key from embedded key_id.
// Returns nil, nil if ciphertext is nil (NULL preservation).
func (c *Cipher) Open(ciphertext []byte) ([]byte, error) {
	if ciphertext == nil {
		return nil, nil // NULL preservation
	}

	// Parse outer format
	flag, outerKeyID, nonce, encrypted, err := parseFormat(ciphertext)
	if err != nil {
		return nil, err
	}

	c.mu.RLock()
	keys, ok := c.keys[outerKeyID]
	c.mu.RUnlock()

	if !ok {
		return nil, ErrKeyNotFound
	}

	// Decrypt
>>>>
```

```go
<<<<
// OpenWithKey decrypts ciphertext using a specific key.
// This can be used when the key_id is stored separately.
func (c *Cipher) OpenWithKey(keyID string, ciphertext []byte) ([]byte, error) {
	if ciphertext == nil {
		return nil, nil
	}

	keys, ok := c.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Parse outer format
====
// OpenWithKey decrypts ciphertext using a specific key.
// This can be used when the key_id is stored separately.
func (c *Cipher) OpenWithKey(keyID string, ciphertext []byte) ([]byte, error) {
	if ciphertext == nil {
		return nil, nil
	}

	c.mu.RLock()
	keys, ok := c.keys[keyID]
	c.mu.RUnlock()

	if !ok {
		return nil, ErrKeyNotFound
	}

	// Parse outer format
>>>>
```

```go
<<<<
// Close zeros out all key material from memory.
// Call this when the Cipher is no longer needed to reduce key exposure window.
// After calling Close, the Cipher is no longer usable.
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
====
// Close zeros out all key material from memory.
// Call this when the Cipher is no longer needed to reduce key exposure window.
// After calling Close, the Cipher is no longer usable.
func (c *Cipher) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
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
>>>>
```

### 2. Blind Index Concurrency
The `BlindIndex` methods also read from `c.keys`. They need similar protection.

```go
<<<<
// BlindIndex computes an HMAC-SHA256 blind index using the default key.
// This enables searchable encryption via exact-match queries.
// Returns nil if plaintext is nil (NULL preservation).
//
// The blind index is deterministic: same plaintext + same key = same index.
// This allows database lookups without exposing the plaintext.
func (c *Cipher) BlindIndex(plaintext []byte) []byte {
	if plaintext == nil {
		return nil
	}
	return c.computeHMAC(c.defaultID, plaintext)
}

// BlindIndexWithKey computes an HMAC-SHA256 blind index using a specific key.
// Returns nil if plaintext is nil (NULL preservation).
func (c *Cipher) BlindIndexWithKey(keyID string, plaintext []byte) ([]byte, error) {
	if plaintext == nil {
		return nil, nil
	}
	keys, ok := c.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return computeHMACWithKey(&keys.hmac, plaintext), nil
}
====
// BlindIndex computes an HMAC-SHA256 blind index using the default key.
// This enables searchable encryption via exact-match queries.
// Returns nil if plaintext is nil (NULL preservation).
//
// The blind index is deterministic: same plaintext + same key = same index.
// This allows database lookups without exposing the plaintext.
func (c *Cipher) BlindIndex(plaintext []byte) []byte {
	if plaintext == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.computeHMAC(c.defaultID, plaintext)
}

// BlindIndexWithKey computes an HMAC-SHA256 blind index using a specific key.
// Returns nil if plaintext is nil (NULL preservation).
func (c *Cipher) BlindIndexWithKey(keyID string, plaintext []byte) ([]byte, error) {
	if plaintext == nil {
		return nil, nil
	}
	c.mu.RLock()
	keys, ok := c.keys[keyID]
	c.mu.RUnlock()
	if !ok {
		return nil, ErrKeyNotFound
	}
	return computeHMACWithKey(&keys.hmac, plaintext), nil
}
>>>>
```

```go
<<<<
// computeHMAC computes HMAC-SHA256 using the specified key's HMAC key.
func (c *Cipher) computeHMAC(keyID string, data []byte) []byte {
	keys := c.keys[keyID]
	return computeHMACWithKey(&keys.hmac, data)
}
====
// computeHMAC computes HMAC-SHA256 using the specified key's HMAC key.
// Caller must hold read lock.
func (c *Cipher) computeHMAC(keyID string, data []byte) []byte {
	keys := c.keys[keyID]
	return computeHMACWithKey(&keys.hmac, data)
}
>>>>
```
