Date Created: 2026-01-19_2155
TOTAL_SCORE: 93/100

# 1. AUDIT

### [High] Panic on RNG Failure
The `generateNonce` function panics if `crypto/rand` fails. While RNG failure is catastrophic, a library should ideally return an error to allow the application to handle it (e.g., graceful shutdown or retry), especially in `SealWithKey` which already returns an error.

### [Low] Non-Constant Time Key ID Verification
In `decryptAndVerify`, the inner key ID is checked using a standard string comparison (`innerKeyID != expectedKeyID`). While this check happens inside an authenticated envelope (secretbox), replacing it with `subtle.ConstantTimeCompare` adds defense-in-depth against potential timing attacks if the authentication layer were ever bypassed or if the key ID itself is considered sensitive.

### [Low] Restrictive Column Name Validation
`isValidColumnName` in `search.go` restricts column names to `[a-zA-Z_][a-zA-Z0-9_]*`. This matches standard variable naming but may reject valid SQL identifiers (e.g., quoted identifiers containing spaces or hyphens).

# 2. TESTS

The current test suite is comprehensive (95% coverage). However, `Close()` is not verified to actually clear memory (though difficult to test deterministically). We can add a test to ensure the `Cipher` is unusable after `Close()`.

### Proposed Test: `TestClose_Unusable`
Verifies that `Seal` and `Open` fail or panic safely after `Close` is called.

```go
<<<<
// TestClose checks if keys are wiped.
func TestClose(t *testing.T) {
	cipher, err := New(WithKey("v1", testKey("v1")))
	if err != nil {
		t.Fatal(err)
	}

	cipher.Close()

	if cipher.keys != nil {
		t.Error("keys map should be nil after Close")
	}
}
====
func TestClose_Unusable(t *testing.T) {
	cipher, err := New(WithKey("v1", testKey("v1")))
	if err != nil {
		t.Fatal(err)
	}

	cipher.Close()

	if cipher.keys != nil {
		t.Error("keys map should be nil after Close")
	}

	// Operations should fail (likely panic due to nil map, or return error if we fix it)
	// Currently, Seal panics on nil map access, which is expected for a closed object.
	// We just want to ensure we don't accidentally use old keys.
	defer func() {
		if r := recover(); r == nil {
			t.Error("Seal should panic or fail after Close")
		}
	}()
	cipher.Seal([]byte("test"))
}
>>>>
```

# 3. FIXES

### Fix: Handle RNG Errors Gracefully
Update `generateNonce` to return an error, and propagate it. `Seal` will panic explicitly (maintaining API compatibility), but `SealWithKey` will return the error.

**Files:** `cipher.go`

```go
<<<<
// generateNonce generates a cryptographically secure random 24-byte nonce.
// Panics if the system's random source fails (unrecoverable).
func generateNonce() [24]byte {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return nonce
}
====
// generateNonce generates a cryptographically secure random 24-byte nonce.
func generateNonce() ([24]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, err
	}
	return nonce, nil
}
>>>>
```

```go
<<<<
// sealWithKeyID performs the actual encryption.
func (c *Cipher) sealWithKeyID(keyID string, plaintext []byte) []byte {
	keys := c.keys[keyID]

	// Format inner plaintext with key_id for authentication
	innerPlaintext := formatInnerPlaintext(keyID, plaintext)

	// Maybe compress
	toEncrypt, flag := maybeCompress(
		innerPlaintext,
		c.config.compressionThreshold,
		c.config.compressionAlgorithm,
		c.config.compressionDisabled,
	)

	// Generate nonce
	nonce := generateNonce()

	// Encrypt with secretbox
	encrypted := secretbox.Seal(nil, toEncrypt, &nonce, &keys.encryption)

	// Format outer ciphertext
	return formatCiphertext(flag, keyID, nonce, encrypted)
}
====
// sealWithKeyID performs the actual encryption.
func (c *Cipher) sealWithKeyID(keyID string, plaintext []byte) ([]byte, error) {
	keys := c.keys[keyID]

	// Format inner plaintext with key_id for authentication
	innerPlaintext := formatInnerPlaintext(keyID, plaintext)

	// Maybe compress
	toEncrypt, flag := maybeCompress(
		innerPlaintext,
		c.config.compressionThreshold,
		c.config.compressionAlgorithm,
		c.config.compressionDisabled,
	)

	// Generate nonce
	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}

	// Encrypt with secretbox
	encrypted := secretbox.Seal(nil, toEncrypt, &nonce, &keys.encryption)

	// Format outer ciphertext
	return formatCiphertext(flag, keyID, nonce, encrypted), nil
}
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
====
// Seal encrypts plaintext using the default key.
// Returns ciphertext with embedded key_id, or nil if plaintext is nil (NULL preservation).
// Panics if random source fails.
//
// The ciphertext format is:
// [flag:1][keyIDLen:1][keyID:n][nonce:24][secretbox(innerKeyID + plaintext)]
func (c *Cipher) Seal(plaintext []byte) []byte {
	if plaintext == nil {
		return nil // NULL preservation
	}
	out, err := c.sealWithKeyID(c.defaultID, plaintext)
	if err != nil {
		panic("encryptedcol: encryption failed: " + err.Error())
	}
	return out
}

// SealWithKey encrypts plaintext using a specific key version.
func (c *Cipher) SealWithKey(keyID string, plaintext []byte) ([]byte, error) {
	if plaintext == nil {
		return nil, nil // NULL preservation
	}
	if _, ok := c.keys[keyID]; !ok {
		return nil, ErrKeyNotFound
	}
	return c.sealWithKeyID(keyID, plaintext)
}
>>>>
```

### Fix: Constant Time Comparison
Use `crypto/subtle` for key ID verification.

**Files:** `cipher.go`

```go
<<<<
	// Verify inner key_id matches expected
	if innerKeyID != expectedKeyID {
		return nil, ErrKeyIDMismatch
	}

	return actualPlaintext, nil
}
====
	// Verify inner key_id matches expected
	if subtle.ConstantTimeCompare([]byte(innerKeyID), []byte(expectedKeyID)) != 1 {
		return nil, ErrKeyIDMismatch
	}

	return actualPlaintext, nil
}
>>>>
```

**Note:** Requires `import "crypto/subtle"`.

# 4. REFACTOR

### Improve SQL Generation Flexibility
The `SearchCondition` struct and method are tightly coupled to PostgreSQL's `$N` placeholder syntax.
*   **Recommendation:** Accept a `Placeholders` interface or function that generates placeholders (e.g., `?` for MySQL/SQLite, `$N` for Postgres).
*   **Recommendation:** Allow customizing the `OR` operator or the entire SQL template to support different dialects.

### API Consistency
`Seal` panics on error, while `Open` returns error. Consider deprecating `Seal` in favor of a `Seal2` or `Encrypt` method that returns `([]byte, error)` to enforce error handling for RNG failures, making the library more robust for mission-critical systems.
