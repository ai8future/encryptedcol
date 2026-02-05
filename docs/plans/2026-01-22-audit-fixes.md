# Audit Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Address all 9 issues identified in the 2026-01-22 security audit of the encryptedcol library.

**Architecture:** Targeted fixes to existing files. No new files needed. Each fix is isolated and can be implemented independently. Tests first for behavioral changes.

**Tech Stack:** Go 1.24, testify/require, XSalsa20-Poly1305 (nacl/secretbox), HKDF-SHA256

---

## Summary of Issues

| ID | Priority | Description | File |
|----|----------|-------------|------|
| H1 | High | Dead code in default key selection | cipher.go |
| H2 | High | StaticKeyProvider.GetKey returns internal reference | provider.go |
| M1 | Medium | Missing closed check in BlindIndex methods | blindindex.go |
| M2 | Medium | config.keys reference retained after zeroing | cipher.go |
| M3 | Medium | SearchCondition panic leaks column name | search.go |
| M4 | Medium | Compression division by zero edge case | compress.go |
| L1 | Low | Options comment says Snappy supported | options.go |
| L2 | Low | No validation of negative compression threshold | options.go |
| L3 | Low | NeedsRotation silently returns false on error | rotate.go |

---

## Task 1: Fix H2 - StaticKeyProvider.GetKey Returns Copy

**Files:**
- Modify: `provider.go:77-82`
- Test: `provider_test.go`

**Step 1: Write the failing test**

Add to `provider_test.go`:

```go
func TestStaticKeyProvider_GetKey_ReturnsCopy(t *testing.T) {
	originalKey := testKey("v1")
	keys := map[string][]byte{
		"v1": originalKey,
	}

	provider := NewStaticKeyProvider("v1", keys)

	// Get the key
	key1, err := provider.GetKey("v1")
	require.NoError(t, err)

	// Modify the returned key
	key1[0] = 0xFF
	key1[1] = 0xFF

	// Get the key again - should be unaffected
	key2, err := provider.GetKey("v1")
	require.NoError(t, err)

	require.NotEqual(t, key1[0], key2[0], "GetKey should return a copy, not internal reference")
}
```

**Step 2: Run test to verify it fails**

Run: `go test -v -run TestStaticKeyProvider_GetKey_ReturnsCopy ./...`
Expected: FAIL - key2[0] equals key1[0] because both reference same slice

**Step 3: Write minimal implementation**

Modify `provider.go:77-82`:

```go
// GetKey implements KeyProvider.
func (p *StaticKeyProvider) GetKey(keyID string) ([]byte, error) {
	key, ok := p.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	// Return a copy to prevent external modification
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return keyCopy, nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test -v -run TestStaticKeyProvider_GetKey_ReturnsCopy ./...`
Expected: PASS

**Step 5: Run full test suite**

Run: `go test -race ./...`
Expected: PASS

**Step 6: Commit**

```bash
git add provider.go provider_test.go
git commit -m "$(cat <<'EOF'
fix(provider): return copy from GetKey to prevent modification

StaticKeyProvider.GetKey was returning a reference to internal key
material. Callers could modify the key in place, affecting all
subsequent uses. Now returns a copy.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Fix M1 - Add Closed Checks to BlindIndex Methods

**Files:**
- Modify: `blindindex.go:14-60`
- Test: `blindindex_test.go`

**Step 1: Write the failing test**

Add to `blindindex_test.go`:

```go
func TestBlindIndex_UseAfterClose(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))
	cipher.Close()

	// All BlindIndex methods should return error or handle closed state
	require.Panics(t, func() {
		cipher.BlindIndex([]byte("test"))
	}, "BlindIndex should panic after Close")

	require.Panics(t, func() {
		cipher.BlindIndexString("test")
	}, "BlindIndexString should panic after Close")

	require.Panics(t, func() {
		cipher.BlindIndexes([]byte("test"))
	}, "BlindIndexes should panic after Close")

	_, err := cipher.BlindIndexWithKey("v1", []byte("test"))
	require.ErrorIs(t, err, ErrCipherClosed, "BlindIndexWithKey should return ErrCipherClosed")
}
```

**Step 2: Run test to verify it fails**

Run: `go test -v -run TestBlindIndex_UseAfterClose ./...`
Expected: FAIL with nil pointer dereference or wrong error

**Step 3: Write minimal implementation**

Modify `blindindex.go`:

```go
// BlindIndex computes an HMAC-SHA256 blind index using the default key.
// This enables searchable encryption via exact-match queries.
// Returns nil if plaintext is nil (NULL preservation).
//
// The blind index is deterministic: same plaintext + same key = same index.
// This allows database lookups without exposing the plaintext.
func (c *Cipher) BlindIndex(plaintext []byte) []byte {
	if c.closed.Load() {
		panic("encryptedcol: use of closed Cipher")
	}
	if plaintext == nil {
		return nil
	}
	return c.computeHMAC(c.defaultID, plaintext)
}

// BlindIndexWithKey computes an HMAC-SHA256 blind index using a specific key.
// Returns nil if plaintext is nil (NULL preservation).
func (c *Cipher) BlindIndexWithKey(keyID string, plaintext []byte) ([]byte, error) {
	if c.closed.Load() {
		return nil, ErrCipherClosed
	}
	if plaintext == nil {
		return nil, nil
	}
	keys, ok := c.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return computeHMACWithKey(&keys.hmac, plaintext), nil
}

// BlindIndexes computes HMAC blind indexes for all active key versions.
// This is useful for search queries that need to match across key rotations.
// Returns a map of keyID -> blind index.
// Returns nil if plaintext is nil (NULL preservation).
func (c *Cipher) BlindIndexes(plaintext []byte) map[string][]byte {
	if c.closed.Load() {
		panic("encryptedcol: use of closed Cipher")
	}
	if plaintext == nil {
		return nil
	}

	indexes := make(map[string][]byte, len(c.keys))
	for keyID := range c.keys {
		indexes[keyID] = c.computeHMAC(keyID, plaintext)
	}
	return indexes
}

// BlindIndexString computes a blind index for a string value.
// Convenience method that converts string to bytes.
func (c *Cipher) BlindIndexString(s string) []byte {
	return c.BlindIndex([]byte(s))
}
```

**Step 4: Run test to verify it passes**

Run: `go test -v -run TestBlindIndex_UseAfterClose ./...`
Expected: PASS

**Step 5: Run full test suite**

Run: `go test -race ./...`
Expected: PASS

**Step 6: Commit**

```bash
git add blindindex.go blindindex_test.go
git commit -m "$(cat <<'EOF'
fix(blindindex): add closed checks to all BlindIndex methods

BlindIndex, BlindIndexString, and BlindIndexes now panic if called
after Close() (consistent with Seal behavior). BlindIndexWithKey
returns ErrCipherClosed (consistent with SealWithKey behavior).

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Fix H1 - Remove Dead Code in Default Key Selection

**Files:**
- Modify: `cipher.go:70-76`

**Step 1: Verify the code is dead**

The code at cipher.go:70-76 only runs when `cfg.defaultKeyID == ""`, but `WithKey()` in options.go:19-22 always sets defaultKeyID on first call. Verify with a test:

```go
func TestNew_DefaultKeyID_AlwaysSetByWithKey(t *testing.T) {
	// This test documents that WithKey always sets defaultKeyID
	// so the sortedMapKeys fallback in New() is dead code
	cfg := defaultConfig()

	// Before any WithKey, defaultKeyID is empty
	require.Equal(t, "", cfg.defaultKeyID)

	// After WithKey, defaultKeyID is set
	WithKey("zebra", testKey("zebra"))(cfg)
	require.Equal(t, "zebra", cfg.defaultKeyID, "WithKey should set defaultKeyID")

	// Additional WithKey calls don't change it
	WithKey("alpha", testKey("alpha"))(cfg)
	require.Equal(t, "zebra", cfg.defaultKeyID, "defaultKeyID should remain first key")
}
```

**Step 2: Run the verification test**

Run: `go test -v -run TestNew_DefaultKeyID_AlwaysSetByWithKey ./...`
Expected: PASS (confirms the code is dead)

**Step 3: Remove dead code and fix comment**

Modify `cipher.go:66-76` to remove the dead code block:

```go
	if len(cfg.keys) == 0 {
		return nil, ErrNoKeys
	}

	// Note: defaultKeyID is always set by the first WithKey() call.
	// If using NewWithProvider(), it's set explicitly via WithDefaultKeyID().

	// Verify default key exists
	if _, ok := cfg.keys[cfg.defaultKeyID]; !ok {
		return nil, ErrDefaultKeyNotFound
	}
```

**Step 4: Run full test suite**

Run: `go test -race ./...`
Expected: PASS

**Step 5: Commit**

```bash
git add cipher.go cipher_test.go
git commit -m "$(cat <<'EOF'
refactor(cipher): remove dead default key selection code

The sortedMapKeys fallback in New() was unreachable because WithKey()
always sets defaultKeyID on first call. Removed dead code and added
clarifying comment.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Fix M2 - Clear config.keys Reference After Zeroing

**Files:**
- Modify: `cipher.go:96-105`

**Step 1: Analyze the issue**

The defer block zeros cfg.keys but the Cipher retains a reference to cfg. While currently safe, this is fragile. Fix by setting cfg.keys to nil after zeroing.

**Step 2: Modify the defer block**

Change `cipher.go:96-105`:

```go
	// Zero out master keys from config (they're no longer needed)
	// Defer ensures this happens even if key derivation fails
	defer func() {
		for keyID := range cfg.keys {
			key := cfg.keys[keyID]
			for i := range key {
				key[i] = 0
			}
		}
		cfg.keys = nil // Clear reference to prevent accidental access
	}()
```

**Step 3: Run full test suite**

Run: `go test -race ./...`
Expected: PASS

**Step 4: Commit**

```bash
git add cipher.go
git commit -m "$(cat <<'EOF'
fix(cipher): clear config.keys reference after zeroing

After zeroing master keys in the defer block, cfg.keys now set to nil.
Prevents future code from accidentally accessing zeroed key material
through the config reference retained in the Cipher struct.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Fix M3 - Remove Column Name from Panic Message

**Files:**
- Modify: `search.go:57-59`

**Step 1: Modify panic message**

Change `search.go:57-59`:

```go
	if !isValidColumnName(column) {
		panic("encryptedcol: invalid column name (must start with letter/underscore, contain only alphanumeric/underscore)")
	}
```

**Step 2: Run full test suite**

Run: `go test -race ./...`
Expected: PASS

**Step 3: Commit**

```bash
git add search.go
git commit -m "$(cat <<'EOF'
fix(search): remove column name from panic message

Panic messages should not include potentially sensitive input values.
Column names are typically hardcoded, but defense-in-depth applies.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Fix M4 - Document Compression Threshold Edge Case

**Files:**
- Modify: `options.go:34-39`

**Step 1: Add documentation**

Change `options.go:34-39`:

```go
// WithCompressionThreshold sets the minimum size in bytes before compression is attempted.
// Default is 1024 (1KB). Data smaller than this will not be compressed.
// Must be > 0; a threshold of 0 could cause issues with empty data.
func WithCompressionThreshold(bytes int) Option {
	return func(c *config) {
		c.compressionThreshold = bytes
	}
}
```

**Step 2: Commit**

```bash
git add options.go
git commit -m "$(cat <<'EOF'
docs(options): document compression threshold must be > 0

Added note that threshold should be > 0 to avoid edge case with
empty data causing division by zero in savings calculation.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Fix L1 - Correct Snappy Support Comment

**Files:**
- Modify: `options.go:42-48`

**Step 1: Fix documentation**

Change `options.go:42-48`:

```go
// WithCompressionAlgorithm sets the compression algorithm to use.
// Currently only "zstd" (default) is supported.
// "snappy" is reserved for future implementation.
func WithCompressionAlgorithm(algo string) Option {
	return func(c *config) {
		c.compressionAlgorithm = algo
	}
}
```

**Step 2: Commit**

```bash
git add options.go
git commit -m "$(cat <<'EOF'
docs(options): clarify snappy is reserved, not supported

The comment incorrectly stated snappy was supported. Only zstd works;
snappy is reserved for future implementation.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Fix L2 - Document Negative Threshold Behavior

**Files:**
- Modify: `options.go:34-40` (already modified in Task 6, extend)

**Step 1: Extend documentation**

The documentation added in Task 6 already addresses this. No additional changes needed.

**Step 2: Skip to next task**

---

## Task 9: Fix L3 - Document NeedsRotation Silent Failure

**Files:**
- Modify: `rotate.go:77-91`

**Step 1: Add documentation**

Change `rotate.go:77-91`:

```go
// NeedsRotation checks if a ciphertext was encrypted with an old key.
// Returns true if the key_id in the ciphertext differs from the default key.
// Returns false for nil ciphertext (NULL values don't need rotation).
//
// Note: Returns false if the ciphertext format is invalid. Use ExtractKeyID
// if you need to detect malformed ciphertext.
func (c *Cipher) NeedsRotation(ciphertext []byte) bool {
	if ciphertext == nil {
		return false
	}

	_, keyID, _, _, err := parseFormat(ciphertext)
	if err != nil {
		return false // Can't determine, assume doesn't need rotation
	}

	return keyID != c.defaultID
}
```

**Step 2: Commit**

```bash
git add rotate.go
git commit -m "$(cat <<'EOF'
docs(rotate): document NeedsRotation returns false on invalid format

Added note that NeedsRotation returns false for malformed ciphertext.
Users should use ExtractKeyID if they need to detect invalid data.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Final Verification

**Step 1: Run complete test suite with race detection**

Run: `go test -race -cover ./...`
Expected: PASS with coverage > 95%

**Step 2: Run go vet**

Run: `go vet ./...`
Expected: No issues

**Step 3: Build**

Run: `go build ./...`
Expected: Success

---

## Summary

| Task | Issue | Type | Files Modified |
|------|-------|------|----------------|
| 1 | H2 | Security | provider.go, provider_test.go |
| 2 | M1 | Security | blindindex.go, blindindex_test.go |
| 3 | H1 | Cleanup | cipher.go, cipher_test.go |
| 4 | M2 | Security | cipher.go |
| 5 | M3 | Security | search.go |
| 6 | M4 | Docs | options.go |
| 7 | L1 | Docs | options.go |
| 8 | L2 | Docs | (covered by Task 6) |
| 9 | L3 | Docs | rotate.go |
