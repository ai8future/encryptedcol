# rcodegen Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement security and code quality fixes identified in rcodegen reports

**Architecture:** Defensive programming improvements - use-after-close protection, key material isolation, decompression limits, and constant-time comparisons

**Tech Stack:** Go, sync/atomic, crypto/subtle

---

## Summary of Fixes

| Priority | ID | Description | File(s) |
|----------|-----|-------------|---------|
| HIGH | FIX-1 | Use-after-close protection | cipher.go, errors.go |
| HIGH | FIX-2 | StaticKeyProvider deep-copy keys | provider.go |
| MEDIUM | FIX-3 | Decompression size limit | compress.go |
| MEDIUM | FIX-4 | paramOffset upper bound check | search.go |
| LOW | FIX-5 | go.mod version fix | go.mod |
| LOW | FIX-6 | Constant-time key ID comparison | cipher.go |
| LOW | FIX-7 | Zstd cleanup on decoder failure | compress.go |
| LOW | FIX-8 | SealWithKey nil check order | cipher.go |

---

## Task 1: Add ErrCipherClosed Error

**Files:**
- Modify: `errors.go`

**Step 1: Add new error variable**

Add after line 38 (after ErrUnsupportedCompression):

```go
	// ErrCipherClosed indicates the cipher was used after Close() was called.
	ErrCipherClosed = errors.New("encryptedcol: cipher is closed")
```

**Step 2: Run build to verify**

Run: `go build ./...`
Expected: Success

**Step 3: Commit**

```bash
git add errors.go
git commit -m "$(cat <<'EOF'
feat: add ErrCipherClosed error for use-after-close detection

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Add Use-After-Close Protection to Cipher

**Files:**
- Modify: `cipher.go`

**Step 1: Add sync/atomic import and closed field**

Update imports to add `sync/atomic`:

```go
import (
	"crypto/rand"
	"sort"
	"sync/atomic"

	"golang.org/x/crypto/nacl/secretbox"
)
```

Add `closed` field to Cipher struct after `config`:

```go
type Cipher struct {
	keys      map[string]*derivedKeys // keyID -> derived keys (cached)
	defaultID string                  // default key ID for new encryptions
	config    *config                 // configuration options
	closed    atomic.Bool             // true after Close() called
}
```

**Step 2: Add closed check to Seal method**

At the start of `Seal()` method, before the nil check:

```go
func (c *Cipher) Seal(plaintext []byte) []byte {
	if c.closed.Load() {
		panic("encryptedcol: use of closed Cipher")
	}
	if plaintext == nil {
```

**Step 3: Add closed check to SealWithKey method**

At the start of `SealWithKey()` method:

```go
func (c *Cipher) SealWithKey(keyID string, plaintext []byte) ([]byte, error) {
	if c.closed.Load() {
		return nil, ErrCipherClosed
	}
	if _, ok := c.keys[keyID]; !ok {
```

**Step 4: Add closed check to Open method**

At the start of `Open()` method:

```go
func (c *Cipher) Open(ciphertext []byte) ([]byte, error) {
	if c.closed.Load() {
		return nil, ErrCipherClosed
	}
	if ciphertext == nil {
```

**Step 5: Add closed check to OpenWithKey method**

At the start of `OpenWithKey()` method:

```go
func (c *Cipher) OpenWithKey(keyID string, ciphertext []byte) ([]byte, error) {
	if c.closed.Load() {
		return nil, ErrCipherClosed
	}
	if ciphertext == nil {
```

**Step 6: Set closed flag in Close method**

At the start of `Close()` method:

```go
func (c *Cipher) Close() {
	c.closed.Store(true)
	for _, dk := range c.keys {
```

**Step 7: Run tests to verify**

Run: `go test -v ./...`
Expected: All tests pass

**Step 8: Commit**

```bash
git add cipher.go
git commit -m "$(cat <<'EOF'
feat: add use-after-close protection to Cipher

Operations on a closed Cipher now return ErrCipherClosed or panic
with a clear message instead of nil pointer dereference.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Add Deep-Copy and Close to StaticKeyProvider

**Files:**
- Modify: `provider.go`

**Step 1: Update NewStaticKeyProvider to deep-copy keys**

Replace the NewStaticKeyProvider function:

```go
// NewStaticKeyProvider creates a StaticKeyProvider with the given keys.
// Keys are deep-copied to prevent external modification.
func NewStaticKeyProvider(defaultKeyID string, keys map[string][]byte) *StaticKeyProvider {
	// Deep-copy all keys to prevent external modification
	keysCopy := make(map[string][]byte, len(keys))
	for id, key := range keys {
		keyCopy := make([]byte, len(key))
		copy(keyCopy, key)
		keysCopy[id] = keyCopy
	}
	return &StaticKeyProvider{
		keys:      keysCopy,
		defaultID: defaultKeyID,
	}
}
```

**Step 2: Add Close method to StaticKeyProvider**

Add after ActiveKeyIDs method:

```go
// Close zeros out all key material from memory.
// After calling Close, the provider should not be used.
func (p *StaticKeyProvider) Close() {
	for _, key := range p.keys {
		for i := range key {
			key[i] = 0
		}
	}
	p.keys = nil
}
```

**Step 3: Run tests to verify**

Run: `go test -v ./...`
Expected: All tests pass

**Step 4: Commit**

```bash
git add provider.go
git commit -m "$(cat <<'EOF'
feat: deep-copy keys in StaticKeyProvider and add Close method

- NewStaticKeyProvider now copies keys to prevent external modification
- Added Close() method to zero key material when provider is discarded

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Add Decompression Size Limit

**Files:**
- Modify: `compress.go`

**Step 1: Add maxDecompressedSize constant**

After line 12 (after minCompressionSavings), add:

```go
	// maxDecompressedSize is the maximum allowed decompressed size (64MB).
	// This prevents zip bomb attacks where a small compressed payload
	// expands to consume all available memory.
	maxDecompressedSize = 64 * 1024 * 1024
```

**Step 2: Update decompressZstd to check size**

Replace the decompressZstd function:

```go
// decompressZstd decompresses zstd-compressed data.
// Returns ErrDecompressionFailed if decompressed size exceeds maxDecompressedSize.
func decompressZstd(data []byte) ([]byte, error) {
	_, decoder, err := initZstd()
	if err != nil {
		return nil, err
	}
	result, err := decoder.DecodeAll(data, nil)
	if err != nil {
		return nil, ErrDecompressionFailed
	}
	if len(result) > maxDecompressedSize {
		return nil, ErrDecompressionFailed
	}
	return result, nil
}
```

**Step 3: Run tests to verify**

Run: `go test -v ./...`
Expected: All tests pass

**Step 4: Commit**

```bash
git add compress.go
git commit -m "$(cat <<'EOF'
fix: add decompression size limit to prevent zip bombs

Limit decompressed output to 64MB to prevent memory exhaustion from
maliciously crafted compressed payloads.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Add paramOffset Upper Bound Check

**Files:**
- Modify: `search.go`

**Step 1: Add maxParamNumber constant**

After the imports, add:

```go
// maxParamNumber is the PostgreSQL maximum parameter number.
const maxParamNumber = 65535
```

**Step 2: Update SearchCondition validation**

Replace the paramOffset validation in SearchCondition:

```go
	if paramOffset < 1 || paramOffset > maxParamNumber {
		panic(fmt.Sprintf("encryptedcol: invalid paramOffset (must be 1-%d)", maxParamNumber))
	}
```

**Step 3: Add check for parameter overflow**

After getting ids (after line `ids := c.ActiveKeyIDs()`):

```go
	ids := c.ActiveKeyIDs()

	// Check that parameters won't exceed PostgreSQL limit
	maxParam := paramOffset + (len(ids) * 2) - 1
	if maxParam > maxParamNumber {
		panic(fmt.Sprintf("encryptedcol: too many keys (%d) would exceed PostgreSQL parameter limit", len(ids)))
	}
```

**Step 4: Run tests to verify**

Run: `go test -v ./...`
Expected: All tests pass

**Step 5: Commit**

```bash
git add search.go
git commit -m "$(cat <<'EOF'
fix: validate paramOffset upper bound in SearchCondition

Add check for PostgreSQL's 65535 parameter limit to prevent silent
query failures with many keys during aggressive key rotation.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Fix go.mod Version

**Files:**
- Modify: `go.mod`

**Step 1: Change Go version**

Change line 3 from `go 1.25` to `go 1.23`

**Step 2: Run go mod tidy**

Run: `go mod tidy`
Expected: Success

**Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "$(cat <<'EOF'
fix: correct Go version in go.mod from 1.25 to 1.23

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Use Constant-Time Key ID Comparison

**Files:**
- Modify: `cipher.go`

**Step 1: Add crypto/subtle import**

Update imports:

```go
import (
	"crypto/rand"
	"crypto/subtle"
	"sort"
	"sync/atomic"

	"golang.org/x/crypto/nacl/secretbox"
)
```

**Step 2: Update decryptAndVerify to use constant-time comparison**

Replace the key ID verification in decryptAndVerify:

```go
	// Verify inner key_id matches expected (constant-time for defense-in-depth)
	if subtle.ConstantTimeCompare([]byte(innerKeyID), []byte(expectedKeyID)) != 1 {
		return nil, ErrKeyIDMismatch
	}
```

**Step 3: Run tests to verify**

Run: `go test -v ./...`
Expected: All tests pass

**Step 4: Commit**

```bash
git add cipher.go
git commit -m "$(cat <<'EOF'
fix: use constant-time comparison for key ID verification

While key IDs are not secret, constant-time comparison is a
cryptographic best practice for defense-in-depth.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Clean Up Zstd Encoder on Decoder Failure

**Files:**
- Modify: `compress.go`

**Step 1: Update initZstd to clean up on failure**

Replace the initZstd function:

```go
// initZstd initializes the zstd encoder and decoder once.
func initZstd() (*zstd.Encoder, *zstd.Decoder, error) {
	zstdOnce.Do(func() {
		zstdEncoder, zstdErr = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
		if zstdErr != nil {
			return
		}
		zstdDecoder, zstdErr = zstd.NewReader(nil)
		if zstdErr != nil {
			// Clean up encoder if decoder creation fails
			zstdEncoder.Close()
			zstdEncoder = nil
		}
	})
	return zstdEncoder, zstdDecoder, zstdErr
}
```

**Step 2: Run tests to verify**

Run: `go test -v ./...`
Expected: All tests pass

**Step 3: Commit**

```bash
git add compress.go
git commit -m "$(cat <<'EOF'
fix: clean up zstd encoder if decoder initialization fails

Prevents resource leak when decoder creation fails after encoder
succeeds during zstd initialization.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Fix SealWithKey Nil Check Order

**Files:**
- Modify: `cipher.go`

**Step 1: Reorder checks in SealWithKey**

The current order (after Task 2's closed check) should be:
1. closed check
2. keyID validation
3. plaintext nil check

Ensure the method looks like:

```go
func (c *Cipher) SealWithKey(keyID string, plaintext []byte) ([]byte, error) {
	if c.closed.Load() {
		return nil, ErrCipherClosed
	}
	if _, ok := c.keys[keyID]; !ok {
		return nil, ErrKeyNotFound
	}
	if plaintext == nil {
		return nil, nil // NULL preservation
	}
	return c.sealWithKeyID(keyID, plaintext), nil
}
```

**Step 2: Run tests to verify**

Run: `go test -v ./...`
Expected: All tests pass

**Step 3: Commit**

```bash
git add cipher.go
git commit -m "$(cat <<'EOF'
fix: validate keyID before nil check in SealWithKey

Invalid keyID errors should not be hidden when plaintext is nil.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: Final Verification

**Step 1: Run all tests**

Run: `go test -v ./...`
Expected: All tests pass

**Step 2: Run race detector**

Run: `go test -race ./...`
Expected: No races detected

**Step 3: Run build**

Run: `go build ./...`
Expected: Success

---

## Task 11: Update rcodegen Reports

After all fixes are implemented, update the report files to remove completed items and add "Date Updated: 2026-01-22".

**Files to update:**
- `_rcodegen/encryptedcol-claude-fix-2026-01-21_2243.md`
- `_rcodegen/encryptedcol-claude-audit-2026-01-21_2231.md`
- `_rcodegen/encryptedcol-claude-quick-2026-01-21_2247.md`

---

## Completion Checklist

- [ ] Task 1: ErrCipherClosed error added
- [ ] Task 2: Use-after-close protection implemented
- [ ] Task 3: StaticKeyProvider deep-copy and Close()
- [ ] Task 4: Decompression size limit
- [ ] Task 5: paramOffset upper bound check
- [ ] Task 6: go.mod version fixed
- [ ] Task 7: Constant-time key ID comparison
- [ ] Task 8: Zstd cleanup on failure
- [ ] Task 9: SealWithKey nil check order
- [ ] Task 10: Final verification passed
- [ ] Task 11: Reports updated
