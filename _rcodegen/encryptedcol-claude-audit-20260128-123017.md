Date Created: 2026-01-28 12:30:17
TOTAL_SCORE: 92/100

# encryptedcol Security & Code Audit Report

## Executive Summary

This audit reviews `encryptedcol`, a Go library for client-side encrypted columns in PostgreSQL/Supabase with blind indexing support. The library demonstrates **excellent security practices**, **comprehensive test coverage (95.7%)**, and **clean, idiomatic Go code**. Only minor issues were identified, none of which are critical security vulnerabilities.

---

## Scoring Breakdown

| Category | Score | Max | Notes |
|----------|-------|-----|-------|
| Security Architecture | 28/30 | 30 | Excellent crypto choices, minor salt concern |
| Code Quality | 24/25 | 25 | Clean, idiomatic Go |
| Test Coverage | 20/20 | 20 | 95.7% coverage, comprehensive edge cases |
| Documentation | 10/10 | 10 | Thorough docs, anti-pattern warnings |
| Error Handling | 8/10 | 10 | Good, but inconsistent panic vs error patterns |
| Maintainability | 2/5 | 5 | No linter config, some dead code |

**TOTAL: 92/100**

---

## Security Analysis

### Strengths

1. **Strong Cryptographic Primitives**
   - XSalsa20-Poly1305 (NaCl secretbox) - industry-standard AEAD
   - HKDF-SHA256 for key derivation with distinct info strings
   - HMAC-SHA256 for blind indexes
   - 24-byte random nonces from crypto/rand

2. **Defense-in-Depth Key Authentication**
   - Dual key_id (outer header + inner authenticated payload)
   - Prevents key confusion attacks (cipher.go:192-199)
   - Constant-time comparison for inner key_id verification

3. **Memory Safety**
   - Keys zeroed on Close() (cipher.go:272-283)
   - Master keys zeroed after derivation (cipher.go:93-101)
   - Key copies prevent external modification (options.go:15-18, provider.go:63-69)

4. **Compression Safety**
   - 64MB decompression limit prevents zip bombs (compress.go:17)
   - 10% minimum savings threshold prevents pointless compression

5. **SQL Injection Prevention**
   - Strict column name validation (search.go:13-32)
   - Parameterized queries only
   - PostgreSQL parameter limit enforcement

### Issues (Minor)

#### ISSUE-SEC-01: No Salt in HKDF Derivation (Low Severity)
**File:** kdf.go:52
**Current Code:**
```go
reader := hkdf.New(sha256.New, masterKey, nil, []byte(info))
```

**Analysis:** While using nil salt is cryptographically valid per RFC 5869 (HKDF uses zero-filled salt), adding a unique salt per key_id would provide additional defense against related-key attacks. This is a hardening suggestion, not a vulnerability.

**Recommendation:** Consider deriving with `salt = []byte(keyID)` for additional separation.

**PATCH:**
```diff
--- a/kdf.go
+++ b/kdf.go
@@ -49,6 +49,9 @@ func deriveKeys(masterKey []byte) (*derivedKeys, error) {

 // hkdfDerive performs HKDF-SHA256 key derivation with the given info string.
 // No salt is used (nil salt means HKDF uses a zero-filled salt of HashLen bytes).
-func hkdfDerive(masterKey []byte, info string, out []byte) error {
-	reader := hkdf.New(sha256.New, masterKey, nil, []byte(info))
+// NOTE: Consider passing keyID as salt for additional key separation in future versions.
+func hkdfDerive(masterKey []byte, info string, out []byte) error {
+	// Using nil salt is safe per RFC 5869 but could be hardened with keyID-based salt
+	reader := hkdf.New(sha256.New, masterKey, nil, []byte(info))
 	_, err := io.ReadFull(reader, out)
```

#### ISSUE-SEC-02: Blind Index Rainbow Table Vulnerability (Documented Design)
**File:** blindindex.go
**Analysis:** Static HMAC keys enable rainbow table attacks on low-entropy fields. This is **explicitly documented as an intentional design decision** in AGENTS.md to enable global search capability.

**No patch needed** - this is working as designed. Users are warned not to use blind indexes for low-entropy fields.

---

## Code Quality Analysis

### Strengths

1. **Consistent Error Handling**
   - Well-defined sentinel errors (errors.go)
   - Errors.Is compatible for checking

2. **Thread Safety**
   - atomic.Bool for closed state
   - sync.Once for zstd initialization
   - Thread-safe zstd encoder/decoder reuse

3. **Clean API Design**
   - Functional options pattern
   - Type-safe generics (SealJSON/OpenJSON)
   - NULL preservation throughout

### Issues (Minor)

#### ISSUE-CODE-01: Inconsistent Error vs Panic Pattern
**Files:** cipher.go, blindindex.go, search.go

Some methods panic on closed cipher (Seal, BlindIndex, BlindIndexes) while others return ErrCipherClosed (Open, SealWithKey, OpenWithKey, BlindIndexWithKey).

**Current inconsistency:**
```go
// Panics (cipher.go:128-130)
func (c *Cipher) Seal(plaintext []byte) []byte {
    if c.closed.Load() {
        panic("encryptedcol: use of closed Cipher")
    }

// Returns error (cipher.go:139-141)
func (c *Cipher) SealWithKey(keyID string, plaintext []byte) ([]byte, error) {
    if c.closed.Load() {
        return nil, ErrCipherClosed
    }
```

**PATCH (documentation clarification):**
```diff
--- a/cipher.go
+++ b/cipher.go
@@ -122,6 +122,9 @@ func New(opts ...Option) (*Cipher, error) {

 // Seal encrypts plaintext using the default key.
 // Returns ciphertext with embedded key_id, or nil if plaintext is nil (NULL preservation).
+//
+// Panics if called on a closed Cipher. Methods returning (value, error) return
+// ErrCipherClosed instead. The panic behavior matches Go's crypto library conventions.
 //
 // The ciphertext format is:
 // [flag:1][keyIDLen:1][keyID:n][nonce:24][secretbox(innerKeyID + plaintext)]
```

#### ISSUE-CODE-02: Unused Snappy Constant
**File:** format.go:19, compress.go:23-24

`flagSnappy` and `compressionAlgorithmSnappy` are defined but never used except in decompress error handling.

**PATCH:**
```diff
--- a/format.go
+++ b/format.go
@@ -16,7 +16,7 @@ const (
 	flagNoCompression byte = 0x00
 	flagZstd          byte = 0x01
-	flagSnappy        byte = 0x02
+	flagSnappy        byte = 0x02 // Reserved for future implementation

 	nonceSize = 24
 )
```

Note: This is actually documented in compress.go:118-120. No change needed.

#### ISSUE-CODE-03: config.keys Reference Leak After Zeroing
**File:** cipher.go:100

After zeroing master keys, the code sets `cfg.keys = nil` but the Cipher still holds a reference to `cfg` which could theoretically be inspected.

**Current code:**
```go
defer func() {
    for keyID := range cfg.keys {
        key := cfg.keys[keyID]
        for i := range key {
            key[i] = 0
        }
    }
    cfg.keys = nil // Clear reference to prevent accidental access
}()
// ... later ...
c := &Cipher{
    // ...
    config:    cfg, // cfg.keys is nil but cfg still accessible
}
```

**Analysis:** Low impact since cfg.keys is nil and derived keys are stored separately. The recent commit b70b067 documents this behavior.

---

## Test Coverage Analysis

**Coverage: 95.7%** - Excellent

### Test Strengths

1. **Comprehensive edge cases** - NULL handling, empty slices, unicode, binary data
2. **Security-focused tests**:
   - `TestOpen_TamperedKeyID` - header tampering detection
   - `TestOpen_InnerKeyIDMismatch` - key confusion attack prevention
   - `TestOpen_InvalidInnerPlaintext` - malformed payload handling
3. **Concurrent testing** - `TestSealOpen_Concurrent` with 100 goroutines
4. **Nonce uniqueness verification** - `TestGenerateNonce_Unique`
5. **SQL injection prevention tests** - `TestSearchCondition_InvalidColumnName`

### Test Gaps (Minor)

#### ISSUE-TEST-01: No Fuzz Testing
**Recommendation:** Add fuzz tests for parseFormat and parseInnerPlaintext to catch edge cases in format parsing.

**PATCH:**
```diff
--- /dev/null
+++ b/format_fuzz_test.go
@@ -0,0 +1,25 @@
+//go:build go1.18
+
+package encryptedcol
+
+import "testing"
+
+func FuzzParseFormat(f *testing.F) {
+	// Seed with valid ciphertexts
+	cipher, _ := New(WithKey("v1", testKey("v1")))
+	ct := cipher.Seal([]byte("test"))
+	f.Add(ct)
+	f.Add([]byte{})
+	f.Add([]byte{0x00, 0x02, 'v', '1'})
+
+	f.Fuzz(func(t *testing.T, data []byte) {
+		// Should not panic on any input
+		_, _, _, _, _ = parseFormat(data)
+	})
+}
+
+func FuzzParseInnerPlaintext(f *testing.F) {
+	f.Fuzz(func(t *testing.T, data []byte) {
+		_, _, _ = parseInnerPlaintext(data)
+	})
+}
```

#### ISSUE-TEST-02: No Benchmark Memory Profiling
**Recommendation:** Add memory allocation tracking to benchmarks.

**PATCH:**
```diff
--- a/benchmark_test.go
+++ b/benchmark_test.go
@@ -23,6 +23,7 @@ func init() {
 func BenchmarkSeal_100B(b *testing.B) {
 	data := []byte(strings.Repeat("x", 100))
+	b.ReportAllocs()
 	b.ResetTimer()
 	for i := 0; i < b.N; i++ {
 		benchCipher.Seal(data)
```

---

## Documentation Analysis

**Score: 10/10** - Excellent

### Strengths

1. **Comprehensive doc.go** with usage examples
2. **AGENTS.md anti-patterns section** prevents well-meaning "fixes" that would break security
3. **INTEGRATION_GUIDE.md** for real-world usage
4. **Inline code comments** explaining security decisions

### No Issues Identified

---

## Maintainability Analysis

### Issues

#### ISSUE-MAINT-01: No Linter Configuration
**Recommendation:** Add golangci-lint configuration for consistent code quality.

**PATCH:**
```diff
--- /dev/null
+++ b/.golangci.yml
@@ -0,0 +1,20 @@
+run:
+  timeout: 5m
+
+linters:
+  enable:
+    - govet
+    - staticcheck
+    - gosec
+    - errcheck
+    - ineffassign
+    - unused
+
+linters-settings:
+  gosec:
+    excludes:
+      - G104  # Unhandled errors (we use panic for crypto/rand)
+
+issues:
+  exclude-use-default: false
```

#### ISSUE-MAINT-02: Dead Code in New() (Line Never Reached)
**File:** cipher.go (conceptual - documented in test)

The test `TestNew_DefaultKeyID_AlwaysSetByWithKey` documents that a theoretical fallback for default key selection is dead code because WithKey always sets defaultKeyID. This is documented behavior per recent commits.

---

## Dependency Analysis

| Dependency | Version | Status | Notes |
|------------|---------|--------|-------|
| golang.org/x/crypto | v0.47.0 | Current | NaCl secretbox, HKDF |
| github.com/klauspost/compress | v1.18.3 | Current | Zstd compression |
| github.com/stretchr/testify | v1.11.1 | Current | Test assertions |

**No known vulnerabilities in dependencies.**

---

## Summary of Findings

### Critical Issues: 0
### High Severity: 0
### Medium Severity: 0
### Low Severity: 2

| ID | Severity | Category | Description |
|----|----------|----------|-------------|
| ISSUE-SEC-01 | Low | Security | No salt in HKDF (hardening suggestion) |
| ISSUE-CODE-01 | Low | Code Quality | Inconsistent panic vs error pattern |

### Informational: 4

| ID | Category | Description |
|----|----------|-------------|
| ISSUE-CODE-02 | Code Quality | Unused snappy constant (documented) |
| ISSUE-CODE-03 | Code Quality | config reference after zeroing (documented) |
| ISSUE-TEST-01 | Testing | No fuzz testing |
| ISSUE-MAINT-01 | Maintainability | No linter config |

---

## Conclusion

This is a **well-engineered cryptographic library** that follows security best practices. The codebase demonstrates:

- Strong understanding of applied cryptography
- Thoughtful API design for safe usage
- Comprehensive documentation preventing misuse
- Excellent test coverage

The identified issues are minor and mostly suggestions for hardening rather than actual vulnerabilities. The library is **suitable for production use** with the documented constraints (notably: blind indexes should only be used for high-entropy fields).

---

## Audit Metadata

- **Auditor:** Claude Opus 4.5 (claude-opus-4-5-20251101)
- **Audit Date:** 2026-01-28
- **Codebase Version:** Latest (commit c1c8340)
- **Go Version:** 1.24.0
- **Test Coverage:** 95.7%
- **Static Analysis:** go vet - no issues
