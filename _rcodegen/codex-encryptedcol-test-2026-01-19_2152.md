Date Created: 2026-01-19 21:52:06 +0100
Date Updated: 2026-01-26 (Review complete: valuable tests implemented, low-value tests skipped)
TOTAL_SCORE: 93/100

**Overview**
- Coverage snapshot: `go test -coverprofile /tmp/encryptedcol_coverage.out ./...` reports 95.2% statements; remaining gaps are mostly defensive error paths.
- Strong baseline coverage across core encryption/search flows; missing tests are narrowly scoped to failure handling and guard rails.
- Several branches are effectively unreachable without test seams (noted below).

**Untested Areas - Review 2026-01-26**
- `cipher.go:182` parseInnerPlaintext error - ✅ IMPLEMENTED as TestOpen_InvalidInnerPlaintext
- `cipher.go:187` inner key ID mismatch - ✅ IMPLEMENTED as TestOpen_InnerKeyIDMismatch
- `cipher.go:224`, `cipher.go:230`, `cipher.go:239` OpenWithKey paths - ✅ ALREADY TESTED (TestOpenWithKey_KeyNotFound, TestOpen_InvalidFormat)
- `cipher.go:276` nonce generation panic - ❌ LOW VALUE (requires mocking crypto/rand.Reader)
- `compress.go` zstd init failure paths - ❌ LOW VALUE (requires test seam manipulation)
- `helpers.go` OpenJSON/OpenInt64 decrypt errors - ✅ ALREADY TESTED
- `options.go:12` WithKey nil config - ❌ LOW VALUE (never happens in normal usage)
- `search.go` invalid column/offset - ✅ ALREADY TESTED (TestSearchCondition_InvalidColumnName, TestSearchCondition_InvalidParamOffset)
- `search.go:75` internal panic - ❌ UNREACHABLE (requires internal state corruption)
- `kdf.go` deriveKeys error branches - ❌ UNREACHABLE (without a seam)

**Proposed Tests - Review 2026-01-26**
- `cipher_test.go`: ✅ Inner key ID mismatch and invalid inner plaintext IMPLEMENTED
- `compress_test.go`: ❌ Zstd init errors require test seam manipulation - LOW VALUE
- `helpers_test.go`: ✅ ALREADY TESTED
- `options_test.go`: ❌ nil config map never happens in practice - LOW VALUE
- `search_test.go`: ✅ ALREADY TESTED
- Unreachable branches: Not worth the complexity to add test seams

**Patch-Ready Diffs**
- **cipher_test.go**
```diff
diff --git a/cipher_test.go b/cipher_test.go
--- a/cipher_test.go
+++ b/cipher_test.go
@@ -2,11 +2,14 @@
 
 import (
 	"bytes"
+	"crypto/rand"
+	"errors"
 	"strings"
 	"sync"
 	"testing"
 
 	"github.com/stretchr/testify/require"
+	"golang.org/x/crypto/nacl/secretbox"
 )
@@ -208,6 +211,58 @@
 	}
 }
 
+func TestOpen_InvalidInnerPlaintext(t *testing.T) {
+	cipher, _ := New(WithKey("v1", testKey("v1")))
+
+	keys := cipher.keys["v1"]
+	nonce := [24]byte{}
+	invalidInner := []byte{0x00}
+	encrypted := secretbox.Seal(nil, invalidInner, &nonce, &keys.encryption)
+	ciphertext := formatCiphertext(flagNoCompression, "v1", nonce, encrypted)
+
+	_, err := cipher.Open(ciphertext)
+	require.ErrorIs(t, err, ErrInvalidFormat)
+}
+
+func TestOpen_InnerKeyIDMismatch(t *testing.T) {
+	cipher, _ := New(WithKey("v1", testKey("v1")))
+
+	keys := cipher.keys["v1"]
+	nonce := [24]byte{}
+	innerPlaintext := formatInnerPlaintext("v2", []byte("test"))
+	encrypted := secretbox.Seal(nil, innerPlaintext, &nonce, &keys.encryption)
+	ciphertext := formatCiphertext(flagNoCompression, "v1", nonce, encrypted)
+
+	_, err := cipher.Open(ciphertext)
+	require.ErrorIs(t, err, ErrKeyIDMismatch)
+}
+
+func TestOpenWithKey_Success(t *testing.T) {
+	cipher, _ := New(WithKey("v1", testKey("v1")))
+
+	ciphertext, err := cipher.SealWithKey("v1", []byte("test"))
+	require.NoError(t, err)
+
+	plaintext, err := cipher.OpenWithKey("v1", ciphertext)
+	require.NoError(t, err)
+	require.Equal(t, []byte("test"), plaintext)
+}
+
+func TestOpenWithKey_KeyNotFound(t *testing.T) {
+	cipher, _ := New(WithKey("v1", testKey("v1")))
+
+	ciphertext := cipher.Seal([]byte("test"))
+	_, err := cipher.OpenWithKey("missing", ciphertext)
+	require.ErrorIs(t, err, ErrKeyNotFound)
+}
+
+func TestOpenWithKey_InvalidFormat(t *testing.T) {
+	cipher, _ := New(WithKey("v1", testKey("v1")))
+
+	_, err := cipher.OpenWithKey("v1", []byte{0x00})
+	require.ErrorIs(t, err, ErrInvalidFormat)
+}
+
 func TestOpenWithKey_Mismatch(t *testing.T) {
 	cipher, _ := New(
 		WithKey("v1", testKey("v1")),
@@ -399,6 +454,24 @@
 	require.ErrorIs(t, err, ErrUnsupportedCompression)
 }
 
+type errReader struct{}
+
+func (errReader) Read(_ []byte) (int, error) {
+	return 0, errors.New("boom")
+}
+
+func TestGenerateNonce_RandFailure(t *testing.T) {
+	original := rand.Reader
+	rand.Reader = errReader{}
+	t.Cleanup(func() {
+		rand.Reader = original
+	})
+
+	require.PanicsWithValue(t, "crypto/rand failed: boom", func() {
+		_ = generateNonce()
+	})
+}
+
 func TestActiveKeyIDs_Sorted(t *testing.T) {
 	cipher, err := New(
 		WithKey("charlie", testKey("charlie")),
```
- **compress_test.go**
```diff
diff --git a/compress_test.go b/compress_test.go
--- a/compress_test.go
+++ b/compress_test.go
@@ -2,6 +2,8 @@
 
 import (
 	"bytes"
+	"errors"
+	"math/rand"
 	"strings"
 	"sync"
 	"testing"
@@ -9,6 +11,30 @@
 	"github.com/stretchr/testify/require"
 )
 
+func withZstdInitError(t *testing.T, err error) {
+	t.Helper()
+
+	origEncoder := zstdEncoder
+	origDecoder := zstdDecoder
+	origErr := zstdErr
+	origOnce := zstdOnce
+
+	zstdEncoder = nil
+	zstdDecoder = nil
+	zstdErr = err
+	zstdOnce = sync.Once{}
+	zstdOnce.Do(func() {
+		zstdErr = err
+	})
+
+	t.Cleanup(func() {
+		zstdEncoder = origEncoder
+		zstdDecoder = origDecoder
+		zstdErr = origErr
+		zstdOnce = origOnce
+	})
+}
+
 func TestCompressZstd_RoundTrip(t *testing.T) {
 	tests := []struct {
 		name string
@@ -44,6 +70,33 @@
 	require.Less(t, len(compressed), len(data)/2, "compression should reduce size by at least 50%")
 }
 
+func TestCompressZstd_InitError(t *testing.T) {
+	initErr := errors.New("zstd init failed")
+	withZstdInitError(t, initErr)
+
+	_, err := compressZstd([]byte("data"))
+	require.ErrorIs(t, err, initErr)
+}
+
+func TestDecompressZstd_InitError(t *testing.T) {
+	initErr := errors.New("zstd init failed")
+	withZstdInitError(t, initErr)
+
+	_, err := decompressZstd([]byte("data"))
+	require.ErrorIs(t, err, initErr)
+}
+
+func TestMaybeCompress_ZstdInitError(t *testing.T) {
+	initErr := errors.New("zstd init failed")
+	withZstdInitError(t, initErr)
+
+	data := []byte(strings.Repeat("hello world ", 200))
+	result, flag := maybeCompress(data, 1, compressionAlgorithmZstd, false)
+
+	require.Equal(t, flagNoCompression, flag)
+	require.True(t, bytes.Equal(data, result))
+}
+
 func TestMaybeCompress_BelowThreshold(t *testing.T) {
 	data := []byte("small")
 	threshold := 1024
@@ -92,6 +145,17 @@
 	}
 }
 
+func TestMaybeCompress_InsufficientSavings_Deterministic(t *testing.T) {
+	rng := rand.New(rand.NewSource(1))
+	data := make([]byte, 4096)
+	_, _ = rng.Read(data)
+
+	result, flag := maybeCompress(data, 1, compressionAlgorithmZstd, false)
+
+	require.Equal(t, flagNoCompression, flag)
+	require.True(t, bytes.Equal(data, result))
+}
+
 func TestMaybeCompress_UnsupportedAlgorithm(t *testing.T) {
 	data := []byte(strings.Repeat("hello ", 500))
```
- **helpers_test.go**
```diff
diff --git a/helpers_test.go b/helpers_test.go
--- a/helpers_test.go
+++ b/helpers_test.go
@@ -278,6 +278,21 @@
 	ciphertext := cipher.Seal([]byte("not valid json"))
 	_, err := OpenJSON[map[string]any](cipher, ciphertext)
 	require.Error(t, err)
+}
+
+func TestOpenJSON_DecryptionError(t *testing.T) {
+	cipher1, _ := New(WithKey("v1", testKey("v1")))
+	cipher2, _ := New(WithKey("v2", testKey("v2")))
+
+	type TestData struct {
+		Name string `json:"name"`
+	}
+
+	ciphertext, err := SealJSON(cipher1, TestData{Name: "test"})
+	require.NoError(t, err)
+
+	_, err = OpenJSON[TestData](cipher2, ciphertext)
+	require.ErrorIs(t, err, ErrKeyNotFound)
 }
 
 func TestSealJSONIndexed_MarshalError(t *testing.T) {
@@ -296,6 +311,15 @@
 	require.ErrorIs(t, err, ErrInvalidFormat)
 }
 
+func TestOpenInt64_DecryptionError(t *testing.T) {
+	cipher1, _ := New(WithKey("v1", testKey("v1")))
+	cipher2, _ := New(WithKey("v2", testKey("v2")))
+
+	ciphertext := cipher1.SealInt64(42)
+	_, err := cipher2.OpenInt64(ciphertext)
+	require.ErrorIs(t, err, ErrKeyNotFound)
+}
+
 func TestOpenString_InvalidCiphertext(t *testing.T) {
 	cipher, _ := New(WithKey("v1", testKey("v1")))
```
- **options_test.go**
```diff
diff --git a/options_test.go b/options_test.go
--- a/options_test.go
+++ b/options_test.go
@@ -14,6 +14,16 @@
 	require.Equal(t, "v1", cipher.DefaultKeyID())
 }
 
+func TestWithKey_InitializesNilConfig(t *testing.T) {
+	cfg := &config{}
+	opt := WithKey("v1", testKey("v1"))
+	opt(cfg)
+
+	require.NotNil(t, cfg.keys)
+	require.Len(t, cfg.keys, 1)
+	require.Equal(t, "v1", cfg.defaultKeyID)
+}
+
 func TestWithKey_Multiple(t *testing.T) {
 	cipher, err := New(
 		WithKey("v1", testKey("v1")),
```
- **search_test.go**
```diff
diff --git a/search_test.go b/search_test.go
--- a/search_test.go
+++ b/search_test.go
@@ -45,6 +45,25 @@
 	require.Equal(t, "(key_id = $3 AND email_idx = $4)", cond.SQL)
 }
 
+func TestSearchCondition_InvalidParamOffset(t *testing.T) {
+	cipher, _ := New(WithKey("v1", testKey("v1")))
+
+	tests := []struct {
+		name   string
+		offset int
+	}{
+		{"zero", 0},
+		{"negative", -1},
+	}
+	for _, tt := range tests {
+		t.Run(tt.name, func(t *testing.T) {
+			require.Panics(t, func() {
+				cipher.SearchCondition("email", []byte("test@example.com"), tt.offset)
+			})
+		})
+	}
+}
+
 func TestSearchCondition_ParamOffset_MultiKey(t *testing.T) {
 	cipher, _ := New(
 		WithKey("v1", testKey("v1")),
@@ -173,6 +192,7 @@
 		name   string
 		column string
 	}{
+		{"leading digit", "1email"},
 		{"sql injection", "email; DROP TABLE users; --"},
 		{"empty", ""},
 		{"special chars", "email$1"},
```
