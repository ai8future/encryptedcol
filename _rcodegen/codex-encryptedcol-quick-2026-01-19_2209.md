Date Created: 2026-01-19 22:09:05 +0100
TOTAL_SCORE: 93/100

## 1) AUDIT - Security and code quality issues with PATCH-READY DIFFS

Finding A1 (Code quality - doc mismatch): `WithCompressionAlgorithm` advertises snappy support but the implementation rejects it with `ErrUnsupportedCompression`. This is misleading and can cause user confusion.

Patch (update the option docstring to match behavior):
```diff
diff --git a/options.go b/options.go
index 8d5a9ef..b6e0a5a 100644
--- a/options.go
+++ b/options.go
@@ -38,7 +38,7 @@ func WithCompressionThreshold(bytes int) Option {
 }
 
 // WithCompressionAlgorithm sets the compression algorithm to use.
-// Supported values: "zstd" (default), "snappy".
+// Supported values: "zstd" (default). "snappy" is reserved but not implemented.
 func WithCompressionAlgorithm(algo string) Option {
 	return func(c *config) {
 		c.compressionAlgorithm = algo
 	}
 }
```

## 2) TESTS - Proposed unit tests for untested code with PATCH-READY DIFFS

Finding T1: `SearchCondition` panics on invalid `paramOffset`, but there is no test coverage for this guard.

Patch (add invalid `paramOffset` panic test):
```diff
diff --git a/search_test.go b/search_test.go
index 2e7c9ef..6d2f4b1 100644
--- a/search_test.go
+++ b/search_test.go
@@ -151,6 +151,20 @@ func TestSearchCondition_InvalidColumnName(t *testing.T) {
 	}
 }
 
+func TestSearchCondition_InvalidParamOffset(t *testing.T) {
+	cipher, _ := New(WithKey("v1", testKey("v1")))
+
+	require.Panics(t, func() {
+		cipher.SearchCondition("email", []byte("test@example.com"), 0)
+	})
+
+	require.Panics(t, func() {
+		cipher.SearchCondition("email", []byte("test@example.com"), -1)
+	})
+}
+
 func TestSearchCondition_ValidColumnNames(t *testing.T) {
 	cipher, _ := New(WithKey("v1", testKey("v1")))
 
 	validNames := []string{
@@ -164,6 +178,6 @@ func TestSearchCondition_ValidColumnNames(t *testing.T) {
 		}
 	}
 }
```

Finding T2: Sentinel error tests omit `ErrInvalidKeyID` and `ErrUnsupportedCompression`, leaving them unverified for identity and message consistency.

Patch (extend error tests to include missing errors):
```diff
diff --git a/errors_test.go b/errors_test.go
index 8b4a3c2..02cb0c6 100644
--- a/errors_test.go
+++ b/errors_test.go
@@ -16,6 +16,8 @@ func TestErrors_Identity(t *testing.T) {
 		ErrDecompressionFailed,
 		ErrInvalidFormat,
 		ErrNoKeys,
 		ErrDefaultKeyNotFound,
+		ErrInvalidKeyID,
+		ErrUnsupportedCompression,
 	}
@@ -38,6 +40,8 @@ func TestErrors_Messages(t *testing.T) {
 		{"ErrDecompressionFailed", ErrDecompressionFailed, "decompression failed"},
 		{"ErrInvalidFormat", ErrInvalidFormat, "invalid ciphertext format"},
 		{"ErrNoKeys", ErrNoKeys, "no keys"},
 		{"ErrDefaultKeyNotFound", ErrDefaultKeyNotFound, "default key not found"},
+		{"ErrInvalidKeyID", ErrInvalidKeyID, "key ID"},
+		{"ErrUnsupportedCompression", ErrUnsupportedCompression, "unsupported compression"},
 	}
```

## 3) FIXES - Bugs, issues, and code smells with fixes and PATCH-READY DIFFS

Finding F1 (Behavior consistency): `SearchConditionNormalized` bypasses column name and `paramOffset` validation when `plaintext` is nil. This makes behavior inconsistent with `SearchCondition` and can hide invalid inputs.

Patch (delegate to `SearchCondition` for nil input so validation is preserved):
```diff
diff --git a/search.go b/search.go
index 5a0e0f7..b4f2f10 100644
--- a/search.go
+++ b/search.go
@@ -92,13 +92,10 @@ func (c *Cipher) SearchConditionStringNormalized(column string, plaintext string
 func (c *Cipher) SearchConditionNormalized(column string, plaintext []byte, paramOffset int, norm Normalizer) *SearchCondition {
 	if plaintext == nil {
-		return &SearchCondition{
-			SQL:  "FALSE",
-			Args: nil,
-		}
+		return c.SearchCondition(column, nil, paramOffset)
 	}
 	normalized := norm(string(plaintext))
 	return c.SearchCondition(column, []byte(normalized), paramOffset)
 }
```

## 4) REFACTOR - Opportunities to improve code quality (no diffs needed)

- Consider adding a non-panicking search API (e.g., `SearchConditionSafe` returning `(*SearchCondition, error)`) to avoid DoS risk if column names or offsets ever originate from untrusted input.
- Consolidate compression algorithm identifiers and flags into a single enum-like mapping to avoid future drift between format flags and option strings.
- Add lightweight benchmarks for `SearchCondition` and blind indexing paths to capture any regressions in the hot search and hashing flows.
- Consider a small comment in `compress.go` on thread-safe reuse for zstd encoder/decoder to align with the concurrency expectation and reduce future questions.
