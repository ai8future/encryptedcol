Date Created: Monday, January 19, 2026 21:30:00
TOTAL_SCORE: 98/100

# Audit Report: encryptedcol

## 1. Overview
The `encryptedcol` package demonstrates excellent code quality and high test coverage (95.1%). The API is clean, idiomatic, and well-documented. The encryption scheme (Secretbox + HMAC blind indexing) is implemented securely using standard libraries.

## 2. Coverage Analysis
Existing tests cover the vast majority of success and error paths. A few edge cases and defensive panic conditions remain untested:

*   **`helpers.go`**:
    *   `OpenJSON`: Logic for handling `json.Unmarshal` errors on decrypted data is not explicitly tested.
    *   `OpenInt64`: Logic for validating the length of the decrypted data (must be 8 bytes) is not explicitly tested.
*   **`cipher.go`**:
    *   `OpenWithKey`: The `nil` ciphertext check (NULL preservation) is not covered.
    *   `decompress`: The default case handling invalid compression flags is not reachable via standard tests.
*   **`search.go`**:
    *   `SearchCondition`: Validation panics (invalid column name, invalid param offset) are not tested.
    *   `isValidColumnName`: The empty string case is not tested.

## 3. Proposed Test Coverage
The following patch introduces `coverage_gap_test.go` to target these specific areas, aiming to raise coverage to ~98%.

### Patch

```diff
diff --git a/coverage_gap_test.go b/coverage_gap_test.go
new file mode 100644
index 0000000..e69de29
--- /dev/null
+++ b/coverage_gap_test.go
@@ -0,0 +1,67 @@
+package encryptedcol
+
+import (
+	"testing"
+)
+
+// TestCoverage_Gaps targets specific edge cases identified in the audit
+// to improve overall package coverage.
+func TestCoverage_Gaps(t *testing.T) {
+	key := make([]byte, 32)
+	c, err := New(WithKey("k1", key))
+	if err != nil {
+		t.Fatal(err)
+	}
+
+	// 1. Helpers: OpenJSON with valid ciphertext but invalid JSON content
+	t.Run("OpenJSON_UnmarshalError", func(t *testing.T) {
+		// Seal something that isn't JSON
+		enc := c.Seal([]byte("not valid json"))
+		_, err := OpenJSON[map[string]any](c, enc)
+		if err == nil {
+			t.Error("OpenJSON should fail on invalid JSON content")
+		}
+	})
+
+	// 2. Helpers: OpenInt64 with valid ciphertext but wrong length
+	t.Run("OpenInt64_WrongLength", func(t *testing.T) {
+		// Int64 requires 8 bytes, seal 3 bytes instead
+		enc := c.Seal([]byte{1, 2, 3})
+		_, err := c.OpenInt64(enc)
+		if err != ErrInvalidFormat {
+			t.Errorf("OpenInt64: expected ErrInvalidFormat, got %v", err)
+		}
+	})
+
+	// 3. Cipher: OpenWithKey with nil ciphertext (NULL preservation)
+	t.Run("OpenWithKey_Nil", func(t *testing.T) {
+		res, err := c.OpenWithKey("k1", nil)
+		if err != nil || res != nil {
+			t.Error("OpenWithKey(nil) should return nil, nil")
+		}
+	})
+
+	// 4. Compress: Invalid flag in ciphertext (triggers decompress default case)
+	t.Run("Decompress_InvalidFlag", func(t *testing.T) {
+		enc := c.Seal([]byte("data"))
+		// Corrupt the flag byte (index 0) to an unknown value
+		enc[0] = 0xFF
+		_, err := c.Open(enc)
+		if err != ErrInvalidFormat {
+			t.Errorf("Open with invalid flag: expected ErrInvalidFormat, got %v", err)
+		}
+	})
+
+	// 5. Search: SearchCondition panics
+	t.Run("SearchCondition_Panics", func(t *testing.T) {
+		defer func() {
+			if r := recover(); r == nil {
+				t.Error("SearchCondition should panic on empty/invalid column")
+			}
+		}()
+		// Empty column name is invalid
+		c.SearchCondition("", []byte("val"), 1)
+	})
+
+	t.Run("SearchCondition_ParamOffset_Panic", func(t *testing.T) {
+		defer func() {
+			if r := recover(); r == nil {
+				t.Error("SearchCondition should panic on invalid paramOffset")
+			}
+		}()
+		// Param offset must be >= 1
+		c.SearchCondition("col", []byte("val"), 0)
+	})
+}
```
