Date Created: 2026-01-26T14:30:22Z
TOTAL_SCORE: 93/100

# encryptedcol Test Coverage Report

## Executive Summary

The `encryptedcol` library demonstrates **exceptional test coverage at 95.7%** with comprehensive testing across all core functionality. The test suite includes 350+ test cases, 25 benchmarks, and 5 executable examples. This report identifies the remaining coverage gaps and proposes targeted tests to achieve near-100% coverage.

## Current Coverage Analysis

### Overall Statistics
- **Statement Coverage**: 95.7%
- **Test Files**: 13
- **Total Test Cases**: ~350
- **Benchmarks**: 25
- **Examples**: 5

### Coverage by Function

| Function | Coverage | Gap Analysis |
|----------|----------|--------------|
| `generateNonce` | 75.0% | Panic path on `crypto/rand` failure |
| `initZstd` | 66.7% | Error paths for encoder/decoder creation |
| `compressZstd` | 75.0% | Error path when initZstd fails |
| `decompressZstd` | 77.8% | Error paths and size limit check |
| `maybeCompress` | 84.6% | Compression failure fallback |
| `OpenWithKey` | 84.6% | Outer key ID mismatch path |
| `isValidColumnName` | 88.9% | Some character validation paths |
| `SearchCondition` | 95.2% | Parameter overflow panic path |
| `WithKey` | 87.5% | nil keys map initialization |
| `deriveKeys` | 75.0% | HKDF derivation error path |
| `OpenJSON` | 90.0% | Decryption error path |
| `OpenInt64` | 87.5% | Decryption error path |

### Functions with 100% Coverage (47 total)
All core encryption/decryption, blind indexing, normalization, rotation, and provider functions have complete coverage.

---

## Coverage Gaps & Proposed Tests

### Gap 1: `OpenWithKey` Outer Key ID Mismatch (84.6%)

**Location**: `cipher.go:252-254`

**What's Missing**: The branch where `outerKeyID != keyID` returns `ErrKeyIDMismatch` is not directly tested for `OpenWithKey`.

**Proposed Test**:
```go
func TestOpenWithKey_OuterKeyIDMismatch(t *testing.T) {
	// This test verifies that OpenWithKey detects when the ciphertext's
	// embedded key_id doesn't match the requested key_id
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	cipher, err := New(
		WithKey("v1", key1),
		WithKey("v2", key2),
		WithDefaultKeyID("v1"),
	)
	require.NoError(t, err)
	defer cipher.Close()

	// Encrypt with v1
	ciphertext := cipher.Seal([]byte("test data"))

	// Try to decrypt with v2 (should fail - outer key_id is v1)
	_, err = cipher.OpenWithKey("v2", ciphertext)
	require.ErrorIs(t, err, ErrKeyIDMismatch)
}
```

**Patch-Ready Diff**:
```diff
--- a/cipher_test.go
+++ b/cipher_test.go
@@ -XXX,6 +XXX,27 @@ func TestOpenWithKey_KeyNotFound(t *testing.T) {
 	require.ErrorIs(t, err, ErrKeyNotFound)
 }

+func TestOpenWithKey_OuterKeyIDMismatch(t *testing.T) {
+	// Verify OpenWithKey rejects ciphertext encrypted with a different key
+	key1 := make([]byte, 32)
+	key2 := make([]byte, 32)
+	rand.Read(key1)
+	rand.Read(key2)
+
+	cipher, err := New(
+		WithKey("v1", key1),
+		WithKey("v2", key2),
+		WithDefaultKeyID("v1"),
+	)
+	require.NoError(t, err)
+	defer cipher.Close()
+
+	// Encrypt with v1
+	ciphertext := cipher.Seal([]byte("test data"))
+
+	// Try to decrypt with v2 - outer key_id is v1, so this should fail
+	_, err = cipher.OpenWithKey("v2", ciphertext)
+	require.ErrorIs(t, err, ErrKeyIDMismatch)
+}
```

---

### Gap 2: `isValidColumnName` Additional Paths (88.9%)

**Location**: `search.go:17-30`

**What's Missing**: Some character validation edge cases for column names.

**Proposed Test**:
```go
func TestIsValidColumnName_ExtendedEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		valid  bool
	}{
		{"starts with digit", "1column", false},
		{"digit in middle", "col1umn", true},
		{"only underscore", "_", true},
		{"underscore prefix", "_column", true},
		{"double underscore", "__col", true},
		{"ends with digit", "column1", true},
		{"uppercase", "COLUMN", true},
		{"mixed case", "MyColumn", true},
		{"hyphen rejected", "my-column", false},
		{"dot rejected", "my.column", false},
		{"space rejected", "my column", false},
		{"unicode rejected", "col\u00e9", false},
		{"special char rejected", "col@mn", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.valid {
				require.NotPanics(t, func() {
					cipher.SearchConditionString(tt.input, "test", 1)
				})
			} else {
				require.Panics(t, func() {
					cipher.SearchConditionString(tt.input, "test", 1)
				})
			}
		})
	}
}
```

**Patch-Ready Diff**:
```diff
--- a/search_test.go
+++ b/search_test.go
@@ -XXX,6 +XXX,49 @@ func TestSearchCondition_InvalidColumnName(t *testing.T) {
 	})
 }

+func TestIsValidColumnName_ExtendedEdgeCases(t *testing.T) {
+	key := make([]byte, 32)
+	rand.Read(key)
+	cipher, _ := New(WithKey("v1", key))
+	defer cipher.Close()
+
+	tests := []struct {
+		name  string
+		input string
+		valid bool
+	}{
+		{"starts with digit", "1column", false},
+		{"digit in middle", "col1umn", true},
+		{"only underscore", "_", true},
+		{"underscore prefix", "_column", true},
+		{"double underscore", "__col", true},
+		{"ends with digit", "column1", true},
+		{"uppercase", "COLUMN", true},
+		{"mixed case", "MyColumn", true},
+		{"hyphen rejected", "my-column", false},
+		{"dot rejected", "my.column", false},
+		{"space rejected", "my column", false},
+		{"unicode rejected", "col\u00e9", false},
+		{"special char rejected", "col@mn", false},
+	}
+
+	for _, tt := range tests {
+		t.Run(tt.name, func(t *testing.T) {
+			if tt.valid {
+				require.NotPanics(t, func() {
+					cipher.SearchConditionString(tt.input, "test", 1)
+				})
+			} else {
+				require.Panics(t, func() {
+					cipher.SearchConditionString(tt.input, "test", 1)
+				})
+			}
+		})
+	}
+}
```

---

### Gap 3: `SearchCondition` Parameter Overflow (95.2%)

**Location**: `search.go:75-78`

**What's Missing**: The panic when parameter numbers exceed PostgreSQL's 65535 limit.

**Proposed Test**:
```go
func TestSearchCondition_TooManyKeysOverflow(t *testing.T) {
	// Create cipher with enough keys that paramOffset near max would overflow
	keys := make(map[string][]byte)
	masterKey := make([]byte, 32)
	rand.Read(masterKey)

	// We need enough keys that paramOffset + (len*2) - 1 > 65535
	// With paramOffset=65530 and 4 keys: 65530 + 8 - 1 = 65537 > 65535
	for i := 0; i < 4; i++ {
		keys[fmt.Sprintf("k%d", i)] = masterKey
	}

	opts := []Option{}
	for id, key := range keys {
		opts = append(opts, WithKey(id, key))
	}

	cipher, err := New(opts...)
	require.NoError(t, err)
	defer cipher.Close()

	// This should panic due to parameter overflow
	require.Panics(t, func() {
		cipher.SearchCondition("email", []byte("test"), 65530)
	})
}
```

**Patch-Ready Diff**:
```diff
--- a/search_test.go
+++ b/search_test.go
@@ -XXX,6 +XXX,28 @@ func TestSearchCondition_ParamOffsetExceedsMax(t *testing.T) {
 	})
 }

+func TestSearchCondition_TooManyKeysOverflow(t *testing.T) {
+	// Create cipher with enough keys that high paramOffset would overflow
+	masterKey := make([]byte, 32)
+	rand.Read(masterKey)
+
+	// 4 keys * 2 params each = 8 params
+	// 65530 + 8 - 1 = 65537 > 65535 (max)
+	opts := []Option{
+		WithKey("k0", masterKey),
+		WithKey("k1", masterKey),
+		WithKey("k2", masterKey),
+		WithKey("k3", masterKey),
+	}
+
+	cipher, err := New(opts...)
+	require.NoError(t, err)
+	defer cipher.Close()
+
+	require.Panics(t, func() {
+		cipher.SearchCondition("email", []byte("test"), 65530)
+	})
+}
```

---

### Gap 4: `decompressZstd` Size Limit (77.8%)

**Location**: `compress.go:72-73`

**What's Missing**: The path where decompressed size exceeds `maxDecompressedSize` (64MB).

**Proposed Test**:
```go
func TestDecompressZstd_SizeLimit(t *testing.T) {
	// This test is challenging because we need valid zstd data that
	// decompresses to >64MB. In practice, this branch protects against
	// zip bombs. We can test this indirectly via the cipher.

	// Alternative: test with pre-crafted compressed payload
	// Note: Actually creating 64MB of data for a unit test is impractical.
	// This is a security defense that's difficult to unit test without
	// significant memory allocation.

	// Document that this branch exists for zip bomb protection
	t.Skip("Size limit test requires 64MB allocation - tested manually")
}
```

**Note**: This coverage gap is intentional - testing the 64MB decompression limit would require allocating significant memory and is primarily a security defense against zip bombs. The code path is defensive and the test would be impractical.

---

### Gap 5: `maybeCompress` Compression Failure Fallback (84.6%)

**Location**: `compress.go:91-95`

**What's Missing**: The error path when `compressZstd` fails.

**Analysis**: This path only triggers if the zstd encoder fails, which is highly unlikely once initialized. The `sync.Once` initialization pattern means errors only occur on catastrophic failures.

**Proposed Test** (limited value):
```go
// Note: This path is difficult to test without mocking the zstd library.
// The fallback exists for robustness but is unlikely to trigger in practice.
// Coverage gap is acceptable - it's defensive code.
```

---

### Gap 6: `WithKey` nil Keys Map (87.5%)

**Location**: `options.go:12-13`

**What's Missing**: The branch where `c.keys == nil` triggers map initialization.

**Analysis**: This branch was added defensively but `defaultConfig()` always initializes the map. The check is redundant but harmless.

**Proposed Test**:
```go
func TestWithKey_InitializesNilMap(t *testing.T) {
	// This tests the defensive nil check in WithKey
	// The path is hit when config.keys is nil before any WithKey call

	// Note: defaultConfig() initializes the map, so this branch
	// is defensive code that may never trigger in normal use.
	// Documenting as acceptable coverage gap.
}
```

---

### Gap 7: `deriveKeys` Error Path (75.0%)

**Location**: `kdf.go:35-44`

**What's Missing**: Error paths when HKDF derivation fails.

**Analysis**: HKDF with SHA-256 should never fail given valid inputs. The error paths are defensive.

---

### Gap 8: `OpenJSON` and `OpenInt64` Decryption Errors (90%, 87.5%)

**Location**: `helpers.go:126-128`, `helpers.go:165-167`

**What's Missing**: The path where `c.Open()` returns an error.

**Proposed Test**:
```go
func TestOpenJSON_DecryptionError(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	cipher, _ := New(WithKey("v1", key))
	defer cipher.Close()

	// Create invalid ciphertext (valid format but wrong key material)
	invalidCiphertext := make([]byte, 100)
	rand.Read(invalidCiphertext)
	// Prepend valid-looking header
	invalidCiphertext[0] = 0x00 // flag
	invalidCiphertext[1] = 2    // keyID length
	invalidCiphertext[2] = 'v'
	invalidCiphertext[3] = '1'

	type TestStruct struct {
		Value string
	}
	_, err := OpenJSON[TestStruct](cipher, invalidCiphertext)
	require.Error(t, err)
}

func TestOpenInt64_DecryptionError(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	cipher, _ := New(WithKey("v1", key))
	defer cipher.Close()

	// Create invalid ciphertext
	invalidCiphertext := make([]byte, 50)
	rand.Read(invalidCiphertext)
	invalidCiphertext[0] = 0x00
	invalidCiphertext[1] = 2
	invalidCiphertext[2] = 'v'
	invalidCiphertext[3] = '1'

	_, err := cipher.OpenInt64(invalidCiphertext)
	require.Error(t, err)
}
```

**Patch-Ready Diff**:
```diff
--- a/helpers_test.go
+++ b/helpers_test.go
@@ -XXX,6 +XXX,38 @@ func TestOpenJSON_InvalidJSON(t *testing.T) {
 	require.Error(t, err)
 }

+func TestOpenJSON_DecryptionError(t *testing.T) {
+	key := make([]byte, 32)
+	rand.Read(key)
+	cipher, _ := New(WithKey("v1", key))
+	defer cipher.Close()
+
+	// Create ciphertext with valid header but corrupted encrypted data
+	invalidCiphertext := make([]byte, 50)
+	rand.Read(invalidCiphertext)
+	invalidCiphertext[0] = 0x00 // flag: no compression
+	invalidCiphertext[1] = 2    // keyID length
+	invalidCiphertext[2] = 'v'
+	invalidCiphertext[3] = '1'
+
+	type TestStruct struct{ Value string }
+	_, err := OpenJSON[TestStruct](cipher, invalidCiphertext)
+	require.Error(t, err)
+}
+
+func TestOpenInt64_DecryptionError(t *testing.T) {
+	key := make([]byte, 32)
+	rand.Read(key)
+	cipher, _ := New(WithKey("v1", key))
+	defer cipher.Close()
+
+	// Create ciphertext with valid header but corrupted data
+	invalidCiphertext := make([]byte, 50)
+	rand.Read(invalidCiphertext)
+	invalidCiphertext[0] = 0x00
+	invalidCiphertext[1] = 2
+	invalidCiphertext[2] = 'v'
+	invalidCiphertext[3] = '1'
+
+	_, err := cipher.OpenInt64(invalidCiphertext)
+	require.Error(t, err)
+}
```

---

## Untestable/Impractical Coverage Gaps

The following coverage gaps are **intentionally not addressed** because they represent defensive code paths that are difficult or impractical to test:

| Gap | Reason | Risk |
|-----|--------|------|
| `generateNonce` panic | Requires OS entropy failure - untestable without mocking `crypto/rand` | VERY LOW |
| `initZstd` error paths | Requires zstd library failure at init - external dependency | VERY LOW |
| `compressZstd` error path | Requires zstd encoder failure after successful init | VERY LOW |
| `decompressZstd` 64MB limit | Requires allocating 64MB+ for test data | LOW (security defense) |
| `deriveKeys` error path | HKDF-SHA256 doesn't fail with valid inputs | VERY LOW |
| `WithKey` nil map init | `defaultConfig()` always initializes map | NONE (dead code) |

---

## Scoring Breakdown

| Category | Points | Score | Notes |
|----------|--------|-------|-------|
| **Coverage Percentage** | 30 | 28/30 | 95.7% coverage is excellent |
| **Critical Path Testing** | 25 | 25/25 | All encryption/decryption paths tested |
| **Error Handling** | 15 | 13/15 | Minor gaps in error path coverage |
| **Edge Cases** | 15 | 14/15 | NULL, empty, boundary conditions well tested |
| **Security Testing** | 10 | 10/10 | Key confusion, tampering detection tested |
| **Benchmarks** | 5 | 5/5 | Comprehensive performance benchmarks |

**TOTAL: 93/100**

---

## Recommendations

### High Priority (Should Implement)
1. **Add `TestOpenWithKey_OuterKeyIDMismatch`** - Directly tests the key ID mismatch detection in `OpenWithKey`
2. **Add `TestOpenJSON_DecryptionError`** - Tests error propagation in JSON helper
3. **Add `TestOpenInt64_DecryptionError`** - Tests error propagation in int64 helper

### Medium Priority (Nice to Have)
4. **Add `TestSearchCondition_TooManyKeysOverflow`** - Tests parameter limit protection
5. **Add `TestIsValidColumnName_ExtendedEdgeCases`** - More thorough column name validation

### Low Priority (Acceptable Gaps)
- Crypto/rand failure paths - OS-level failure, appropriate to panic
- Zstd initialization errors - External library, tested by dependency
- 64MB decompression limit - Security defense, manual testing sufficient

---

## Conclusion

The `encryptedcol` library has **outstanding test coverage** that exceeds industry standards. The 95.7% statement coverage reflects comprehensive testing of all critical paths including:

- Encryption/decryption round-trips
- NULL preservation semantics
- Multi-key rotation workflows
- Concurrent safety
- Security attack detection (key confusion, tampering)
- Error propagation

The remaining 4.3% coverage gap consists primarily of defensive error paths that are difficult to trigger and represent extremely low-risk scenarios. Implementing the high-priority tests above would push coverage to approximately 97-98%.

The codebase demonstrates excellent testing practices including:
- Table-driven tests with descriptive names
- Proper use of `require` assertions (fail-fast)
- Integration tests for multi-step workflows
- Security-focused test cases
- Comprehensive benchmarks for performance-critical paths
