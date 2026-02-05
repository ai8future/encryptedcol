# Comprehensive Unit Test Analysis for encryptedcol

**Date Created:** 2026-01-21 22:36 UTC
**Date Updated:** 2026-01-26 (Review complete: security-critical tests added)

## Implementation Status

The following test gaps have been implemented:

| ID | Status | Notes |
|----|--------|-------|
| G1 | ✅ Implemented | `TestOpenWithKey_KeyNotFound` added to cipher_test.go |
| G2 | ✅ Implemented | `TestSearchCondition_InvalidParamOffset` and `TestSearchCondition_MaxParamOverflow` added to search_test.go |
| G5 | ✅ Implemented | `TestOpenJSON_TypeMismatch` and `TestOpenJSON_StructFieldMismatch` added to helpers_test.go |
| G6 | ✅ Implemented | `TestClose_UseAfterClose` added to cipher_test.go |
| G12 | ✅ Implemented | `TestStaticKeyProvider_ActiveKeyIDs_Sorted` and `TestStaticKeyProvider_Close` added to provider_test.go |
| G15 | ✅ Implemented | Updated `TestErrors_Identity` and `TestErrors_Messages` to include all 12 errors |
| G21 | ✅ Implemented | `TestNew_DefaultKeySelection_FirstRegistered` added to cipher_test.go (note: first-registered, not alphabetical) |

**New tests added 2026-01-26:**
- `TestOpen_InnerKeyIDMismatch` - Security-critical test for key confusion attack defense
- `TestOpen_InvalidInnerPlaintext` - Tests malformed decrypted payload handling

Tests skipped as low-value or already covered:
- G3, G7, G8, G9, G10, G11, G14, G16, G17, G18, G19, G20, G22, G23: Dead weight or already covered by existing tests

---

## Executive Summary

This report analyzes the `encryptedcol` Go library for client-side encrypted columns in PostgreSQL/Supabase. After thorough code review, I identified **23 untested edge cases and scenarios** across the codebase. The existing test suite is well-structured with 144+ unit tests, but gaps exist in error path coverage, boundary conditions, and some concurrent scenarios.

---

## Table of Contents

1. [Test Coverage Overview](#test-coverage-overview)
2. [Identified Test Gaps](#identified-test-gaps)
3. [Proposed Tests with Patch-Ready Diffs](#proposed-tests-with-patch-ready-diffs)
4. [Priority Matrix](#priority-matrix)

---

## Test Coverage Overview

### Current Test Statistics
| File | Tests | Coverage Areas |
|------|-------|----------------|
| cipher_test.go | 28 | Core encryption/decryption, NULL handling, multi-key |
| blindindex_test.go | 13 | HMAC indexing, determinism, key separation |
| search_test.go | 15 | SQL generation, column validation |
| helpers_test.go | 21 | Type-safe wrappers, JSON, int64 |
| normalize_test.go | 8 | All normalizer functions |
| format_test.go | 7 | Ciphertext format round-trips |
| kdf_test.go | 9 | Key derivation, test vectors |
| compress_test.go | 13 | Zstd compression, thresholds |
| options_test.go | 11 | Functional options |
| provider_test.go | 6 | KeyProvider interface |
| rotate_test.go | 14 | Key rotation workflows |
| errors_test.go | 3 | Error identity and messages |

### Well-Tested Areas
- Core Seal/Open round-trips
- NULL preservation throughout
- Multi-key scenarios
- Compression thresholds and savings checks
- Column name SQL injection prevention
- Key rotation complete workflows

---

## Identified Test Gaps

### High Priority (Security/Correctness Impact)

| ID | File | Gap Description | Risk | Status |
|----|------|-----------------|------|--------|
| G1 | cipher.go | `OpenWithKey` with non-existent key before format parsing | Medium | ✅ Done |
| G2 | search.go | `SearchCondition` panic behavior with paramOffset=0 | Medium | ✅ Done |
| G3 | format.go | Max-length keyID (255 bytes) round-trip verification | Medium | ✅ Covered by TestNew_InvalidKeyID_MaxLength |
| G4 | compress.go | Concurrent `initZstd` race condition (sync.Once correctness) | Low | ❌ Low value |
| G5 | helpers.go | `OpenJSON` with valid JSON but wrong target type | Medium | ✅ Done |

### Medium Priority (Edge Cases)

| ID | File | Gap Description | Status |
|----|------|-----------------|--------|
| G6 | cipher.go | Close() then attempt operations (use-after-close) | ✅ Done |
| G7 | blindindex.go | `BlindIndexes` with single key returns correct structure | ❌ Low value |
| G8 | helpers.go | `SealInt64` boundary values (-1, 0) with compression enabled | ❌ Low value |
| G9 | options.go | `WithCompressionThreshold(0)` - always compress | ❌ Low value |
| G10 | options.go | `WithCompressionThreshold(-1)` - negative value handling | ❌ Low value |
| G11 | rotate.go | `RotateValue` when already using default key (no-op verification) | ❌ Low value |
| G12 | provider.go | `StaticKeyProvider.ActiveKeyIDs` returns sorted order | ✅ Done |
| G13 | format.go | `parseInnerPlaintext` with exactly 2 bytes (keyIDLen=1, empty keyID) | ✅ IMPLEMENTED as TestOpen_InvalidInnerPlaintext |
| G14 | compress.go | `maybeCompress` with empty algorithm string | ❌ Low value |

### Low Priority (Completeness)

| ID | File | Gap Description | Status |
|----|------|-----------------|--------|
| G15 | errors.go | `ErrInvalidKeyID` and `ErrUnsupportedCompression` missing from identity test | ✅ Done |
| G16 | kdf.go | `hkdfDerive` with empty info string | ❌ Low value |
| G17 | normalize.go | `NormalizePhone` with only non-ASCII digits (full Unicode) | ❌ Low value |
| G18 | search.go | `SearchConditionString` with empty string | ❌ Low value |
| G19 | helpers.go | `SealStringPtr` with `WithEmptyStringAsNull` and pointer to empty string | ❌ Low value |
| G20 | benchmark_test.go | Missing benchmark for `deriveKeys` | ❌ Low value |
| G21 | cipher.go | Multiple keys but no explicit default (first-registered selection) | ✅ Done |
| G22 | compress.go | Decompression of truncated zstd data | ❌ Low value - Invalid zstd already tested |
| G23 | rotate.go | `ExtractKeyID` on ciphertext with max-length keyID | ❌ Low value - Max keyID already tested |

---

## Proposed Tests with Patch-Ready Diffs

### G1: OpenWithKey with Non-Existent Key

**File:** `cipher_test.go`

```diff
--- a/cipher_test.go
+++ b/cipher_test.go
@@ -222,6 +222,16 @@ func TestOpenWithKey_Mismatch(t *testing.T) {
 	require.ErrorIs(t, err, ErrKeyIDMismatch)
 }

+func TestOpenWithKey_KeyNotFound(t *testing.T) {
+	cipher, _ := New(WithKey("v1", testKey("v1")))
+
+	ciphertext := cipher.Seal([]byte("test"))
+
+	// Try to decrypt with non-existent key
+	_, err := cipher.OpenWithKey("nonexistent", ciphertext)
+	require.ErrorIs(t, err, ErrKeyNotFound)
+}
+
 func TestSealOpen_Concurrent(t *testing.T) {
```

---

### G2: SearchCondition Panic with Invalid paramOffset

**File:** `search_test.go`

```diff
--- a/search_test.go
+++ b/search_test.go
@@ -213,3 +213,23 @@ func TestSearchCondition_ValidColumnNames(t *testing.T) {
 		})
 	}
 }
+
+func TestSearchCondition_InvalidParamOffset(t *testing.T) {
+	cipher, _ := New(WithKey("v1", testKey("v1")))
+
+	tests := []struct {
+		name   string
+		offset int
+	}{
+		{"zero", 0},
+		{"negative", -1},
+		{"negative large", -100},
+	}
+
+	for _, tt := range tests {
+		t.Run(tt.name, func(t *testing.T) {
+			require.Panics(t, func() {
+				cipher.SearchCondition("email", []byte("test"), tt.offset)
+			})
+		})
+	}
+}
```

---

### G3: Max-Length KeyID Round-Trip

**File:** `format_test.go`

```diff
--- a/format_test.go
+++ b/format_test.go
@@ -196,3 +196,28 @@ func TestFlagConstants(t *testing.T) {
 		seen[f] = true
 	}
 }
+
+func TestFormatCiphertext_MaxLengthKeyID(t *testing.T) {
+	// Maximum valid keyID length is 255 bytes
+	maxKeyID := strings.Repeat("k", 255)
+	nonce := [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
+	ciphertext := []byte("encrypted data")
+
+	formatted := formatCiphertext(flagNoCompression, maxKeyID, nonce, ciphertext)
+
+	flag, keyID, parsedNonce, parsedCiphertext, err := parseFormat(formatted)
+	require.NoError(t, err)
+	require.Equal(t, flagNoCompression, flag)
+	require.Equal(t, maxKeyID, keyID)
+	require.Equal(t, nonce, parsedNonce)
+	require.True(t, bytes.Equal(ciphertext, parsedCiphertext))
+}
+
+func TestFormatInnerPlaintext_MaxLengthKeyID(t *testing.T) {
+	maxKeyID := strings.Repeat("k", 255)
+	plaintext := []byte("test data")
+
+	formatted := formatInnerPlaintext(maxKeyID, plaintext)
+	keyID, parsedPlaintext, err := parseInnerPlaintext(formatted)
+	require.NoError(t, err)
+	require.Equal(t, maxKeyID, keyID)
+	require.True(t, bytes.Equal(plaintext, parsedPlaintext))
+}
```

**Note:** Add import `"strings"` to format_test.go if not present.

---

### G5: OpenJSON with Type Mismatch

**File:** `helpers_test.go`

```diff
--- a/helpers_test.go
+++ b/helpers_test.go
@@ -311,3 +311,23 @@ func TestOpenStringPtr_InvalidCiphertext(t *testing.T) {
 	require.ErrorIs(t, err, ErrInvalidFormat)
 	require.Nil(t, result)
 }
+
+func TestOpenJSON_TypeMismatch(t *testing.T) {
+	cipher, _ := New(WithKey("v1", testKey("v1")))
+
+	// Encrypt valid JSON array
+	ciphertext, err := SealJSON(cipher, []string{"a", "b", "c"})
+	require.NoError(t, err)
+
+	// Try to decrypt as struct - should fail with unmarshal error
+	type WrongType struct {
+		Name string `json:"name"`
+	}
+	_, err = OpenJSON[WrongType](cipher, ciphertext)
+	require.Error(t, err)
+}
+
+func TestOpenJSON_DecryptionError(t *testing.T) {
+	cipher, _ := New(WithKey("v1", testKey("v1")))
+
+	// Invalid ciphertext should fail with decryption/format error
+	_, err := OpenJSON[map[string]any](cipher, []byte{0x00, 0x01})
+	require.Error(t, err)
+}
```

---

### G6: Use-After-Close

**File:** `cipher_test.go`

```diff
--- a/cipher_test.go
+++ b/cipher_test.go
@@ -333,6 +333,28 @@ func TestClose(t *testing.T) {
 	require.Nil(t, cipher.keys)
 }

+func TestClose_UseAfterClose(t *testing.T) {
+	cipher, err := New(WithKey("v1", testKey("v1")))
+	require.NoError(t, err)
+
+	ciphertext := cipher.Seal([]byte("test"))
+	require.NotNil(t, ciphertext)
+
+	cipher.Close()
+
+	// After Close, attempting to use cipher should panic or fail gracefully
+	// Since keys is nil, map access will panic
+	require.Panics(t, func() {
+		cipher.Seal([]byte("test"))
+	})
+
+	require.Panics(t, func() {
+		cipher.Open(ciphertext)
+	})
+
+	require.Panics(t, func() {
+		cipher.BlindIndex([]byte("test"))
+	})
+}
+
 func TestNew_InvalidKeyID_Empty(t *testing.T) {
```

---

### G7: BlindIndexes with Single Key

**File:** `blindindex_test.go`

```diff
--- a/blindindex_test.go
+++ b/blindindex_test.go
@@ -126,6 +126,18 @@ func TestBlindIndexes_NullPreservation(t *testing.T) {
 	require.Nil(t, indexes)
 }

+func TestBlindIndexes_SingleKey(t *testing.T) {
+	cipher, _ := New(WithKey("v1", testKey("v1")))
+
+	plaintext := []byte("test@example.com")
+	indexes := cipher.BlindIndexes(plaintext)
+
+	require.Len(t, indexes, 1)
+	require.Contains(t, indexes, "v1")
+	require.Len(t, indexes["v1"], 32)
+	// Should match BlindIndex result
+	require.True(t, bytes.Equal(indexes["v1"], cipher.BlindIndex(plaintext)))
+}
+
 func TestBlindIndexString(t *testing.T) {
```

---

### G9 & G10: Compression Threshold Edge Cases

**File:** `options_test.go`

```diff
--- a/options_test.go
+++ b/options_test.go
@@ -123,3 +123,30 @@ func TestOptions_ChainedCorrectly(t *testing.T) {
 	require.Equal(t, 2048, cipher.config.compressionThreshold)
 	require.Equal(t, "zstd", cipher.config.compressionAlgorithm)
 }
+
+func TestWithCompressionThreshold_Zero(t *testing.T) {
+	// Threshold of 0 means always attempt compression
+	cipher, err := New(
+		WithKey("v1", testKey("v1")),
+		WithCompressionThreshold(0),
+	)
+	require.NoError(t, err)
+	require.Equal(t, 0, cipher.config.compressionThreshold)
+
+	// Even small compressible data should be compressed if savings >= 10%
+	// (though very small data rarely compresses well)
+	data := []byte(strings.Repeat("a", 100))
+	_ = cipher.Seal(data) // Should not panic
+}
+
+func TestWithCompressionThreshold_Negative(t *testing.T) {
+	// Negative threshold should behave like 0 (always attempt)
+	cipher, err := New(
+		WithKey("v1", testKey("v1")),
+		WithCompressionThreshold(-1),
+	)
+	require.NoError(t, err)
+
+	data := []byte(strings.Repeat("x", 100))
+	_ = cipher.Seal(data) // Should not panic
+}
```

**Note:** Add import `"strings"` to options_test.go.

---

### G11: RotateValue When Already Using Default Key

**File:** `rotate_test.go`

```diff
--- a/rotate_test.go
+++ b/rotate_test.go
@@ -230,3 +230,27 @@ func TestRotation_CompleteWorkflow(t *testing.T) {
 	// New index matches rotated data
 	require.True(t, bytes.Equal(newSealed.BlindIndex, idx3))
 }
+
+func TestRotateValue_AlreadyDefault(t *testing.T) {
+	cipher, _ := New(
+		WithKey("v1", testKey("v1")),
+		WithKey("v2", testKey("v2")),
+		WithDefaultKeyID("v2"),
+	)
+
+	// Encrypt with v2 (default)
+	originalCiphertext := cipher.Seal([]byte("secret data"))
+
+	// Rotation should still work but produce different ciphertext (new nonce)
+	newCiphertext, err := cipher.RotateValue(originalCiphertext)
+	require.NoError(t, err)
+	require.NotNil(t, newCiphertext)
+
+	// Different ciphertext (random nonce), same key
+	require.False(t, bytes.Equal(originalCiphertext, newCiphertext))
+
+	// Same plaintext
+	result, _ := cipher.Open(newCiphertext)
+	require.Equal(t, []byte("secret data"), result)
+
+	// Still uses v2
+	keyID, _ := cipher.ExtractKeyID(newCiphertext)
+	require.Equal(t, "v2", keyID)
+}
```

---

### G12: StaticKeyProvider ActiveKeyIDs Sorted

**File:** `provider_test.go`

```diff
--- a/provider_test.go
+++ b/provider_test.go
@@ -129,3 +129,22 @@ func TestNewWithProvider_GetKeyError(t *testing.T) {
 	_, err := NewWithProvider(provider)
 	require.ErrorIs(t, err, ErrKeyNotFound)
 }
+
+func TestStaticKeyProvider_ActiveKeyIDs_Sorted(t *testing.T) {
+	// Add keys in non-alphabetical order
+	keys := map[string][]byte{
+		"charlie": testKey("charlie"),
+		"alpha":   testKey("alpha"),
+		"bravo":   testKey("bravo"),
+		"delta":   testKey("delta"),
+	}
+
+	provider := NewStaticKeyProvider("alpha", keys)
+
+	ids := provider.ActiveKeyIDs()
+
+	// Should be sorted alphabetically
+	require.Len(t, ids, 4)
+	require.Equal(t, []string{"alpha", "bravo", "charlie", "delta"}, ids)
+}
```

---

### G14: maybeCompress with Empty Algorithm

**File:** `compress_test.go`

```diff
--- a/compress_test.go
+++ b/compress_test.go
@@ -205,3 +205,14 @@ func TestMaybeCompress_JustBelowThreshold(t *testing.T) {
 	require.Equal(t, flagNoCompression, flag, "below threshold should not compress")
 	require.True(t, bytes.Equal(data, result))
 }
+
+func TestMaybeCompress_EmptyAlgorithm(t *testing.T) {
+	// Empty algorithm string should not compress
+	data := []byte(strings.Repeat("hello world ", 200))
+
+	result, flag := maybeCompress(data, 100, "", false)
+
+	// Should return uncompressed with no-compression flag
+	require.Equal(t, flagNoCompression, flag)
+	require.True(t, bytes.Equal(data, result))
+}
```

---

### G15: Complete Error Identity Test

**File:** `errors_test.go`

```diff
--- a/errors_test.go
+++ b/errors_test.go
@@ -19,6 +19,8 @@ func TestErrors_Identity(t *testing.T) {
 		ErrInvalidFormat,
 		ErrNoKeys,
 		ErrDefaultKeyNotFound,
+		ErrInvalidKeyID,
+		ErrUnsupportedCompression,
 	}

 	// Each error should be equal to itself
@@ -53,6 +55,8 @@ func TestErrors_Messages(t *testing.T) {
 		{"ErrInvalidFormat", ErrInvalidFormat, "invalid ciphertext format"},
 		{"ErrNoKeys", ErrNoKeys, "no keys"},
 		{"ErrDefaultKeyNotFound", ErrDefaultKeyNotFound, "default key not found"},
+		{"ErrInvalidKeyID", ErrInvalidKeyID, "key ID"},
+		{"ErrUnsupportedCompression", ErrUnsupportedCompression, "unsupported compression"},
 	}

 	for _, tt := range tests {
```

---

### G16: hkdfDerive with Empty Info

**File:** `kdf_test.go`

```diff
--- a/kdf_test.go
+++ b/kdf_test.go
@@ -141,3 +141,16 @@ func TestDeriveKeys_KnownVector(t *testing.T) {
 	require.Equal(t, expectedHMACFirst4, keys.hmac[:4],
 		"hmac key derivation changed - this breaks backward compatibility")
 }
+
+func TestHkdfDerive_EmptyInfo(t *testing.T) {
+	masterKey := []byte("01234567890123456789012345678901")
+
+	out := make([]byte, 32)
+	err := hkdfDerive(masterKey, "", out)
+	require.NoError(t, err)
+
+	// Empty info should still produce valid output
+	allZeros := make([]byte, 32)
+	require.False(t, bytes.Equal(out, allZeros),
+		"HKDF with empty info should still produce non-zero output")
+}
```

---

### G18: SearchConditionString with Empty String

**File:** `search_test.go`

```diff
--- a/search_test.go
+++ b/search_test.go
@@ -145,6 +145,19 @@ func TestSearchConditionNormalized_Null(t *testing.T) {
 	require.Nil(t, cond.Args)
 }

+func TestSearchConditionString_Empty(t *testing.T) {
+	cipher, _ := New(WithKey("v1", testKey("v1")))
+
+	// Empty string is NOT null - should generate valid search condition
+	cond := cipher.SearchConditionString("email", "", 1)
+
+	require.NotEqual(t, "FALSE", cond.SQL)
+	require.Len(t, cond.Args, 2)
+	require.Equal(t, "v1", cond.Args[0])
+	// Blind index of empty string should be 32 bytes
+	require.Len(t, cond.Args[1].([]byte), 32)
+}
+
 func TestSearchCondition_ColumnName(t *testing.T) {
```

---

### G19: SealStringPtr with EmptyStringAsNull and Empty String Pointer

**File:** `helpers_test.go`

```diff
--- a/helpers_test.go
+++ b/helpers_test.go
@@ -240,6 +240,18 @@ func TestSealString_EmptyStringAsNull(t *testing.T) {
 	require.NotNil(t, ct3)
 }

+func TestSealStringPtr_EmptyStringAsNull(t *testing.T) {
+	cipher, _ := New(
+		WithKey("v1", testKey("v1")),
+		WithEmptyStringAsNull(),
+	)
+
+	// Pointer to empty string should return nil with EmptyStringAsNull
+	empty := ""
+	ct := cipher.SealStringPtr(&empty)
+	require.Nil(t, ct, "pointer to empty string should be nil with EmptyStringAsNull")
+}
+
 func TestSealStringIndexedNormalized_EmptyString(t *testing.T) {
```

---

### G21: Multiple Keys Without Explicit Default

**File:** `cipher_test.go`

```diff
--- a/cipher_test.go
+++ b/cipher_test.go
@@ -411,3 +411,20 @@ func TestActiveKeyIDs_Sorted(t *testing.T) {
 	ids := cipher.ActiveKeyIDs()
 	require.Equal(t, []string{"alpha", "bravo", "charlie"}, ids)
 }
+
+func TestNew_DefaultKeySelection_Alphabetical(t *testing.T) {
+	// When no default is specified, the alphabetically first key becomes default
+	cipher, err := New(
+		WithKey("zebra", testKey("zebra")),
+		WithKey("alpha", testKey("alpha")),
+		WithKey("mike", testKey("mike")),
+	)
+	require.NoError(t, err)
+
+	// "alpha" should be selected as default (alphabetically first)
+	require.Equal(t, "alpha", cipher.DefaultKeyID())
+
+	// Encryption should use alpha key
+	ct := cipher.Seal([]byte("test"))
+	keyID, _ := cipher.ExtractKeyID(ct)
+	require.Equal(t, "alpha", keyID)
+}
```

---

### G22: Decompression of Truncated Zstd Data

**File:** `compress_test.go`

```diff
--- a/compress_test.go
+++ b/compress_test.go
@@ -127,6 +127,16 @@ func TestDecompress_InvalidZstd(t *testing.T) {
 	require.ErrorIs(t, err, ErrDecompressionFailed)
 }

+func TestDecompress_TruncatedZstd(t *testing.T) {
+	// First compress some valid data
+	original := []byte(strings.Repeat("test data ", 100))
+	compressed, _ := compressZstd(original)
+
+	// Truncate the compressed data
+	truncated := compressed[:len(compressed)/2]
+
+	_, err := decompress(truncated, flagZstd)
+	require.ErrorIs(t, err, ErrDecompressionFailed)
+}
+
 func TestDecompress_UnknownFlag(t *testing.T) {
```

---

### G23: ExtractKeyID with Max-Length KeyID

**File:** `rotate_test.go`

```diff
--- a/rotate_test.go
+++ b/rotate_test.go
@@ -192,6 +192,19 @@ func TestExtractKeyID_Invalid(t *testing.T) {
 	require.ErrorIs(t, err, ErrInvalidFormat)
 }

+func TestExtractKeyID_MaxLengthKeyID(t *testing.T) {
+	// Test with maximum valid keyID length (255 bytes)
+	maxKeyID := strings.Repeat("k", 255)
+	cipher, err := New(WithKey(maxKeyID, testKey("max")))
+	require.NoError(t, err)
+
+	ct := cipher.Seal([]byte("test"))
+
+	keyID, err := cipher.ExtractKeyID(ct)
+	require.NoError(t, err)
+	require.Equal(t, maxKeyID, keyID)
+}
+
 func TestRotateValue_DecryptionError(t *testing.T) {
```

**Note:** Add import `"strings"` to rotate_test.go.

---

### Additional Test: Concurrent Blind Index Computation

**File:** `blindindex_test.go`

```diff
--- a/blindindex_test.go
+++ b/blindindex_test.go
@@ -3,6 +3,7 @@ package encryptedcol
 import (
 	"bytes"
+	"sync"
 	"testing"

 	"github.com/stretchr/testify/require"
@@ -166,3 +167,32 @@ func TestBlindIndex_CaseSensitive(t *testing.T) {
 	// Without normalization, different cases produce different indexes
 	require.False(t, bytes.Equal(idx1, idx2), "blind index should be case-sensitive by default")
 }
+
+func TestBlindIndex_Concurrent(t *testing.T) {
+	cipher, _ := New(WithKey("v1", testKey("v1")))
+
+	plaintexts := []string{
+		"user1@example.com",
+		"user2@example.com",
+		"user3@example.com",
+		"user4@example.com",
+	}
+
+	var wg sync.WaitGroup
+	results := make([][]byte, len(plaintexts))
+
+	for i, pt := range plaintexts {
+		wg.Add(1)
+		go func(idx int, data string) {
+			defer wg.Done()
+			results[idx] = cipher.BlindIndex([]byte(data))
+		}(i, pt)
+	}
+
+	wg.Wait()
+
+	// Verify all results are valid (32 bytes each)
+	for i, result := range results {
+		require.Len(t, result, 32, "result %d should be 32 bytes", i)
+	}
+}
```

---

## Priority Matrix

| Priority | Test ID | Risk Mitigated | Effort |
|----------|---------|----------------|--------|
| **Critical** | G1 | Key not found before parse | Low |
| **Critical** | G2 | Panic with invalid offset | Low |
| **Critical** | G6 | Use-after-close behavior | Low |
| **High** | G3 | Max keyID boundary | Low |
| **High** | G5 | JSON type safety | Low |
| **High** | G15 | Complete error coverage | Low |
| **High** | G22 | Truncated data handling | Low |
| **Medium** | G7-G14, G16-G21 | Edge case coverage | Low |
| **Low** | G23 | Completeness | Low |

---

## Implementation Notes

### Import Requirements

Several test files need additional imports:

1. **format_test.go**: Add `"strings"`
2. **options_test.go**: Add `"strings"`
3. **rotate_test.go**: Add `"strings"`
4. **blindindex_test.go**: Add `"sync"`

### Test Execution

After applying patches, run:

```bash
go test -v ./...           # Run all tests
go test -race ./...        # Verify concurrent safety
go test -cover ./...       # Check coverage improvement
```

### Expected Coverage Improvement

Adding these 23 tests should improve line coverage by approximately **3-5%** and significantly improve branch coverage for error paths and boundary conditions.

---

## Summary

The `encryptedcol` library has a solid foundation of tests but lacks coverage for:

1. **Error paths** - Several error conditions aren't explicitly tested
2. **Boundary conditions** - Max-length keyIDs, zero thresholds, negative values
3. **State transitions** - Use-after-close behavior
4. **Panic conditions** - Invalid parameter validation

All proposed tests follow existing patterns (table-driven with `t.Run()`, using `require` from testify) and can be applied incrementally.
