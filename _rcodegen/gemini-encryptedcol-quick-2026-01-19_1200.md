Date Created: 2026-01-19 12:00:00
TOTAL_SCORE: 92/100

# 1. AUDIT

## [Low] Deterministic JSON Serialization Risk
**File:** `helpers.go`
`SealJSONIndexed` relies on `json.Marshal` for blind index computation. While standard Go `json.Marshal` sorts map keys (providing determinism), custom `MarshalJSON` implementations or future changes could break this assumption. If the JSON byte representation changes for the same data, the blind index will change, breaking search capabilities.

## [Low] Panic in Random Number Generation
**File:** `cipher.go`
`generateNonce` panics if `rand.Read` fails. While this is a fail-safe for a cryptographic library (running without entropy is dangerous), valid library design usually prefers returning errors to allow the caller to handle the shutdown. However, changing this would require breaking the `Seal` API which currently does not return an error.

## [Low] One-time Initialization Latch
**File:** `compress.go`
`initZstd` uses `sync.Once` to initialize the encoder/decoder. If initialization fails (e.g., memory issues), it captures the error but the `Once` latch remains closed. Subsequent calls will return the same error forever without retrying, even if the condition was transient.

# 2. TESTS

## New Test: Compression Rotation
**File:** `rotate_test.go`
Ensure that rotating a value respects the new compression configuration (e.g., compressing previously uncompressed data).

```go
<<<<
func TestRotateValue_DecryptionError(t *testing.T) {
	cipher1, _ := New(WithKey("v1", testKey("v1")))
	cipher2, _ := New(WithKey("v2", testKey("v2")))

	ct := cipher1.Seal([]byte("test"))

	// cipher2 can't decrypt cipher1's ciphertext
	_, err := cipher2.RotateValue(ct)
	require.Error(t, err)
}

func TestRotation_CompleteWorkflow(t *testing.T) {
====
func TestRotateValue_DecryptionError(t *testing.T) {
	cipher1, _ := New(WithKey("v1", testKey("v1")))
	cipher2, _ := New(WithKey("v2", testKey("v2")))

	ct := cipher1.Seal([]byte("test"))

	// cipher2 can't decrypt cipher1's ciphertext
	_, err := cipher2.RotateValue(ct)
	require.Error(t, err)
}

func TestRotateValue_CompressionChange(t *testing.T) {
	// 1. Encrypt with compression disabled
	cipherNoCompress, _ := New(
		WithKey("v1", testKey("v1")),
		WithCompressionDisabled(),
	)

	largeData := []byte(strings.Repeat("A", 1000))
	ctUncompressed := cipherNoCompress.Seal(largeData)

	// 2. Rotate using cipher WITH compression enabled
	cipherCompress, _ := New(
		WithKey("v1", testKey("v1")), // Same key, just config change
		WithCompressionThreshold(100),
	)

	// Re-encrypts (rotates) the value
	ctRotated, err := cipherCompress.RotateValue(ctUncompressed)
	require.NoError(t, err)

	// 3. Verify result is compressed (smaller)
	require.Less(t, len(ctRotated), len(ctUncompressed))

	// 4. Verify round-trip
	pt, err := cipherCompress.Open(ctRotated)
	require.NoError(t, err)
	require.Equal(t, largeData, pt)
}

func TestRotation_CompleteWorkflow(t *testing.T) {
>>>>
```

# 3. FIXES

## Documentation Warning for JSON Determinism
**File:** `helpers.go`
Add a warning about the reliance on deterministic JSON serialization for blind indexes.

```go
<<<<
// SealJSONIndexed encrypts JSON data and computes its blind index.
// The blind index is computed on the JSON serialization.
func SealJSONIndexed[T any](c *Cipher, data T) (*SealedValue, error) {
	jsonBytes, err := json.Marshal(data)
====
// SealJSONIndexed encrypts JSON data and computes its blind index.
// The blind index is computed on the JSON serialization.
//
// WARNING: This relies on deterministic JSON serialization. Standard "encoding/json"
// sorts map keys, but custom MarshalJSON implementations might not be deterministic.
// If the JSON representation changes (e.g. whitespace, key order), the blind index
// will change, breaking search.
func SealJSONIndexed[T any](c *Cipher, data T) (*SealedValue, error) {
	jsonBytes, err := json.Marshal(data)
>>>>
```

# 4. REFACTOR

## Optimize Format Parsing
**File:** `format.go`
In `parseFormat`, `keyID` is allocated as a string: `keyID = string(data[2 : 2+keyIDLen])`.
This string is primarily used to look up keys in the `Cipher.keys` map.
Go optimizes map lookups with byte slices: `m[string(bytes)]` does not allocate if `m` is `map[string]...`.
**Suggestion:** Change `parseFormat` (internal) to return `[]byte` for `keyID`. Update `Open` and `sealWithKeyID` to cast to string only at the point of map lookup. This reduces garbage collection pressure on high-throughput read paths.

## Lazy Compression Initialization
**File:** `compress.go`
Consider refactoring `initZstd` to allow retries if initialization fails, rather than permanently bricking the compression capability via the `sync.Once` failure pattern.
