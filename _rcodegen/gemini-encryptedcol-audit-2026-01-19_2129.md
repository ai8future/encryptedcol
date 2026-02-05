Date Created: 2026-01-19 21:29:00
TOTAL_SCORE: 95/100

# Code Audit Report: encryptedcol

## 1. Executive Summary

The `encryptedcol` library is a high-quality, security-conscious implementation of client-side encryption for database columns. It employs modern, authenticated cryptography (XSalsa20-Poly1305) and robust key derivation (HKDF-SHA256). The code is clean, well-tested, and easy to use.

One medium-severity issue was identified regarding potential resource exhaustion (Decompression Bomb) when processing malicious compressed payloads. A patch is provided to enforce a maximum decompression size.

## 2. Scoring Breakdown

| Category | Score | Notes |
| :--- | :--- | :--- |
| **Security** | 35/35 | Excellent choice of primitives (NaCl Secretbox, HKDF, HMAC). Proper nonce management. |
| **Code Quality** | 30/30 | Idiomatic Go, clean structure, type-safe helpers. |
| **Reliability** | 15/20 | **Issue:** Unbounded decompression could lead to OOM (DoS). |
| **Documentation** | 10/10 | Comprehensive README and clear comments. |
| **Testing** | 5/5 | High coverage, including edge cases and errors. |
| **Total** | **95/100** | **Grade: A** |

## 3. Security Analysis

-   **Cryptography:** Uses `golang.org/x/crypto/nacl/secretbox` for encryption, which provides confidentiality and integrity. Key management uses HKDF-SHA256 for domain separation (encryption vs. blind indexing), which is best practice.
-   **Blind Indexing:** Uses HMAC-SHA256. This is the standard approach for searchable encryption (exact match). It deterministically leaks equality but nothing else.
-   **Randomness:** Uses `crypto/rand` and properly handles failures by panicking (fail-secure) rather than continuing with weak entropy.
-   **Timing Attacks:** String comparison of Key IDs happens *after* authenticated decryption. Since `secretbox` guarantees ciphertext integrity, an attacker cannot manipulate the inner Key ID to trigger timing leaks without breaking the encryption first.

## 4. Findings & Recommendations

### [Medium] Unbounded Decompression (DoS Risk)

**File:** `compress.go`

The `decompressZstd` function uses `zstd.Decoder.DecodeAll` without an output size limit. If an attacker can inject a "zip bomb" (a small file that decompresses to a massive size) into the database, reading this row could cause the application to run out of memory (OOM).

**Recommendation:** Enforce a maximum decompressed size (e.g., 10MB) appropriate for a database column.

### [Low] Redundant Length Check

**File:** `format.go`

In `parseFormat` and `parseInnerPlaintext`, the check `keyIDLen > 255` is mathematically impossible because `keyIDLen` is derived from a `byte` (0-255).

## 5. Patches

### Patch 1: Enforce Decompression Limit

This patch adds a 10MB limit to decompression.

**File:** `compress.go`

```go
<<<<
import (
	"sync"

	"github.com/klauspost/compress/zstd"
)
====
import (
	"bytes"
	"io"
	"sync"

	"github.com/klauspost/compress/zstd"
)
>>>>
```

```go
<<<<
// decompressZstd decompresses zstd-compressed data.
func decompressZstd(data []byte) ([]byte, error) {
	_, decoder, err := initZstd()
	if err != nil {
		return nil, err
	}
	result, err := decoder.DecodeAll(data, nil)
	if err != nil {
		return nil, ErrDecompressionFailed
	}
	return result, nil
}
====
// maxDecompressedSize limits the output size to prevent memory exhaustion attacks.
const maxDecompressedSize = 10 * 1024 * 1024 // 10MB

// decompressZstd decompresses zstd-compressed data.
func decompressZstd(data []byte) ([]byte, error) {
	_, decoder, err := initZstd()
	if err != nil {
		return nil, err
	}

	// Use stream interface with LimitReader to prevent zip bombs
	if err := decoder.Reset(bytes.NewReader(data)); err != nil {
		return nil, err
	}
	defer decoder.Reset(nil) // Cleanup

	return io.ReadAll(io.LimitReader(decoder, maxDecompressedSize))
}
>>>>
```

### Patch 2: Remove Redundant Check

**File:** `format.go`

```go
<<<<
	flag = data[0]
	keyIDLen := int(data[1])

	// Validate keyIDLen
	if keyIDLen == 0 || keyIDLen > 255 {
		err = ErrInvalidFormat
		return
	}
====
	flag = data[0]
	keyIDLen := int(data[1])

	// Validate keyIDLen
	if keyIDLen == 0 {
		err = ErrInvalidFormat
		return
	}
>>>>
```
