# encryptedcol

Client-side encrypted columns for PostgreSQL/Supabase with blind indexing for searchable encryption.

Data is encrypted before it leaves your application. The database stores only ciphertext and opaque blind indexes — it never sees plaintext.

## Features

- **XSalsa20-Poly1305** authenticated encryption (NaCl secretbox)
- **HKDF-SHA256** key derivation — one master key derives separate encryption and HMAC keys
- **Blind indexes** — HMAC-SHA256 enables exact-match queries on encrypted fields
- **Normalizers** — case-insensitive and format-agnostic search (email, phone, username)
- **Key rotation** — multi-version keys with zero-downtime migration helpers
- **Compression** — optional zstd for large payloads, applied before encryption
- **NULL preservation** — `nil` in, `nil` out; empty strings configurable
- **Type-safe helpers** — `SealString`, `SealJSON[T]`, `SealInt64`, pointer variants
- **SQL builder** — generates parameterized `WHERE` clauses across key versions
- **KeyProvider interface** — plug in Vault, AWS KMS, or any external key source
- **Tamper detection** — key ID authenticated inside and outside the ciphertext

## Install

```bash
go get github.com/ai8future/encryptedcol
```

Requires **Go 1.24+**.

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/ai8future/encryptedcol"
)

func main() {
    // 32-byte master key (in production, load from secure storage)
    masterKey := []byte("01234567890123456789012345678901")

    cipher, err := encryptedcol.New(
        encryptedcol.WithKey("v1", masterKey),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer cipher.Close()

    // Encrypt
    ciphertext := cipher.SealString("Hello, World!")

    // Decrypt
    plaintext, err := cipher.OpenString(ciphertext)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(plaintext) // Hello, World!
}
```

## Searchable Encryption

Blind indexes let you query encrypted columns without exposing plaintext to the database.

### Write Path (INSERT)

```go
sealed := cipher.SealStringIndexedNormalized(
    "Alice@Example.COM",
    encryptedcol.NormalizeEmail,
)

// INSERT INTO users (email_encrypted, email_idx, key_id) VALUES ($1, $2, $3)
db.Exec(query, sealed.Ciphertext, sealed.BlindIndex, sealed.KeyID)
```

The ciphertext preserves the original value (`Alice@Example.COM`). The blind index is computed from the normalized form (`alice@example.com`), enabling case-insensitive lookup.

### Read Path (SELECT)

```go
cond := cipher.SearchConditionStringNormalized(
    "email", "alice@example.com", 1, encryptedcol.NormalizeEmail,
)

query := fmt.Sprintf("SELECT * FROM users WHERE %s", cond.SQL)
rows, _ := db.Query(query, cond.Args...)
// SQL: (key_id = $1 AND email_idx = $2)
```

During key rotation (multiple active keys), the builder generates OR clauses for each key version automatically.

### Composing with Other Conditions

```go
emailCond := cipher.SearchConditionString("email", "alice@example.com", 3)

query := "SELECT * FROM users WHERE tenant_id = $1 AND status = $2 AND (" + emailCond.SQL + ")"
args := append([]interface{}{"tenant-123", "active"}, emailCond.Args...)
```

The `paramOffset` argument controls where `$N` numbering starts, so encrypted search composes cleanly with your existing query parameters.

## Normalizers

Normalizers transform input before computing blind indexes. Use the same normalizer on write and search.

| Normalizer | Behavior | Use Case |
|---|---|---|
| `NormalizeEmail` | lowercase + trim whitespace | Email addresses |
| `NormalizeUsername` | lowercase + trim whitespace | Usernames |
| `NormalizePhone` | ASCII digits only | Phone numbers |
| `NormalizeTrim` | trim whitespace, preserve case | Case-sensitive fields |
| `NormalizeLower` | lowercase, no trim | General case-insensitive |
| `NormalizeNone` | identity (no change) | Exact match |

Normalizers are applied only to blind index computation — the encrypted value always preserves the original input.

## JSON Encryption

Encrypt structs and complex types using generics:

```go
type Metadata struct {
    Tags   []string `json:"tags"`
    Source string   `json:"source"`
}

ciphertext, err := encryptedcol.SealJSON(cipher, Metadata{
    Tags:   []string{"important", "vip"},
    Source: "api",
})

result, err := encryptedcol.OpenJSON[Metadata](cipher, ciphertext)
```

## Integer Encryption

```go
ciphertext := cipher.SealInt64(42)
value, err := cipher.OpenInt64(ciphertext)
```

## Pointer Helpers

For nullable database columns, pointer helpers map Go `nil` to SQL `NULL`:

```go
name := "Alice"
ciphertext := cipher.SealStringPtr(&name)  // encrypts "Alice"
ciphertext = cipher.SealStringPtr(nil)      // returns nil (SQL NULL)

result, err := cipher.OpenStringPtr(ciphertext) // returns *string or nil
```

## NULL Handling

NULL values pass through unchanged:

```go
cipher.Seal(nil)   // returns nil
cipher.Open(nil)   // returns nil, nil
```

By default, empty strings are encrypted normally. To treat them as NULL:

```go
cipher, _ := encryptedcol.New(
    encryptedcol.WithKey("v1", key),
    encryptedcol.WithEmptyStringAsNull(),
)

cipher.SealString("") // returns nil (SQL NULL)
```

## Key Rotation

Rotate encryption keys with zero downtime in three phases.

### Phase 1 — Add the new key

```go
cipher, _ := encryptedcol.New(
    encryptedcol.WithKey("v1", oldKey),
    encryptedcol.WithKey("v2", newKey),
    encryptedcol.WithDefaultKeyID("v2"), // new writes use v2
)
```

Both keys are active. Old data decrypts with v1, new data encrypts with v2.

### Phase 2 — Migrate existing rows

```go
rows := getAllRows() // your query

for _, row := range rows {
    if cipher.NeedsRotation(row.EmailEncrypted) {
        rotated, err := cipher.RotateStringIndexedNormalized(
            row.EmailEncrypted,
            encryptedcol.NormalizeEmail,
        )
        if err != nil {
            log.Printf("row %d: %v", row.ID, err)
            continue
        }

        // UPDATE users SET
        //   email_encrypted = $1, email_idx = $2, key_id = $3
        // WHERE id = $4
        db.Exec(updateQuery,
            rotated.Ciphertext,
            rotated.BlindIndex,
            rotated.KeyID,
            row.ID,
        )
    }
}
```

### Phase 3 — Remove the old key

```go
cipher, _ := encryptedcol.New(
    encryptedcol.WithKey("v2", newKey),
)
```

### Rotation Utilities

```go
cipher.NeedsRotation(ct)    // true if ct uses a non-default key (header-only, no decryption)
cipher.ExtractKeyID(ct)     // read the key ID from ciphertext without decrypting
cipher.RotateValue(ct)      // decrypt with old key, re-encrypt with default key
```

## KeyProvider Interface

For external key management (Vault, AWS KMS, etc.), implement the `KeyProvider` interface:

```go
type KeyProvider interface {
    GetKey(keyID string) ([]byte, error)
    DefaultKeyID() string
    ActiveKeyIDs() []string
}
```

Then construct:

```go
cipher, err := encryptedcol.NewWithProvider(myVaultProvider)
```

A built-in `StaticKeyProvider` is included for simpler use cases:

```go
provider := encryptedcol.NewStaticKeyProvider("v2", map[string][]byte{
    "v1": oldKey,
    "v2": newKey,
})
cipher, err := encryptedcol.NewWithProvider(provider)
```

## Configuration Options

| Option | Default | Description |
|---|---|---|
| `WithKey(id, key)` | — | Register a 32-byte master key. First key becomes the default. |
| `WithDefaultKeyID(id)` | first key | Override which key is used for new encryptions. |
| `WithCompressionThreshold(n)` | 1024 | Minimum bytes before zstd compression is attempted. |
| `WithCompressionAlgorithm(algo)` | `"zstd"` | Compression algorithm. Only `"zstd"` is currently supported. |
| `WithCompressionDisabled()` | false | Disable compression entirely. |
| `WithEmptyStringAsNull()` | false | Treat empty strings as NULL (Seal returns nil). |

## Database Schema

Recommended PostgreSQL schema for encrypted columns:

```sql
CREATE TABLE users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Non-searchable encrypted field
    notes_encrypted BYTEA,

    -- Searchable encrypted field
    email_encrypted BYTEA,
    email_idx       BYTEA,

    -- Key version tracking (shared across all encrypted columns)
    key_id TEXT NOT NULL
);

-- Index for blind-index lookups
CREATE INDEX idx_users_email ON users (key_id, email_idx);
```

## Ciphertext Format

```
[flag:1][keyIDLen:1][keyID:n][nonce:24][secretbox(innerKeyID + plaintext)]
```

| Field | Size | Description |
|---|---|---|
| `flag` | 1 byte | Compression: `0x00` = none, `0x01` = zstd |
| `keyIDLen` | 1 byte | Length of key ID (1-255) |
| `keyID` | n bytes | Key version identifier (e.g., `"v1"`) |
| `nonce` | 24 bytes | Random nonce (crypto/rand) |
| `secretbox` | variable | XSalsa20-Poly1305 authenticated ciphertext |

The key ID appears both in the plaintext header and inside the authenticated secretbox payload to prevent key confusion attacks.

## Errors

All errors use the `encryptedcol:` prefix and support `errors.Is()`:

| Error | Meaning |
|---|---|
| `ErrDecryptionFailed` | Secretbox authentication failed (wrong key or corrupted data) |
| `ErrKeyIDMismatch` | Inner key ID doesn't match outer (tampering detected) |
| `ErrKeyNotFound` | Requested key ID not registered |
| `ErrInvalidKeySize` | Master key is not exactly 32 bytes |
| `ErrWasNull` | Ciphertext was nil (database NULL) |
| `ErrDecompressionFailed` | Zstd decompression failed |
| `ErrInvalidFormat` | Ciphertext byte layout is malformed |
| `ErrNoKeys` | No keys provided to constructor |
| `ErrDefaultKeyNotFound` | Specified default key ID not in registry |
| `ErrInvalidKeyID` | Key ID empty or exceeds 255 bytes |
| `ErrUnsupportedCompression` | Unknown compression algorithm |
| `ErrCipherClosed` | Cipher used after `Close()` was called |

## Security Notes

- **Blind indexes on low-entropy fields**: Static HMAC indexes reveal which rows share the same value. Only use blind indexes on high-entropy fields (email, username, UUID). Never index low-entropy fields (status, boolean, enum).
- **crypto/rand panics**: If the OS entropy source fails, the library panics rather than returning an error that might be silently ignored. This follows Go crypto library conventions.
- **Key material cleanup**: Call `cipher.Close()` when done — it zeros all derived key material in memory.
- **Compression oracle**: Compression is applied before encryption. For contexts where an attacker controls part of the plaintext and can observe ciphertext length, consider `WithCompressionDisabled()`.

## Testing

```bash
go test -v ./...           # All tests
go test -race ./...        # Race detection
go test -cover ./...       # Coverage
go test -bench=. ./...     # Benchmarks
```

## Dependencies

| Package | Purpose |
|---|---|
| `golang.org/x/crypto/nacl/secretbox` | XSalsa20-Poly1305 authenticated encryption |
| `golang.org/x/crypto/hkdf` | HKDF-SHA256 key derivation |
| `github.com/klauspost/compress/zstd` | Zstd compression |
| `github.com/stretchr/testify` | Test assertions (test-only) |

## License

MIT
