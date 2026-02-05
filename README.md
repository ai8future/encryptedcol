# encryptedcol

A Go library for client-side encrypted columns in PostgreSQL/Supabase with blind indexing support.

## Features

- **Zero-knowledge storage** - Data encrypted before leaving the application
- **Searchable encryption** - Exact-match queries via blind indexes (HMAC-SHA256)
- **Efficient storage** - BYTEA columns with optional zstd compression
- **Key rotation** - Multiple key versions with seamless migration
- **Type-safe helpers** - String, JSON, and integer encryption

## Installation

```bash
go get github.com/ai8future/encryptedcol
```

## Quick Start

```go
package main

import (
    "fmt"
    "github.com/ai8future/encryptedcol"
)

func main() {
    // 32-byte master key (load from secure storage in production)
    masterKey := []byte("01234567890123456789012345678901")

    cipher, err := encryptedcol.New(
        encryptedcol.WithKey("v1", masterKey),
    )
    if err != nil {
        panic(err)
    }

    // Encrypt
    ciphertext := cipher.SealString("sensitive data")

    // Decrypt
    plaintext, _ := cipher.OpenString(ciphertext)
    fmt.Println(plaintext) // "sensitive data"
}
```

## Searchable Encryption

For fields requiring exact-match search:

```go
// Encrypt with blind index
sealed := cipher.SealStringIndexedNormalized("alice@example.com", encryptedcol.NormalizeEmail)

// INSERT into database
_, err := db.Exec(`
    INSERT INTO users (email_encrypted, email_idx, key_id)
    VALUES ($1, $2, $3)`,
    sealed.Ciphertext, sealed.BlindIndex, sealed.KeyID,
)

// Search
cond := cipher.SearchConditionStringNormalized("email", "alice@example.com", 1, encryptedcol.NormalizeEmail)
query := fmt.Sprintf("SELECT * FROM users WHERE %s", cond.SQL)
rows, _ := db.Query(query, cond.Args...)
```

## Normalizers

Use normalizers for case-insensitive or format-agnostic searches:

| Normalizer | Transformation | Use For |
|------------|---------------|---------|
| `NormalizeEmail` | lowercase + trim | Email addresses |
| `NormalizeUsername` | lowercase + trim | Usernames |
| `NormalizePhone` | digits only | Phone numbers |
| `NormalizeNone` | identity | Exact match |

**Important:** Use the same normalizer on write and search.

## Key Rotation

```go
cipher, _ := encryptedcol.New(
    encryptedcol.WithKey("v1", oldKey),
    encryptedcol.WithKey("v2", newKey),
    encryptedcol.WithDefaultKeyID("v2"),
)

// Check if rotation needed
if cipher.NeedsRotation(oldCiphertext) {
    newCiphertext, _ := cipher.RotateValue(oldCiphertext)
    // Update database with newCiphertext
}
```

## Database Schema

```sql
-- Encrypted + searchable field
ALTER TABLE users ADD COLUMN email_encrypted BYTEA;
ALTER TABLE users ADD COLUMN email_idx BYTEA;
CREATE INDEX idx_users_email ON users (key_id, email_idx);

-- Encrypted only (not searchable)
ALTER TABLE users ADD COLUMN notes_encrypted BYTEA;

-- Key version tracking
ALTER TABLE users ADD COLUMN key_id TEXT NOT NULL DEFAULT 'v1';
```

## Configuration Options

```go
cipher, _ := encryptedcol.New(
    encryptedcol.WithKey("v1", masterKey),
    encryptedcol.WithKey("v2", newKey),
    encryptedcol.WithDefaultKeyID("v2"),
    encryptedcol.WithCompressionThreshold(1024), // Compress if > 1KB
    encryptedcol.WithCompressionDisabled(),      // Or disable compression
    encryptedcol.WithEmptyStringAsNull(),        // Treat "" as NULL
)
```

## Type-Safe Helpers

```go
// Strings
ciphertext := cipher.SealString("hello")
plaintext, _ := cipher.OpenString(ciphertext)

// Nullable strings
ct := cipher.SealStringPtr(&s) // nil -> nil
s, _ := cipher.OpenStringPtr(ct)

// JSON
ct, _ := encryptedcol.SealJSON(cipher, myStruct)
result, _ := encryptedcol.OpenJSON[MyStruct](cipher, ct)

// Integers
ct := cipher.SealInt64(42)
n, _ := cipher.OpenInt64(ct)
```

## Technical Details

- **Encryption:** XSalsa20-Poly1305 (NaCl secretbox)
- **Nonces:** 24-byte random (safe for random generation)
- **Key derivation:** HKDF-SHA256 from master key
- **Blind index:** HMAC-SHA256
- **Compression:** zstd (optional, for large payloads)

## License

MIT
