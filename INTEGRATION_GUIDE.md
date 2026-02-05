# Integration Guide

This guide covers integrating `encryptedcol` into your Go application for client-side encrypted database columns with searchable blind indexes.

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Database Schema](#database-schema)
4. [Encrypting Data](#encrypting-data)
5. [Searchable Encryption](#searchable-encryption)
6. [Key Rotation](#key-rotation)
7. [External Key Management](#external-key-management)
8. [Configuration Options](#configuration-options)
9. [Best Practices](#best-practices)

---

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
    // 32-byte master key (in production, load from secure storage)
    masterKey := []byte("your-32-byte-secret-key-here!!!")

    cipher, err := encryptedcol.New(
        encryptedcol.WithKey("v1", masterKey),
    )
    if err != nil {
        panic(err)
    }
    defer cipher.Close() // Zero out keys when done

    // Encrypt
    ciphertext := cipher.SealString("sensitive data")

    // Decrypt
    plaintext, err := cipher.OpenString(ciphertext)
    if err != nil {
        panic(err)
    }
    fmt.Println(plaintext) // "sensitive data"
}
```

## Database Schema

For searchable encrypted fields, use a three-column pattern:

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,

    -- Searchable encrypted email
    email_encrypted BYTEA,           -- The encrypted value
    email_idx BYTEA,                 -- Blind index for searching
    key_id TEXT NOT NULL,            -- Key version used

    -- Non-searchable encrypted field (just one column)
    ssn_encrypted BYTEA,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for efficient blind index lookups
CREATE INDEX idx_users_email ON users (key_id, email_idx);
```

### Column Naming Convention

| Column | Purpose |
|--------|---------|
| `{field}_encrypted` | Stores the ciphertext (BYTEA) |
| `{field}_idx` | Stores the blind index hash (BYTEA) |
| `key_id` | Tracks which key version encrypted the row |

## Encrypting Data

### Basic Encryption

```go
// Bytes
ciphertext := cipher.Seal([]byte("data"))
plaintext, err := cipher.Open(ciphertext)

// Strings
ciphertext := cipher.SealString("data")
plaintext, err := cipher.OpenString(ciphertext)

// Nullable strings (pointer)
ciphertext := cipher.SealStringPtr(strPtr)  // nil -> nil
plaintext, err := cipher.OpenStringPtr(ciphertext)

// Integers
ciphertext := cipher.SealInt64(12345)
num, err := cipher.OpenInt64(ciphertext)
```

### JSON Encryption

```go
type UserProfile struct {
    Preferences map[string]string `json:"preferences"`
    Tags        []string          `json:"tags"`
}

profile := UserProfile{
    Preferences: map[string]string{"theme": "dark"},
    Tags:        []string{"vip", "early-adopter"},
}

// Encrypt
ciphertext, err := encryptedcol.SealJSON(cipher, profile)

// Decrypt (with generics)
decrypted, err := encryptedcol.OpenJSON[UserProfile](cipher, ciphertext)
```

### NULL Handling

NULL values are preserved through encryption/decryption:

```go
cipher.Seal(nil)   // Returns nil
cipher.Open(nil)   // Returns nil, nil

// Empty string vs NULL (default: empty string is encrypted)
cipher.SealString("")  // Returns ciphertext (not nil)

// Opt-in: treat empty string as NULL
cipher, _ := encryptedcol.New(
    encryptedcol.WithKey("v1", key),
    encryptedcol.WithEmptyStringAsNull(),
)
cipher.SealString("")  // Returns nil
```

## Searchable Encryption

Blind indexes enable exact-match queries on encrypted data.

### Storing with Blind Index

```go
// Basic (case-sensitive)
sealed := cipher.SealStringIndexed("alice@example.com")
// sealed.Ciphertext = encrypted data
// sealed.BlindIndex = HMAC hash for searching
// sealed.KeyID      = key version

// With normalization (case-insensitive email)
sealed := cipher.SealStringIndexedNormalized(
    "Alice@Example.COM",
    encryptedcol.NormalizeEmail,
)
// Ciphertext contains "Alice@Example.COM" (original preserved)
// BlindIndex is HMAC("alice@example.com") (normalized)

// Insert into database
_, err := db.Exec(`
    INSERT INTO users (email_encrypted, email_idx, key_id)
    VALUES ($1, $2, $3)
`, sealed.Ciphertext, sealed.BlindIndex, sealed.KeyID)
```

### Available Normalizers

| Normalizer | Transformation | Example |
|------------|----------------|---------|
| `NormalizeEmail` | lowercase + trim | `" ALICE@Example.COM "` → `"alice@example.com"` |
| `NormalizeUsername` | lowercase + trim | `" JohnDoe "` → `"johndoe"` |
| `NormalizePhone` | digits only | `"(555) 123-4567"` → `"5551234567"` |
| `NormalizeTrim` | trim whitespace | `" hello "` → `"hello"` |
| `NormalizeLower` | lowercase only | `"Hello"` → `"hello"` |
| `NormalizeNone` | no change | exact match |

### Searching Encrypted Data

```go
// Generate search condition
cond := cipher.SearchConditionStringNormalized(
    "email",                        // column name
    "ALICE@example.com",            // search value
    1,                              // parameter offset ($1, $2, ...)
    encryptedcol.NormalizeEmail,
)

// Query
rows, err := db.Query(
    fmt.Sprintf("SELECT * FROM users WHERE %s", cond.SQL),
    cond.Args...,
)

// Generated SQL (single key):
// SELECT * FROM users WHERE (key_id = $1 AND email_idx = $2)

// Generated SQL (during key rotation, multiple keys):
// SELECT * FROM users WHERE
//   (key_id = $1 AND email_idx = $2) OR (key_id = $3 AND email_idx = $4)
```

### Combining with Other Conditions

```go
cond := cipher.SearchConditionStringNormalized("email", email, 2, encryptedcol.NormalizeEmail)

query := fmt.Sprintf(`
    SELECT * FROM users
    WHERE status = $1 AND (%s)
`, cond.SQL)

args := append([]interface{}{"active"}, cond.Args...)
rows, err := db.Query(query, args...)
```

## Key Rotation

### Phase 1: Add New Key as Default

```go
cipher, _ := encryptedcol.New(
    encryptedcol.WithKey("v1", oldKey),
    encryptedcol.WithKey("v2", newKey),
    encryptedcol.WithDefaultKeyID("v2"),  // New encryptions use v2
)
```

At this point:
- New data is encrypted with `v2`
- Old data encrypted with `v1` can still be read
- Searches check both key versions automatically

### Phase 2: Migrate Existing Data

```go
// Check if rotation needed
if cipher.NeedsRotation(ciphertext) {
    // Re-encrypt with current default key
    newCiphertext, err := cipher.RotateValue(ciphertext)

    // For searchable fields with normalization
    sealed, err := cipher.RotateStringIndexedNormalized(
        oldCiphertext,
        encryptedcol.NormalizeEmail,
    )

    // Update database
    _, err = db.Exec(`
        UPDATE users
        SET email_encrypted = $1, email_idx = $2, key_id = $3
        WHERE id = $4
    `, sealed.Ciphertext, sealed.BlindIndex, sealed.KeyID, userID)
}
```

### Phase 3: Remove Old Key

Once all data is migrated:

```go
cipher, _ := encryptedcol.New(
    encryptedcol.WithKey("v2", newKey),  // Only new key
)
```

### Extract Key Version

```go
keyID, err := cipher.ExtractKeyID(ciphertext)
// Returns the key_id without decrypting
```

## External Key Management

Integrate with Vault, AWS KMS, or other secrets managers via `KeyProvider`:

```go
type KeyProvider interface {
    GetKey(keyID string) ([]byte, error)
    DefaultKeyID() string
    ActiveKeyIDs() []string
}
```

### Example: Custom Provider

```go
type VaultKeyProvider struct {
    client    *vault.Client
    keyPath   string
    defaultID string
    activeIDs []string
}

func (p *VaultKeyProvider) GetKey(keyID string) ([]byte, error) {
    secret, err := p.client.Logical().Read(
        fmt.Sprintf("%s/%s", p.keyPath, keyID),
    )
    if err != nil {
        return nil, err
    }
    return base64.StdEncoding.DecodeString(secret.Data["key"].(string))
}

func (p *VaultKeyProvider) DefaultKeyID() string {
    return p.defaultID
}

func (p *VaultKeyProvider) ActiveKeyIDs() []string {
    return p.activeIDs
}

// Usage
provider := &VaultKeyProvider{...}
cipher, err := encryptedcol.NewWithProvider(provider)
```

### Built-in Static Provider

For testing or simple deployments:

```go
provider := encryptedcol.NewStaticKeyProvider("v2", map[string][]byte{
    "v1": oldKey,
    "v2": newKey,
})
cipher, err := encryptedcol.NewWithProvider(provider)
```

## Configuration Options

```go
cipher, err := encryptedcol.New(
    // Required: at least one key
    encryptedcol.WithKey("v1", key1),
    encryptedcol.WithKey("v2", key2),

    // Set default key for new encryptions
    encryptedcol.WithDefaultKeyID("v2"),

    // Compression settings
    encryptedcol.WithCompressionThreshold(2048),  // Default: 1024 bytes
    encryptedcol.WithCompressionDisabled(),       // Disable compression entirely

    // NULL handling
    encryptedcol.WithEmptyStringAsNull(),  // "" -> nil
)
```

### Compression

- **Default threshold**: 1KB - data smaller than this is not compressed
- **Algorithm**: Zstd (only if it saves ≥10%)
- **Transparent**: Format flag indicates compression; `Open()` handles automatically

## Best Practices

### Key Management

1. **Never hardcode keys** - Load from environment, secrets manager, or KMS
2. **Use 32-byte keys** - Required for XSalsa20-Poly1305
3. **Call `cipher.Close()`** - Zeros out key material when done
4. **Key IDs should be meaningful** - e.g., `"2024-01"`, `"v2"`, `"prod-rotation-3"`

### Blind Index Usage

1. **Only for high-entropy fields** - email, username, UUID, phone
2. **Never for low-entropy fields** - status, boolean, enum values (leaks equality)
3. **Use normalizers consistently** - Same normalizer on write AND search
4. **Index the compound** - `CREATE INDEX ON table (key_id, field_idx)`

### Search Considerations

```go
// GOOD: High-entropy field with normalizer
sealed := cipher.SealStringIndexedNormalized(email, encryptedcol.NormalizeEmail)

// BAD: Low-entropy field exposes patterns
sealed := cipher.SealStringIndexed(status)  // "active", "pending", etc.
// Attacker can see which rows share the same status!
```

### Error Handling

```go
plaintext, err := cipher.OpenString(ciphertext)
if err != nil {
    switch err {
    case encryptedcol.ErrWasNull:
        // Handle NULL value
    case encryptedcol.ErrDecryptionFailed:
        // Tampered or wrong key
    case encryptedcol.ErrKeyNotFound:
        // Key version not registered
    case encryptedcol.ErrKeyIDMismatch:
        // Ciphertext tampered (key substitution attack blocked)
    default:
        // Other error
    }
}
```

### Concurrent Usage

The `Cipher` is safe for concurrent use. Create one instance at startup and share it:

```go
var cipher *encryptedcol.Cipher

func init() {
    var err error
    cipher, err = encryptedcol.New(...)
    if err != nil {
        log.Fatal(err)
    }
}
```
