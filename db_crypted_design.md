# Encrypted Column Management for Supabase/PostgreSQL

## Overview

A Go library for managing client-side encrypted columns in Supabase/PostgreSQL with support for blind indexing (searchable encryption). Data is encrypted before it leaves the application, ensuring zero-knowledge storage where the database cannot read the plaintext.

## Goals

1. **Zero-knowledge storage** - Database stores only ciphertext; decryption happens client-side
2. **Searchable encryption** - Support exact-match queries on encrypted fields via blind indexing
3. **Efficient storage** - Use BYTEA columns (50% smaller than hex-encoded strings)
4. **Key rotation** - Support multiple key versions with seamless migration
5. **Minimal integration friction** - Clean API that fits naturally into repository patterns
6. **Reusable** - Standalone Go package usable across multiple projects

## Technical Decisions

### Encryption Algorithm: XSalsa20-Poly1305 (secretbox)

**Choice:** NaCl secretbox via `golang.org/x/crypto/nacl/secretbox`

**Rationale:**
- 24-byte nonce (192-bit) - safer for random nonce generation, virtually no collision risk
- Simpler API, harder to misuse (NaCl's design philosophy)
- Authenticated encryption (includes integrity verification)
- Well-audited, from DJB's NaCl library
- Go has excellent support

**Trade-off:** No hardware acceleration (unlike AES-GCM), but database operations are not typically CPU-bound on encryption.

### Nonce Generation

**Source:** Always use `crypto/rand` (cryptographically secure PRNG), never `math/rand`.

```go
import "crypto/rand"

func generateNonce() [24]byte {
    var nonce [24]byte
    if _, err := rand.Read(nonce[:]); err != nil {
        panic("crypto/rand failed: " + err.Error())
    }
    return nonce
}
```

**Why random nonces are safe for secretbox:**

- secretbox uses 24-byte (192-bit) nonces
- With random generation, birthday collision probability:
  - After 2^48 (~280 trillion) encryptions: 50% chance of collision
  - After 2^32 (~4 billion) encryptions: negligible chance (~0.00000006%)
- For database column encryption, you'll never approach these numbers
- Random nonces are stateless (no counter to persist/synchronize)

**Why NOT to use counter-based nonces:**

- Requires persistent state across restarts
- Requires synchronization in distributed systems
- For our use case (database encryption), random is simpler and safe

**Implementation note:** If `crypto/rand.Read()` fails, the system's entropy source is broken—this is unrecoverable, so panic is appropriate.

### Compression Before Encryption

**Problem:** Encrypted data is high-entropy (random-looking bytes). PostgreSQL's TOAST compression cannot compress it, even for large TEXT fields that would normally compress well.

**Solution:** Compress plaintext before encryption for large fields.

**Algorithm choice:** Zstd (preferred) or Snappy

| Algorithm | Compression Ratio | Speed | Go Library |
|-----------|-------------------|-------|------------|
| **Zstd** | Excellent | Fast | `github.com/klauspost/compress/zstd` |
| **Snappy** | Good | Very fast | `github.com/golang/snappy` |

**Implementation:**

```go
// Ciphertext format with compression flag
+------+----------+-------+------------------+
| flag | key_id   | nonce | compressed_then_ |
| (1B) | (var)    | (24B) | encrypted_data   |
+------+----------+-------+------------------+

// Flag byte:
// 0x00 = no compression
// 0x01 = zstd compressed
// 0x02 = snappy compressed
```

**API:**

```go
// Automatic compression for large payloads (>1KB by default)
cipher.Seal(largeJSON)  // Compresses if beneficial, sets flag

// Explicit control
cipher.SealCompressed(data)      // Always compress
cipher.SealUncompressed(data)    // Never compress

// Configuration
encryptedcol.WithCompressionThreshold(1024)     // Compress if > 1KB
encryptedcol.WithCompressionAlgorithm("zstd")   // or "snappy"
encryptedcol.WithCompressionDisabled()          // Never compress
```

**Benefits:**
- Large JSON blobs: 70-90% size reduction before encryption
- Significant storage savings on fields like `raw_request_json`, `raw_response_json`
- Transparent: `Open()` auto-detects and decompresses

**When to compress:**
- Large text fields (notes, content, JSON)
- Fields > 1KB typically benefit

**When NOT to compress:**
- Small fields (email, name) - overhead exceeds benefit
- Already-compressed data (images, PDFs)
- Blind index values (never compressed)

### Blind Indexing: HMAC-SHA256

For searchable fields, store a keyed hash alongside the encrypted data:

- **Algorithm:** HMAC-SHA256
- **Storage:** BYTEA column (32 bytes)
- **Indexable:** Standard B-Tree index on BYTEA works efficiently

**Security consideration:** Blind indexes enable frequency analysis. Mitigated by:
- HMAC key is derived separately from encryption key (cryptographic isolation)
- Keeping the master key secret
- Accepting this trade-off only for fields that require search
- Key rotation changes both encryption and HMAC keys together

### Blind Index Normalization (Critical)

**The trap:** HMAC is binary-sensitive. If a user registers as `User@Example.com` but logs in as `user@example.com`, the blind indexes will be different bytes. Queries return zero results.

**You cannot fix this in SQL** - the database only sees the HMAC hash, so `LOWER()` won't help.

**Solution:** Canonicalize input before computing blind index.

```go
// Normalizer functions
type Normalizer func(string) string

var (
    // For emails: lowercase + trim whitespace
    NormalizeEmail Normalizer = func(s string) string {
        return strings.ToLower(strings.TrimSpace(s))
    }

    // For usernames: lowercase + trim
    NormalizeUsername Normalizer = func(s string) string {
        return strings.ToLower(strings.TrimSpace(s))
    }

    // For phone numbers: digits only
    NormalizePhone Normalizer = func(s string) string {
        var digits strings.Builder
        for _, r := range s {
            if r >= '0' && r <= '9' {
                digits.WriteRune(r)
            }
        }
        return digits.String()
    }

    // No normalization (case-sensitive, exact match)
    NormalizeNone Normalizer = func(s string) string { return s }
)
```

**API with normalization:**

```go
// Encrypt preserves original value, blind index uses normalized form
func (c *Cipher) SealStringIndexedNormalized(s string, norm Normalizer) *SealedValue

// Search must use same normalizer
func (c *Cipher) SearchConditionStringNormalized(col, s string, offset int, norm Normalizer) *SearchCondition
```

**Usage example:**

```go
// Registration: store original case, normalize for index
sealed := cipher.SealStringIndexedNormalized(user.Email, encryptedcol.NormalizeEmail)
// user.Email = "Alice@Example.COM"
// sealed.Ciphertext contains "Alice@Example.COM" (original preserved)
// sealed.BlindIndex = HMAC("alice@example.com") (normalized)

// Login search: normalize search term
cond := cipher.SearchConditionStringNormalized("email", loginEmail, 1, encryptedcol.NormalizeEmail)
// loginEmail = "ALICE@example.com" → normalized to "alice@example.com" → matches!
```

**Critical rule:** Use the SAME normalizer on write and search. Mixing normalizers breaks lookups.

**Common normalizers by field type:**

| Field Type | Normalizer | Rationale |
|------------|------------|-----------|
| Email | `NormalizeEmail` | RFC 5321: local-part is case-sensitive but domains aren't; in practice, treat as case-insensitive |
| Username | `NormalizeUsername` | Typically case-insensitive |
| Phone | `NormalizePhone` | Strip formatting: `(555) 123-4567` → `5551234567` |
| SSN | `NormalizeNone` | Exact match required |
| Name | `NormalizeNone` or custom | Depends on requirements |

**Note:** The encrypted value (`Ciphertext`) always preserves the original input. Only the `BlindIndex` is computed from the normalized form.

### Key Management

#### Single Master Key with HKDF Derivation

Each `key_id` maps to a single 32-byte master key. The library derives encryption and HMAC keys internally using HKDF:

```go
// User provides one master key
masterKey := []byte("32-byte-master-key-here!!!!!!!!")

// Library internally derives (user never sees these):
encryptionKey := HKDF-SHA256(masterKey, info="encryptedcol-encryption")
hmacKey       := HKDF-SHA256(masterKey, info="encryptedcol-blind-index")
```

**Rationale:**
- Simpler key management: one key to store, rotate, and protect
- Cryptographically sound: HKDF is specifically designed for key derivation
- Lower user error risk: can't accidentally reuse same key for both purposes
- Standard practice: widely used pattern for deriving multiple keys

**Trade-off:** Encryption and HMAC keys rotate together. Independent rotation is not supported, but this is rarely needed.

#### Key Registry

Support multiple key versions for rotation:

```go
cipher := encryptedcol.New(
    encryptedcol.WithKey("v1", masterKey1),
    encryptedcol.WithKey("v2", masterKey2),
    encryptedcol.WithDefaultKeyID("v2"),
)
```

#### Key Provider Interface

For enterprise environments (Vault, KMS):

```go
type KeyProvider interface {
    GetKey(keyID string) ([]byte, error)  // Returns 32-byte master key
    DefaultKeyID() string
    ActiveKeyIDs() []string  // For blind index search across versions
}

cipher := encryptedcol.NewWithProvider(myVaultProvider)
```

#### Simple Path

For straightforward use cases:

```go
cipher := encryptedcol.New(masterKey)
// Internally uses key_id "default"
```

### Row-Level Key Tracking

Since encryption and HMAC keys are derived from the same master key, we only need one column:

| Column | Purpose |
|--------|---------|
| `key_id` | Key version used for all encrypted columns and blind indexes in this row |

**Benefits:**
- Only 1 extra column regardless of encrypted field count
- Clear invariant: all encrypted columns and indexes in a row use same key version
- Simpler migration: rotate one row at a time
- Search: query distinct `key_id` values, compute HMAC for each

### Field Types

Two categories of encrypted fields:

#### Encrypted Only (Non-searchable)

For large text, JSON blobs, or fields never searched by exact match:

- Single column: `{field}_encrypted` (BYTEA)
- No blind index overhead
- Use case: message content, raw JSON payloads

#### Encrypted + Indexed (Searchable)

For fields requiring exact-match search:

- Two columns: `{field}_encrypted` (BYTEA) + `{field}_idx` (BYTEA)
- Blind index enables `WHERE field_idx = ?` queries
- Use case: email, name, external IDs

## Database Schema

### Migration Example

```sql
-- Add encrypted columns (keep original during migration, remove after)
ALTER TABLE users
    ADD COLUMN email_encrypted BYTEA,
    ADD COLUMN email_idx BYTEA,
    ADD COLUMN name_encrypted BYTEA,
    ADD COLUMN name_idx BYTEA,
    ADD COLUMN notes_encrypted BYTEA,  -- No index, not searchable
    ADD COLUMN key_id TEXT NOT NULL DEFAULT 'v1';

-- Index for blind index lookups
CREATE INDEX idx_users_email_idx ON users (email_idx);
CREATE INDEX idx_users_name_idx ON users (name_idx);

-- Composite index for key-aware searches
CREATE INDEX idx_users_email_search ON users (key_id, email_idx);
```

### Ciphertext Format

Encrypted values stored as BYTEA with embedded metadata:

```
Outer format (stored in DB):
+------+----------+-------+----------------------------+
| flag | key_id   | nonce | secretbox_ciphertext       |
| (1B) | (1 byte  | (24B) | (variable)                 |
|      |  length  |       |                            |
|      |  + key_id|       |                            |
|      |  string) |       |                            |
+------+----------+-------+----------------------------+

Flag byte values:
  0x00 = no compression
  0x01 = zstd compressed before encryption
  0x02 = snappy compressed before encryption
```

### Key ID Authentication

**Problem:** secretbox authenticates the message but not additional metadata. The outer key_id is not authenticated—an attacker who could swap key_ids might cause decryption with wrong key.

**Solution:** Include key_id inside the authenticated payload:

```
Plaintext envelope (before encryption):
+----------+------------------+
| key_id   | actual_plaintext |
| (1 byte  | (variable)       |
|  length  |                  |
|  + key_id|                  |
|  string) |                  |
+----------+------------------+
```

**Seal process:**
1. Prepend key_id to plaintext
2. Compress (if enabled and beneficial)
3. Encrypt with secretbox
4. Prepend flag + key_id + nonce to ciphertext

**Open process:**
1. Parse outer key_id from header
2. Select key and decrypt
3. Decompress (if flag indicates)
4. Extract inner key_id from plaintext
5. **Verify inner key_id == outer key_id** (fail if mismatch)
6. Return actual plaintext

```go
func (c *Cipher) Open(ciphertext []byte) ([]byte, error) {
    if ciphertext == nil {
        return nil, nil
    }

    // Parse outer format
    flag, outerKeyID, nonce, encrypted := parseFormat(ciphertext)

    // Decrypt
    key := c.getEncryptionKey(outerKeyID)
    plaintext, ok := secretbox.Open(nil, encrypted, nonce, key)
    if !ok {
        return nil, ErrDecryptionFailed
    }

    // Decompress if needed
    if flag == flagZstd {
        plaintext = zstdDecompress(plaintext)
    }

    // Verify inner key_id matches outer (authentication check)
    innerKeyID, actualPlaintext := parseInnerKeyID(plaintext)
    if innerKeyID != outerKeyID {
        return nil, ErrKeyIDMismatch  // Tampering detected
    }

    return actualPlaintext, nil
}
```

**Why this matters:**
- Prevents key confusion attacks
- Detects tampering with key_id header
- Defense in depth—even if keys were somehow swapped, verification fails

The outer key_id is kept for efficient key lookup (no decryption needed to find the right key), while the inner key_id provides cryptographic binding.

## Library API

### Initialization

```go
package encryptedcol

// Simple: single master key (uses key_id "default")
func New(masterKey []byte) (*Cipher, error)

// Registry: multiple master keys with default
func New(opts ...Option) (*Cipher, error)

type Option func(*config)

func WithKey(keyID string, masterKey []byte) Option
func WithDefaultKeyID(keyID string) Option
func WithCompressionThreshold(bytes int) Option     // Default: 1024
func WithCompressionAlgorithm(algo string) Option   // "zstd" or "snappy"
func WithCompressionDisabled() Option
func WithEmptyStringAsNull() Option                 // Opt-in: treat "" as NULL

// Provider: dynamic key retrieval (Vault, KMS)
func NewWithProvider(provider KeyProvider) (*Cipher, error)

type KeyProvider interface {
    GetKey(keyID string) ([]byte, error)  // Returns 32-byte master key
    DefaultKeyID() string
    ActiveKeyIDs() []string
}
```

### Core Operations

```go
// Seal encrypts plaintext using the default key
// Returns ciphertext with embedded key_id
func (c *Cipher) Seal(plaintext []byte) []byte

// SealWithKey encrypts using a specific key version
func (c *Cipher) SealWithKey(keyID string, plaintext []byte) ([]byte, error)

// Open decrypts ciphertext, auto-detecting key from embedded key_id
func (c *Cipher) Open(ciphertext []byte) ([]byte, error)

// OpenWithKey decrypts using explicit key (for when key_id is stored separately)
func (c *Cipher) OpenWithKey(keyID string, ciphertext []byte) ([]byte, error)

// BlindIndex computes HMAC for searchable encryption using default HMAC key
func (c *Cipher) BlindIndex(plaintext []byte) []byte

// BlindIndexWithKey computes HMAC using specific key version
func (c *Cipher) BlindIndexWithKey(keyID string, plaintext []byte) ([]byte, error)

// BlindIndexes computes HMAC for all active key versions (for search queries)
func (c *Cipher) BlindIndexes(plaintext []byte) map[string][]byte

// DefaultKeyID returns the current default key identifier
func (c *Cipher) DefaultKeyID() string

// ActiveKeyIDs returns all registered key identifiers
func (c *Cipher) ActiveKeyIDs() []string
```

### Error Types

```go
var (
    // ErrDecryptionFailed - secretbox authentication failed (wrong key or corrupted data)
    ErrDecryptionFailed = errors.New("encryptedcol: decryption failed")

    // ErrKeyIDMismatch - inner key_id doesn't match outer (tampering detected)
    ErrKeyIDMismatch = errors.New("encryptedcol: key_id mismatch")

    // ErrKeyNotFound - requested key_id not in registry or provider
    ErrKeyNotFound = errors.New("encryptedcol: key not found")

    // ErrInvalidKeySize - master key must be exactly 32 bytes
    ErrInvalidKeySize = errors.New("encryptedcol: key must be 32 bytes")

    // ErrWasNull - ciphertext was nil (database NULL)
    // Returned by OpenString when input is nil; value will be ""
    ErrWasNull = errors.New("encryptedcol: value was null")

    // ErrDecompressionFailed - zstd/snappy decompression failed
    ErrDecompressionFailed = errors.New("encryptedcol: decompression failed")
)
```

### Type-Safe Helpers

Most developers work with strings, integers, and JSON structs—not raw bytes. These helpers eliminate boilerplate:

```go
// === String helpers (value-based, empty string preserved) ===
func (c *Cipher) SealString(s string) []byte                    // "" → ciphertext
func (c *Cipher) OpenString(ciphertext []byte) (string, error)  // nil → "", ErrWasNull

func (c *Cipher) SealStringIndexed(s string) *SealedValue
func (c *Cipher) SealStringIndexedNormalized(s string, norm Normalizer) *SealedValue
func (c *Cipher) BlindIndexString(s string) []byte

// === String helpers (pointer-based, explicit NULL) ===
func (c *Cipher) SealStringPtr(s *string) []byte                    // nil → nil
func (c *Cipher) OpenStringPtr(ciphertext []byte) (*string, error)  // nil → nil

// === JSON helpers (generic) ===
func SealJSON[T any](c *Cipher, data T) ([]byte, error)
func OpenJSON[T any](c *Cipher, ciphertext []byte) (T, error)

func SealJSONIndexed[T any](c *Cipher, data T) (*SealedValue, error)

// === Integer helpers ===
func (c *Cipher) SealInt64(n int64) []byte
func (c *Cipher) OpenInt64(ciphertext []byte) (int64, error)

// === NULL check ===
func (c *Cipher) WasNull(ciphertext []byte) bool
```

**Usage example:**

```go
// Before (verbose)
emailSealed := cipher.SealIndexed([]byte(user.Email))
email, _ := cipher.Open(emailEnc)
user.Email = string(email)

// After (clean)
emailSealed := cipher.SealStringIndexed(user.Email)
user.Email, _ = cipher.OpenString(emailEnc)

// JSON struct
type Metadata struct {
    Tags   []string `json:"tags"`
    Source string   `json:"source"`
}
ciphertext, _ := encryptedcol.SealJSON(cipher, metadata)
metadata, _ := encryptedcol.OpenJSON[Metadata](cipher, ciphertext)
```

### NULL vs Empty String Handling

**Semantic distinction:**
- `nil` / NULL = "value is unknown/not set"
- `""` (empty string) = "value is known to be empty"

The library preserves this distinction by default:

```go
// === Bytes API ===
cipher.Seal(nil)         // returns nil (NULL)
cipher.Seal([]byte{})    // returns ciphertext (empty byte slice is a value)

cipher.Open(nil)         // returns nil, nil (NULL in, NULL out)
cipher.Open(ciphertext)  // returns []byte{}, nil (if originally empty)

// === String API ===
cipher.SealString("hello")  // returns ciphertext
cipher.SealString("")       // returns ciphertext (empty string IS a value)

// For actual NULL, use pointer variant:
cipher.SealStringPtr(nil)           // returns nil (NULL)
cipher.SealStringPtr(ptr("hello"))  // returns ciphertext

// === Decryption ===
cipher.OpenString(nil)              // returns "", false (was NULL, not empty string)
cipher.OpenString(ciphertext)       // returns "", true (was empty string)

// Or use pointer variant for explicit NULL handling:
cipher.OpenStringPtr(nil)           // returns nil (NULL)
cipher.OpenStringPtr(ciphertext)    // returns *string (empty string or value)
```

**API signatures:**

```go
// Value-based (empty string is preserved)
func (c *Cipher) SealString(s string) []byte           // "" → ciphertext
func (c *Cipher) OpenString(ct []byte) (string, error) // nil → "", ErrWasNull

// Pointer-based (explicit NULL handling)
func (c *Cipher) SealStringPtr(s *string) []byte           // nil → nil, "" → ciphertext
func (c *Cipher) OpenStringPtr(ct []byte) (*string, error) // nil → nil, ciphertext → *string

// Check if decrypted value was NULL
func (c *Cipher) WasNull(ct []byte) bool  // true if ct is nil
```

**Opt-in space optimization:**

If you truly want empty strings treated as NULL (saves ~50 bytes per field):

```go
cipher := encryptedcol.New(
    encryptedcol.WithKey("v1", masterKey),
    encryptedcol.WithEmptyStringAsNull(),  // Opt-in: "" → nil
)
```

**Repository example with nullable field:**

```go
func (r *Repo) GetUser(ctx context.Context, id uuid.UUID) (*User, error) {
    var user User
    var nicknameEnc []byte  // Will be nil if DB column is NULL

    err := r.pool.QueryRow(ctx, query, id).Scan(&user.ID, &nicknameEnc)
    if err != nil {
        return nil, err
    }

    // Option 1: Pointer field (recommended for nullable)
    user.Nickname, err = r.cipher.OpenStringPtr(nicknameEnc)
    // user.Nickname is nil if DB was NULL, or *string if had value

    // Option 2: Value field with NULL check
    if nicknameEnc != nil {
        user.NicknameValue, err = r.cipher.OpenString(nicknameEnc)
    }
    // user.NicknameValue is "" if DB was NULL (ambiguous with actual empty string)

    return &user, nil
}
```

**Recommendation:** Use pointer fields (`*string`) in your models for nullable encrypted columns. This maps cleanly to database NULL semantics.

### Convenience Types

```go
// SealedValue holds encrypted data with its blind index (for indexed fields)
type SealedValue struct {
    Ciphertext []byte
    BlindIndex []byte
    KeyID      string  // Same key used for both encryption and blind index
}

// SealIndexed encrypts and computes blind index in one call
func (c *Cipher) SealIndexed(plaintext []byte) *SealedValue
```

### Search Helpers

```go
// SearchCondition generates SQL WHERE clause for blind index search
// across all active key versions
type SearchCondition struct {
    SQL    string            // e.g., "(key_id = $1 AND email_idx = $2) OR ..."
    Args   []interface{}     // Interleaved key_ids and blind indexes
}

func (c *Cipher) SearchCondition(column string, plaintext []byte, paramOffset int) *SearchCondition
func (c *Cipher) SearchConditionString(column string, plaintext string, paramOffset int) *SearchCondition
func (c *Cipher) SearchConditionStringNormalized(column, plaintext string, paramOffset int, norm Normalizer) *SearchCondition

// Example usage:
cond := cipher.SearchConditionStringNormalized("email", "alice@example.com", 1, encryptedcol.NormalizeEmail)
query := fmt.Sprintf("SELECT * FROM users WHERE %s", cond.SQL)
rows, _ := pool.Query(ctx, query, cond.Args...)
```

**Implementation detail:**

The paramOffset logic handles composing with other WHERE clauses:

```go
func (c *Cipher) SearchCondition(colName string, plaintext []byte, paramOffset int) *SearchCondition {
    ids := c.ActiveKeyIDs()

    var parts []string
    var args []interface{}

    for _, keyID := range ids {
        // Compute blind index for this key version
        idxHash, _ := c.BlindIndexWithKey(keyID, plaintext)

        // Build SQL fragment with correct parameter numbers
        part := fmt.Sprintf("(key_id = $%d AND %s_idx = $%d)", paramOffset, colName, paramOffset+1)

        parts = append(parts, part)
        args = append(args, keyID, idxHash)
        paramOffset += 2
    }

    return &SearchCondition{
        SQL:  strings.Join(parts, " OR "),
        Args: args,
    }
}
```

**Example with 2 active keys (v1, v2):**

```go
cond := cipher.SearchConditionString("email", "alice@example.com", 1)

// cond.SQL:
// "(key_id = $1 AND email_idx = $2) OR (key_id = $3 AND email_idx = $4)"

// cond.Args:
// ["v1", <hmac_v1_bytes>, "v2", <hmac_v2_bytes>]
```

**Composing with other conditions:**

```go
// Start at $3 because $1 and $2 are used by other conditions
cond := cipher.SearchConditionString("email", email, 3)

query := `SELECT * FROM users WHERE tenant_id = $1 AND status = $2 AND (` + cond.SQL + `)`
args := append([]interface{}{tenantID, "active"}, cond.Args...)
rows, _ := pool.Query(ctx, query, args...)
```

## Integration Pattern

### Repository Layer

```go
type UserRepository struct {
    pool   *pgxpool.Pool
    cipher *encryptedcol.Cipher
}

// Create with encryption
func (r *UserRepository) Create(ctx context.Context, user *User) error {
    // Encrypt indexed fields with normalization
    // Email: normalize for case-insensitive lookup, preserve original in ciphertext
    emailSealed := r.cipher.SealStringIndexedNormalized(user.Email, encryptedcol.NormalizeEmail)
    // Name: case-sensitive (no normalization)
    nameSealed := r.cipher.SealStringIndexed(user.Name)

    // Encrypt non-indexed fields
    notesEncrypted := r.cipher.SealString(user.Notes)

    query := `
        INSERT INTO users (
            id, email_encrypted, email_idx, name_encrypted, name_idx,
            notes_encrypted, key_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
    `

    _, err := r.pool.Exec(ctx, query,
        user.ID,
        emailSealed.Ciphertext, emailSealed.BlindIndex,
        nameSealed.Ciphertext, nameSealed.BlindIndex,
        notesEncrypted,
        r.cipher.DefaultKeyID(),
    )
    return err
}

// Read with decryption
func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
    query := `
        SELECT id, email_encrypted, name_encrypted, notes_encrypted
        FROM users WHERE id = $1
    `

    var user User
    var emailEnc, nameEnc, notesEnc []byte

    err := r.pool.QueryRow(ctx, query, id).Scan(
        &user.ID, &emailEnc, &nameEnc, &notesEnc,
    )
    if err != nil {
        return nil, err
    }

    // Decrypt using type-safe helpers (handles NULL gracefully)
    user.Email, _ = r.cipher.OpenString(emailEnc)
    user.Name, _ = r.cipher.OpenString(nameEnc)
    user.Notes, _ = r.cipher.OpenString(notesEnc)

    return &user, nil
}

// Search using blind index (MUST use same normalizer as Create)
func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*User, error) {
    cond := r.cipher.SearchConditionStringNormalized("email", email, 1, encryptedcol.NormalizeEmail)

    query := fmt.Sprintf(`
        SELECT id, email_encrypted, name_encrypted, notes_encrypted
        FROM users WHERE %s
    `, cond.SQL)

    // ... execute query with cond.Args
}
```

### Model Layer

Models remain clean domain objects:

```go
// Domain model - no encryption concerns
type User struct {
    ID    uuid.UUID
    Email string
    Name  string
    Notes string
}

// No changes needed to domain layer
```

### Why Not sql.Scanner/driver.Valuer?

An alternative approach would be to implement `sql.Scanner` and `driver.Valuer` interfaces on wrapper types:

```go
// Hypothetical wrapper (NOT recommended)
type EncryptedString struct {
    cipher *Cipher
    Value  string
}

func (e *EncryptedString) Scan(src interface{}) error {
    ct, _ := src.([]byte)
    e.Value, _ = e.cipher.OpenString(ct)
    return nil
}

func (e *EncryptedString) Value() (driver.Value, error) {
    return e.cipher.SealString(e.Value), nil
}
```

**Why we chose Repository pattern instead:**

| Aspect | Scanner/Valuer | Repository Pattern |
|--------|----------------|-------------------|
| Domain purity | Polluted (needs Cipher reference) | Clean POJOs |
| Testability | Harder (mock Cipher in structs) | Easier (inject mock repo) |
| Cipher lifecycle | Tricky (who sets it?) | Clear (repo owns it) |
| NULL handling | Awkward with value types | Natural with explicit calls |
| Normalization | Hidden magic | Explicit in code |
| Debugging | Black box | Visible in repo |

**Recommendation:** Keep domain models pure. Handle encryption explicitly in the Repository layer. The verbosity is worth the clarity and testability.

## Key Rotation

### Design Decision: Row-Level Key Consistency

All encrypted columns in a row share the same `key_id`. This is intentional:

**Scenario:** You have rows encrypted with v1, then add a new `ssn_encrypted` column and set default key to v2.

**Behavior:** When updating an existing row to add SSN, you must re-encrypt the entire row to v2.

**Why this is good:**
- Forces key hygiene—no mixed key versions within a row
- Simplifies querying—single `key_id` column for all encrypted fields
- Encourages regular rotation rather than perpetual v1 data

**Alternative considered:** Per-column key tracking would allow SSN at v2 while email stays at v1, but adds complexity (N key_id columns) and allows stale keys to linger indefinitely.

### Process

1. **Add new key** to cipher configuration
2. **Set new key as default** for new writes
3. **Migrate existing rows** in batches:
   - Read row (decrypts with old key via embedded key_id)
   - Re-encrypt with new key
   - Update row with new ciphertext and key_id
4. **Remove old key** from configuration after full migration

### Migration Helper

```go
// RotateValue re-encrypts a single value with the current default key
// Handles NULL gracefully: nil in → nil out
func (c *Cipher) RotateValue(oldCiphertext []byte) ([]byte, error) {
    if oldCiphertext == nil {
        return nil, nil  // NULL stays NULL
    }
    plaintext, err := c.Open(oldCiphertext)
    if err != nil {
        return nil, err
    }
    return c.Seal(plaintext), nil
}

// RotateBlindIndex recomputes blind index with current default key
// Handles NULL gracefully: nil in → nil out
func (c *Cipher) RotateBlindIndex(plaintext []byte) []byte {
    if plaintext == nil {
        return nil
    }
    return c.BlindIndex(plaintext)
}
```

**Batch migration example:**

```go
func (r *Repo) RotateBatch(ctx context.Context, oldKeyID string, limit int) (int, error) {
    query := `
        SELECT id, email_encrypted, name_encrypted, ssn_encrypted, notes_encrypted
        FROM users
        WHERE key_id = $1
        LIMIT $2
    `
    rows, err := r.pool.Query(ctx, query, oldKeyID, limit)
    if err != nil {
        return 0, err
    }
    defer rows.Close()

    var count int
    for rows.Next() {
        var id uuid.UUID
        var emailEnc, nameEnc, ssnEnc, notesEnc []byte

        if err := rows.Scan(&id, &emailEnc, &nameEnc, &ssnEnc, &notesEnc); err != nil {
            return count, err
        }

        // Decrypt to get plaintext (for blind index recomputation)
        email, _ := r.cipher.OpenString(emailEnc)  // Handles NULL
        name, _ := r.cipher.OpenString(nameEnc)
        ssn, _ := r.cipher.OpenString(ssnEnc)      // May be NULL for old rows

        // Re-encrypt with new key
        newEmailEnc := r.cipher.SealString(email)
        newNameEnc := r.cipher.SealString(name)
        newSsnEnc := r.cipher.SealString(ssn)      // NULL → nil → NULL
        newNotesEnc, _ := r.cipher.RotateValue(notesEnc)

        // Recompute blind indexes
        newEmailIdx := r.cipher.BlindIndexString(email)
        newNameIdx := r.cipher.BlindIndexString(name)
        newSsnIdx := r.cipher.BlindIndexString(ssn)  // NULL → nil

        updateQuery := `
            UPDATE users SET
                email_encrypted = $2, email_idx = $3,
                name_encrypted = $4, name_idx = $5,
                ssn_encrypted = $6, ssn_idx = $7,
                notes_encrypted = $8,
                key_id = $9
            WHERE id = $1
        `
        _, err := r.pool.Exec(ctx, updateQuery, id,
            newEmailEnc, newEmailIdx,
            newNameEnc, newNameIdx,
            newSsnEnc, newSsnIdx,
            newNotesEnc,
            r.cipher.DefaultKeyID(),
        )
        if err != nil {
            return count, err
        }
        count++
    }
    return count, nil
}
```

**Key points:**
- NULL values remain NULL after rotation (no panics)
- New columns (like `ssn`) that are NULL on old rows stay NULL
- Blind indexes are recomputed from plaintext, not rotated from old index
- Single transaction per row for consistency

## Performance Considerations

### HKDF Key Caching (Critical)

HKDF derivation must happen once at initialization, not on every operation.

**Wrong:**
```go
func (c *Cipher) Seal(plaintext []byte) []byte {
    key := hkdf.Derive(c.masterKey, "encryption")  // ❌ Called every time
    return secretbox.Seal(nil, plaintext, nonce, key)
}
```

**Correct:**
```go
type derivedKeys struct {
    encryption [32]byte
    hmac       [32]byte
}

type Cipher struct {
    keys      map[string]*derivedKeys  // Cached derived keys
    defaultID string
}

func (c *Cipher) addKey(keyID string, masterKey []byte) {
    // Derive once at registration, cache forever
    c.keys[keyID] = &derivedKeys{
        encryption: hkdfDerive(masterKey, "encryptedcol-encryption"),
        hmac:       hkdfDerive(masterKey, "encryptedcol-blind-index"),
    }
}

func (c *Cipher) Seal(plaintext []byte) []byte {
    keys := c.keys[c.defaultID]  // ✓ O(1) map lookup
    return secretbox.Seal(nil, plaintext, nonce, &keys.encryption)
}
```

### Search Performance with Multiple Active Keys

During rotation, searches query all active key versions:

```sql
-- 2 active keys = 2 index seeks
WHERE (key_id = 'v1' AND email_idx = $1)
   OR (key_id = 'v2' AND email_idx = $2)
```

**Analysis:** With composite index `(key_id, email_idx)`, PostgreSQL handles each OR branch as a separate index seek. This is O(N) where N = active key count.

**Recommendations:**
- Keep rotation windows short—complete migrations promptly
- Maximum 2-3 active keys during rotation
- Monitor: `SELECT DISTINCT key_id FROM table` to track active keys
- After migration completes, remove old key from cipher configuration

### Batch Migration Optimization

The basic migration example uses one UPDATE per row. For large tables, use batched operations:

**Basic (N round trips):**
```go
for rows.Next() {
    pool.Exec(ctx, updateQuery, args...)  // One round trip per row
}
```

**Optimized (1 round trip per batch):**
```go
func (r *Repo) RotateBatchOptimized(ctx context.Context, oldKeyID string, batchSize int) error {
    tx, err := r.pool.Begin(ctx)
    if err != nil {
        return err
    }
    defer tx.Rollback(ctx)

    // Prepare statement once
    _, err = tx.Prepare(ctx, "rotate_user", `
        UPDATE users SET
            email_encrypted = $2, email_idx = $3,
            name_encrypted = $4, name_idx = $5,
            key_id = $6
        WHERE id = $1
    `)
    if err != nil {
        return err
    }

    rows, err := tx.Query(ctx, selectQuery, oldKeyID, batchSize)
    if err != nil {
        return err
    }

    // Use pgx Batch for pipelining
    batch := &pgx.Batch{}
    for rows.Next() {
        // ... decrypt, re-encrypt ...
        batch.Queue("rotate_user", id, emailEnc, emailIdx, nameEnc, nameIdx, newKeyID)
    }
    rows.Close()

    // Send all updates in one round trip
    br := tx.SendBatch(ctx, batch)
    defer br.Close()

    // Check results
    for i := 0; i < batch.Len(); i++ {
        if _, err := br.Exec(); err != nil {
            return err
        }
    }

    return tx.Commit(ctx)
}
```

**Performance comparison:**
| Approach | 1000 rows | Network round trips |
|----------|-----------|---------------------|
| Basic | ~1000ms | 1000 |
| Batched | ~50ms | 2 (SELECT + batch UPDATE) |

### Compression Decision Overhead

Auto-compression checks size threshold before compressing:

```go
if len(plaintext) > threshold {
    compressed := zstd.Compress(plaintext)
    if len(compressed) < len(plaintext) * 0.9 {  // 10% minimum savings
        return compressed
    }
}
```

**Recommendations:**
- Default threshold: 1KB (small data skips compression entirely)
- Require 10% minimum savings to use compressed output
- For known-incompressible data, use `SealUncompressed()` explicitly
- JSON and text typically compress 60-80%; already-compressed data won't benefit

### Memory Allocation and Buffer Pooling

For hot paths (frequent DB reads/writes), implement buffer pooling from Day 1.

**Challenge:** secretbox.Seal appends to destination slice. Naive pooling risks returning pooled memory to caller.

**Correct implementation:**

```go
type Cipher struct {
    // ... other fields ...
    bufferPool sync.Pool
}

func NewCipher(...) *Cipher {
    return &Cipher{
        bufferPool: sync.Pool{
            New: func() interface{} {
                buf := make([]byte, 0, 8192)
                return &buf
            },
        },
    }
}

func (c *Cipher) Seal(plaintext []byte) []byte {
    // Calculate final size upfront
    // Format: flag(1) + keyIDLen(1) + keyID(n) + nonce(24) + ciphertext(len+overhead)
    keyID := c.defaultKeyID
    finalSize := 1 + 1 + len(keyID) + 24 + len(plaintext) + secretbox.Overhead

    // Get pooled buffer for intermediate work (compression, format assembly)
    bufPtr := c.bufferPool.Get().(*[]byte)
    workBuf := (*bufPtr)[:0]
    defer c.bufferPool.Put(bufPtr)

    // Compress if beneficial (uses workBuf)
    compressed := c.maybeCompress(plaintext, workBuf)

    // Allocate final output (this is what caller receives)
    output := make([]byte, 0, finalSize)

    // Write header
    output = append(output, flagByte)
    output = append(output, byte(len(keyID)))
    output = append(output, keyID...)
    output = append(output, nonce[:]...)

    // secretbox.Seal appends ciphertext to output
    return secretbox.Seal(output, compressed, &nonce, &c.keys[keyID].encryption)
}
```

**Key insight:** Pool buffers for intermediate work (compression, format parsing), but allocate fresh for return values. Caller must own returned memory.

**Alternative: Caller-provided buffer:**

```go
// SealInto writes to caller's buffer, returns slice of used portion
// Caller responsible for buffer lifecycle
func (c *Cipher) SealInto(dst, plaintext []byte) []byte {
    // ... write directly to dst ...
    return dst[:n]
}

// Usage with pool managed by caller
buf := myPool.Get().([]byte)
result := cipher.SealInto(buf, plaintext)
// ... use result ...
myPool.Put(buf)
```

**Recommendation:** Implement internal pooling for compression buffers. Profile before adding caller-provided buffer API.

### Performance Summary

| Concern | Severity | Implementation Requirement |
|---------|----------|---------------------------|
| HKDF caching | **Critical** | Cache derived keys at init |
| Buffer pooling | **Medium** | Pool compression buffers from Day 1 |
| Multi-key search | Low | Document max active keys |
| Migration batching | Medium | Provide batched helper |
| Compression threshold | Low | Default 1KB, 10% min savings |

### No Double Round Trips

The design avoids unnecessary round trips:
- **Writes:** Go → single INSERT → DB ✓
- **Reads:** DB → single SELECT → Go (decrypt in memory) ✓
- **Search:** Single query with OR conditions ✓
- **Key lookup:** In-memory map, O(1) ✓

## Security Considerations

### Strengths

- **Zero-knowledge storage:** Database never sees plaintext
- **Authenticated encryption:** Tampering detected on decryption
- **Key separation:** Encryption and HMAC keys are derived independently via HKDF
- **Key rotation:** Built-in support for multiple key versions

### Limitations

- **Blind index leaks frequency:** Identical plaintexts produce identical indexes
- **No range queries:** Only exact match supported on encrypted fields
- **No partial search:** Cannot search "contains" or "starts with"
- **Application trust:** Application must be trusted (has keys)

### Mitigations

- Use blind indexing only for fields requiring search
- Monitor for frequency analysis attempts
- Consider adding salt per-tenant for multi-tenant systems
- Rotate keys regularly (rotates both encryption and HMAC together via HKDF)

## Changes Required for Integration

### Airborne Example

| Component | Changes |
|-----------|---------|
| **Schema** | Add `_encrypted`, `_idx` columns; add `key_id` column |
| **Models** | None (domain objects unchanged) |
| **Repository** | Update SQL column names, add encrypt/decrypt calls |
| **Service** | None (uses domain objects) |
| **Config** | Add key configuration |

**Estimated effort:** 15-20% of repository code, plus schema migration.

### Files to Modify (Airborne)

1. `internal/db/models.go` - No changes to domain structs
2. `internal/db/repository.go` - Add cipher, update queries
3. `internal/db/postgres.go` - Initialize cipher at connection time
4. `migrations/` - Add migration for new columns
5. `internal/config/config.go` - Add encryption key configuration

## Dependencies

```
golang.org/x/crypto/nacl/secretbox  # XSalsa20-Poly1305 encryption
golang.org/x/crypto/hkdf            # Key derivation
github.com/klauspost/compress/zstd  # Compression (optional, for large fields)
```

All dependencies are well-maintained and widely used.

## Distribution

### Option 1: Private Git Repository (Recommended)

Host on GitHub/GitLab as a private repository:

```bash
# Module path in go.mod
module github.com/yourorg/encryptedcol
```

**Consumer setup:**

```bash
# Configure Git for private repos (one-time)
git config --global url."git@github.com:".insteadOf "https://github.com/"

# Or use GOPRIVATE environment variable
export GOPRIVATE=github.com/yourorg/*

# Then import normally
go get github.com/yourorg/encryptedcol
```

**In consumer's go.mod:**

```go
require github.com/yourorg/encryptedcol v1.0.0
```

**In consumer's code:**

```go
import "github.com/yourorg/encryptedcol"

func main() {
    cipher, _ := encryptedcol.New(
        encryptedcol.WithKey("v1", masterKey),
    )
    // ...
}
```

### Option 2: Public Git Repository

If open-sourcing, host publicly on GitHub:

```bash
# Consumers just go get
go get github.com/yourorg/encryptedcol
```

### Option 3: Vendoring (Copy into Projects)

Copy the `encryptedcol/` directory into each consuming project:

```
airborne/
├── internal/
│   └── encryptedcol/    # Copied here
│       ├── cipher.go
│       └── ...
```

**Pros:** No external dependency, full control
**Cons:** Manual updates, code duplication

**Import path:**

```go
import "github.com/yourorg/airborne/internal/encryptedcol"
```

### Option 4: Go Workspace (Monorepo)

If all projects are in one repository:

```
_code/
├── go.work
├── encryptedcol/
│   └── go.mod
├── airborne/
│   └── go.mod
└── dispatch/
    └── go.mod
```

**go.work:**

```go
go 1.21

use (
    ./encryptedcol
    ./airborne
    ./dispatch
)
```

**Consumer go.mod:**

```go
module github.com/yourorg/airborne

require github.com/yourorg/encryptedcol v0.0.0

replace github.com/yourorg/encryptedcol => ../encryptedcol
```

### Versioning Strategy

Use semantic versioning:

```
v1.0.0  - Initial stable release
v1.1.0  - New features (backward compatible)
v1.1.1  - Bug fixes
v2.0.0  - Breaking changes (if ever needed)
```

**Tagging releases:**

```bash
git tag v1.0.0
git push origin v1.0.0
```

### Recommended Approach for Your Setup

Given your projects (Airborne, Dispatch, etc.) are in `_code/`:

**Phase 1 (Development):** Use Go Workspace
- Quick iteration without pushing tags
- Local `replace` directives

**Phase 2 (Production):** Private Git Repository
- Create `github.com/yourorg/encryptedcol` (private)
- Tag releases
- Remove `replace` directives from consumers
- Proper versioning and dependency management

## Package Structure

```
encryptedcol/
├── cipher.go         # Core Cipher type, Seal/Open/BlindIndex
├── helpers.go        # Type-safe helpers (SealString, OpenJSON, etc.)
├── normalize.go      # Normalizer functions (NormalizeEmail, NormalizePhone, etc.)
├── kdf.go            # HKDF key derivation (master key → encryption + HMAC keys)
├── options.go        # Configuration options (WithKey, etc.)
├── provider.go       # KeyProvider interface
├── search.go         # SearchCondition helper
├── format.go         # Ciphertext format encoding/decoding (flag, key_id, nonce, data)
├── compress.go       # Zstd/Snappy compression helpers
├── errors.go         # Error types
└── encryptedcol_test.go
```

## Example Usage

```go
package main

import (
    "github.com/yourorg/encryptedcol"
)

func main() {
    // Initialize with master keys (HKDF derives encryption + HMAC keys internally)
    cipher, err := encryptedcol.New(
        encryptedcol.WithKey("v1", []byte("32-byte-master-key-here!!!!!!!!")),
        encryptedcol.WithKey("v2", []byte("another-32-byte-master-key!!!!!")),
        encryptedcol.WithDefaultKeyID("v2"),
    )
    if err != nil {
        panic(err)
    }

    // Simple path: single key
    // cipher, _ := encryptedcol.New([]byte("32-byte-master-key-here!!!!!!!!"))

    // === Type-safe helpers (recommended) ===

    // Encrypt string (non-indexed)
    ciphertext := cipher.SealString("sensitive notes")

    // Decrypt to string (handles NULL gracefully)
    text, _ := cipher.OpenString(ciphertext)

    // Encrypt with blind index (for searchable fields)
    // Use normalization for case-insensitive fields like email
    sealed := cipher.SealStringIndexedNormalized("Alice@Example.COM", encryptedcol.NormalizeEmail)
    // sealed.Ciphertext contains "Alice@Example.COM" (original preserved)
    // sealed.BlindIndex = HMAC("alice@example.com") (normalized for search)
    // sealed.KeyID      -> key_id column

    // JSON struct encryption
    type Metadata struct {
        Tags []string `json:"tags"`
    }
    jsonCiphertext, _ := encryptedcol.SealJSON(cipher, Metadata{Tags: []string{"vip"}})
    meta, _ := encryptedcol.OpenJSON[Metadata](cipher, jsonCiphertext)

    // === Search across all key versions ===
    // Use same normalizer as when sealing!
    cond := cipher.SearchConditionStringNormalized("email", "ALICE@example.com", 1, encryptedcol.NormalizeEmail)
    // Normalized to "alice@example.com" before HMAC → matches the sealed value above
    // cond.SQL  -> "(key_id = $1 AND email_idx = $2) OR (key_id = $3 AND email_idx = $4)"
    // cond.Args -> ["v1", hmac_v1, "v2", hmac_v2]

    // === NULL vs Empty String ===
    cipher.SealString("")           // Returns ciphertext (empty string IS a value)
    cipher.SealStringPtr(nil)       // Returns nil (actual NULL)
    cipher.OpenStringPtr(nil)       // Returns nil (NULL from DB)
    s, _ := cipher.OpenStringPtr(ciphertext)  // Returns *string

    // === Raw bytes API (still available) ===
    raw := cipher.Seal([]byte("binary data"))
    data, _ := cipher.Open(raw)
    _, _, _, _ = text, meta, data, s  // Use variables
}
```

## Requirements

- **Go version:** 1.21+ (for generics in `SealJSON`/`OpenJSON`)
- **PostgreSQL:** 12+ (BYTEA support, standard)
- **Supabase:** Compatible with all versions

## Testing Strategy

### Unit Tests

```go
// cipher_test.go - Core encryption/decryption
func TestSealOpen_RoundTrip(t *testing.T)
func TestSealOpen_DifferentKeys(t *testing.T)
func TestSealOpen_KeyIDAuthentication(t *testing.T)
func TestSealOpen_NULLHandling(t *testing.T)
func TestSealOpen_EmptyString(t *testing.T)
func TestSealOpen_Compression(t *testing.T)

// blindindex_test.go - HMAC blind indexing
func TestBlindIndex_Deterministic(t *testing.T)
func TestBlindIndex_DifferentKeysProduceDifferentHashes(t *testing.T)
func TestBlindIndex_Normalization(t *testing.T)

// search_test.go - Search condition generation
func TestSearchCondition_SingleKey(t *testing.T)
func TestSearchCondition_MultipleKeys(t *testing.T)
func TestSearchCondition_ParamOffset(t *testing.T)

// format_test.go - Ciphertext format parsing
func TestFormat_RoundTrip(t *testing.T)
func TestFormat_KeyIDExtraction(t *testing.T)
func TestFormat_CompressionFlag(t *testing.T)

// kdf_test.go - Key derivation
func TestHKDF_DeterministicDerivation(t *testing.T)
func TestHKDF_DifferentInfoProducesDifferentKeys(t *testing.T)
```

### Integration Tests

```go
// integration_test.go - With real PostgreSQL
func TestIntegration_InsertAndRetrieve(t *testing.T)
func TestIntegration_BlindIndexSearch(t *testing.T)
func TestIntegration_KeyRotation(t *testing.T)
func TestIntegration_NULLColumns(t *testing.T)
```

### Benchmarks

```go
// benchmark_test.go
func BenchmarkSeal_SmallPayload(b *testing.B)      // 100 bytes
func BenchmarkSeal_MediumPayload(b *testing.B)    // 10KB
func BenchmarkSeal_LargePayload(b *testing.B)     // 1MB
func BenchmarkOpen_SmallPayload(b *testing.B)
func BenchmarkBlindIndex(b *testing.B)
func BenchmarkSearchCondition_2Keys(b *testing.B)
func BenchmarkSearchCondition_5Keys(b *testing.B)
```

### Test Vectors

Include known test vectors for:
- HKDF derivation (compare against reference implementation)
- secretbox encryption (compare against NaCl test vectors)
- HMAC-SHA256 (compare against RFC 4231 test vectors)

## Quick Reference

### Seal/Open

| Method | Input | Output | Use Case |
|--------|-------|--------|----------|
| `Seal([]byte)` | bytes | ciphertext | Raw binary |
| `Open([]byte)` | ciphertext | bytes, error | Raw binary |
| `SealString(string)` | string | ciphertext | Text fields |
| `OpenString([]byte)` | ciphertext | string, error | Text fields |
| `SealStringPtr(*string)` | *string | ciphertext/nil | Nullable text |
| `OpenStringPtr([]byte)` | ciphertext | *string, error | Nullable text |
| `SealJSON[T](T)` | struct | ciphertext, error | JSON blobs |
| `OpenJSON[T]([]byte)` | ciphertext | T, error | JSON blobs |

### Indexed (Searchable) Fields

| Method | Input | Output | Use Case |
|--------|-------|--------|----------|
| `SealStringIndexed(string)` | string | SealedValue | Searchable, case-sensitive |
| `SealStringIndexedNormalized(string, Normalizer)` | string, norm | SealedValue | Searchable, normalized |
| `BlindIndexString(string)` | string | index bytes | Index only |
| `SearchConditionStringNormalized(col, val, offset, norm)` | params | SearchCondition | Query building |

### Normalizers

| Normalizer | Transformation | Use For |
|------------|---------------|---------|
| `NormalizeEmail` | lowercase + trim | Email addresses |
| `NormalizeUsername` | lowercase + trim | Usernames |
| `NormalizePhone` | digits only | Phone numbers |
| `NormalizeNone` | identity | Exact match |

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `WithKey(id, key)` | required | Register master key |
| `WithDefaultKeyID(id)` | first key | Default for new encryptions |
| `WithCompressionThreshold(n)` | 1024 | Compress if > n bytes |
| `WithCompressionAlgorithm(algo)` | "zstd" | "zstd" or "snappy" |
| `WithCompressionDisabled()` | enabled | Disable compression |
| `WithEmptyStringAsNull()` | false | Treat "" as NULL |

## Future Considerations

- **Per-tenant keys:** Support different keys for different tenants
- **Field-level key assignment:** Different keys for different sensitivity levels
- **Audit logging:** Track key usage for compliance
- **HSM integration:** Hardware security module support via provider interface
- **Deterministic encryption option:** For when blind indexing overhead isn't acceptable (with security trade-offs documented)
