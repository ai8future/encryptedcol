# encryptedcol -- Product Overview

## What This Product Is

encryptedcol is a Go library that encrypts sensitive data **before** it ever reaches the database. It is purpose-built for applications that use PostgreSQL or Supabase as their data store and need to protect personally identifiable information (PII), financial data, health records, or any other sensitive field at the column level -- while still being able to search on those fields.

The library sits in the application layer. The database never sees, processes, or stores plaintext for any field protected by encryptedcol. What it stores is opaque ciphertext and opaque HMAC-based hashes. This establishes a **zero-knowledge storage model**: a compromised database, a rogue DBA, or a Supabase breach yields nothing intelligible.

---

## Why This Product Exists

### The Core Business Problem

Modern applications collect and store sensitive user data -- emails, phone numbers, social security numbers, medical records, financial identifiers. Regulations (GDPR, HIPAA, PCI-DSS, SOC 2) and customer trust demand that this data be protected. The typical approach -- encrypting data at rest via database-level transparent data encryption (TDE) -- has a fundamental weakness: the database itself can still read the data. A SQL injection, a leaked connection string, a compromised database admin, or a cloud provider incident exposes plaintext to the attacker.

Client-side encryption eliminates this attack surface entirely. Data is encrypted in the application before the INSERT and decrypted in the application after the SELECT. The database is a dumb byte store.

### The Search Problem

The naive version of client-side encryption makes data unsearchable. If you encrypt an email address, you can no longer write `WHERE email = 'alice@example.com'` because the database only has random-looking ciphertext. This forces a painful choice: either you give up search (and scan/decrypt the entire table in the application) or you give up encryption.

encryptedcol solves this with **blind indexing**. Alongside each encrypted value, the library stores a keyed HMAC hash (the "blind index"). The database can use a standard B-tree index on this hash for efficient exact-match lookups -- without ever learning the plaintext. The application computes the same HMAC for the search term and hands it to the database: `WHERE email_idx = <hash>`. The database finds the row, returns the ciphertext, and the application decrypts it.

This is the central value proposition: **encrypted storage with practical searchability**.

### The Operational Problem

Encryption key management is operationally complex. Keys must be rotated periodically (compliance requirements, suspected compromise, employee offboarding). During rotation, the database contains a mix of data encrypted under the old key and data encrypted under the new key. Both must remain readable, and searches must work across both key versions seamlessly.

encryptedcol treats this as a first-class concern with multi-key support, automatic cross-version search, and dedicated rotation utilities.

---

## Who This Product Is For

- **Go application developers** building on PostgreSQL or Supabase who handle sensitive user data.
- **Engineering teams** subject to compliance frameworks (GDPR, HIPAA, PCI-DSS, SOC 2) that require encryption of PII at rest with key rotation capabilities.
- **SaaS platforms** that want to offer their customers a credible data protection story ("we cannot read your data even if our database is breached").
- **Multi-project organizations** that need a reusable, standalone encryption layer across multiple Go services (the library is a standalone Go module with no database driver dependencies).

---

## What the Product Does -- Business Capabilities

### 1. Zero-Knowledge Column Encryption

Any database column can be encrypted client-side. The library converts plaintext to ciphertext on write and reverses it on read. The database stores BYTEA (binary) columns containing opaque ciphertext.

**Business value:** Even a full database dump or a compromised cloud account reveals nothing. This satisfies the strongest interpretation of "encryption at rest" requirements and dramatically reduces breach impact.

**Supported data types:**
- Strings (names, emails, addresses, notes, freeform text)
- Integers (account numbers, monetary amounts, ages)
- JSON/structured data (user profiles, preferences, metadata objects, API payloads)
- Raw binary (any byte payload)
- Nullable fields (NULL in the database maps to nil in Go and passes through unchanged)

### 2. Searchable Encryption via Blind Indexes

For fields that need exact-match search (email lookup at login, phone number lookup for deduplication, username search), the library computes a deterministic HMAC-SHA256 hash alongside the encrypted value. This hash is stored in a separate `_idx` column and indexed with a standard PostgreSQL B-tree index.

**Business value:** Encrypted fields remain queryable for the most common database access pattern -- exact-match lookup. Login flows, deduplication checks, user search, and foreign-key-style lookups all continue to work without application-side full-table scans.

**Important trade-off the product explicitly accepts:** Blind indexes reveal equality. Two rows with the same email will have the same blind index hash. This is appropriate for high-entropy fields (emails, usernames, phone numbers, UUIDs) but inappropriate for low-entropy fields (status enums, boolean flags, country codes) where frequency analysis could reveal patterns. The product documents this trade-off clearly and advises users accordingly.

### 3. Input Normalization for Consistent Search

Users type the same data in different ways. An email might be entered as `Alice@Example.COM`, `alice@example.com`, or ` ALICE@EXAMPLE.COM `. Without normalization, each of these would produce a different blind index hash, and search would fail.

The library provides built-in normalizers that canonicalize input before computing the blind index:

| Normalizer | What It Does | Business Use Case |
|---|---|---|
| NormalizeEmail | lowercase + trim whitespace | Case-insensitive email lookup |
| NormalizeUsername | lowercase + trim whitespace | Case-insensitive username search |
| NormalizePhone | strip all non-digit characters | Phone lookup regardless of formatting (dashes, parens, country prefix) |
| NormalizeTrim | trim whitespace only | Whitespace-insensitive, case-sensitive fields |
| NormalizeLower | lowercase only | General case-insensitive matching |
| NormalizeNone | identity (no change) | Exact binary match (SSN, UUID) |

**Critical design decision:** Normalization is applied only to the blind index. The encrypted value always preserves the original input exactly as entered. When the data is decrypted, the user sees their original casing and formatting. Normalization is invisible to the end user -- it only affects searchability.

### 4. Zero-Downtime Key Rotation

Encryption keys have a finite useful life. Compliance frameworks require periodic rotation. Suspected key compromise demands immediate rotation. encryptedcol supports this with a multi-phase process that requires no downtime:

**Phase 1 -- Add the new key:** Register both old and new keys. Set the new key as the default for new writes. Old data remains readable.

**Phase 2 -- Migrate existing data:** Iterate through rows encrypted with the old key. The library decrypts with the old key and re-encrypts with the new key, recomputing blind indexes in the process. Migration can happen row-by-row or in batches, and the system remains fully operational throughout.

**Phase 3 -- Remove the old key:** Once all rows have been migrated, the old key is deregistered. Only the new key remains.

**Business value:** Key rotation is a compliance requirement that is often deferred because it is operationally painful. encryptedcol makes it a routine, non-disruptive operation.

**Rotation utilities provided:**
- `NeedsRotation()` -- header-only check (no decryption) to identify rows still on old keys
- `ExtractKeyID()` -- inspect which key version a ciphertext uses without decrypting
- `RotateValue()` -- decrypt-then-re-encrypt a single value
- `RotateStringIndexed()` / `RotateStringIndexedNormalized()` -- rotate both ciphertext and blind index in one call

### 5. Automatic Cross-Version Search During Rotation

During the rotation window, the database contains rows encrypted under different key versions. Each key version produces a different blind index hash for the same plaintext. A search query must match against all active key versions.

The library's `SearchCondition` builder automatically generates SQL with OR clauses for each active key version:

```sql
(key_id = 'v1' AND email_idx = <hmac_v1>) OR (key_id = 'v2' AND email_idx = <hmac_v2>)
```

**Business value:** Search continues to work seamlessly during key rotation. There is no "rotation window" where lookups break or return incomplete results.

### 6. External Key Management Integration

For enterprise environments, encryption keys should not be stored in application config files or environment variables. They should live in dedicated secrets managers.

The `KeyProvider` interface allows integration with any external key management system:

- HashiCorp Vault
- AWS KMS
- Google Cloud KMS
- Azure Key Vault
- Any custom secrets manager

The interface requires only three methods: retrieve a key by ID, report the default key ID, and list all active key IDs. A built-in `StaticKeyProvider` is included for simpler deployments and testing.

**Business value:** The library adapts to the organization's existing secrets infrastructure rather than imposing its own key storage model.

### 7. Transparent Compression for Large Payloads

Encrypted data is high-entropy (random-looking bytes). PostgreSQL's internal TOAST compression cannot compress it, even for fields that would normally compress well (large JSON blobs, text content, API payloads). This means encryption can significantly increase storage costs for large fields.

The library applies zstd compression **before** encryption when beneficial. For large JSON or text fields, this typically achieves 60-90% size reduction. The compression is transparent: the ciphertext format includes a flag byte indicating whether compression was applied, and decompression happens automatically on read.

**Business value:** Storage costs for large encrypted fields (notes, JSON payloads, raw API responses) are kept under control. Compression is automatic and requires no application-level awareness.

**Configurable behavior:**
- Default threshold: 1KB (fields smaller than this skip compression)
- Minimum savings requirement: 10% (if compression doesn't save at least 10%, the original data is used)
- Can be disabled entirely for already-compressed content or to eliminate compression oracle risk

### 8. NULL and Empty String Semantics

Database applications distinguish between NULL (value is unknown/not set) and empty string (value is known to be empty). The library preserves this distinction:

- `nil` (NULL) input produces `nil` (NULL) output -- no encryption overhead for absent values
- Empty string is encrypted normally by default
- Optional `WithEmptyStringAsNull()` mode treats empty strings as NULL for storage savings

Pointer-based helpers (`SealStringPtr` / `OpenStringPtr`) map cleanly to nullable database columns.

**Business value:** The encryption layer does not corrupt database semantics. Application code that distinguishes between "user has no phone number" (NULL) and "user explicitly set phone to empty" (empty string) continues to work correctly.

### 9. Tamper Detection

The ciphertext format embeds the key ID in two places: once in the plaintext header (for efficient key lookup without decryption) and once inside the authenticated secretbox payload (cryptographically bound to the ciphertext). On decryption, the library verifies that both key IDs match.

This prevents **key confusion attacks** where an attacker who can modify stored ciphertext swaps the key ID header to cause decryption with the wrong key. The inner key ID, being inside the authenticated encryption envelope, cannot be modified without detection.

**Business value:** Defense in depth against ciphertext tampering. Even if an attacker has write access to the database, they cannot trick the application into misinterpreting data.

### 10. Secure Key Material Lifecycle

The library takes explicit responsibility for key material in memory:

- Master keys are copied on input and zeroed from the config after key derivation
- Derived keys (encryption and HMAC) are cached at initialization and zeroed on `Close()`
- `StaticKeyProvider` deep-copies keys and provides its own `Close()` for zeroing
- If the OS cryptographic random source fails, the library panics immediately rather than producing weak nonces that might be silently accepted

**Business value:** Minimizes the window during which key material exists in application memory, reducing exposure in memory-dump attacks or core-dump scenarios.

---

## How It Fits Into an Application Architecture

The library is designed to live in the **repository/data access layer** of a Go application. Domain models remain clean plain structs with no encryption awareness. The repository layer handles encryption on write, decryption on read, and blind index computation on search.

```
[Domain Model]  <-->  [Repository Layer + encryptedcol]  <-->  [PostgreSQL/Supabase]
   (plaintext)         (encrypt/decrypt/index)                  (ciphertext + blind indexes)
```

This keeps encryption concerns out of business logic, service layers, and API handlers. The domain model for a User has a plain `Email string` field. Only the repository knows that this maps to `email_encrypted BYTEA`, `email_idx BYTEA`, and `key_id TEXT` in the database.

---

## Database Schema Impact

For each encrypted field, the schema changes are:

- **Non-searchable field:** One BYTEA column (`{field}_encrypted`) replaces the plaintext column
- **Searchable field:** Two BYTEA columns (`{field}_encrypted` + `{field}_idx`) replace the plaintext column, plus a composite index on `(key_id, {field}_idx)`
- **Per-row key tracking:** One `key_id TEXT` column shared across all encrypted fields in the row

The `key_id` column is shared per row (not per field) by design. All encrypted fields in a row use the same key version, which simplifies rotation (rotate the entire row at once) and search (one key_id condition per search clause).

---

## Performance Characteristics

- **Encryption/decryption overhead:** XSalsa20-Poly1305 is fast in software. For typical database fields (bytes to low kilobytes), the per-operation overhead is negligible compared to network round-trip and database query time.
- **Key derivation:** HKDF is performed once at cipher initialization and cached. There is zero per-operation key derivation cost.
- **Blind index computation:** One HMAC-SHA256 per field per write. One HMAC per active key version per search query.
- **Search performance:** Standard PostgreSQL B-tree index lookup on BYTEA columns. During key rotation with N active keys, search performs N index seeks (one per key version OR clause).
- **Compression:** zstd encoder/decoder are initialized once (singleton) and reused. Compression work uses pooled buffers. Decompression is capped at 64MB to prevent zip-bomb attacks.
- **Concurrency:** The `Cipher` instance is safe for concurrent use across goroutines. A single cipher can serve the entire application.

---

## Security Model -- What Is and Is Not Protected

### Protected against:
- Database breach (dump, leak, unauthorized access) -- attacker gets only ciphertext
- Cloud provider access to database storage -- zero-knowledge
- SQL injection that reads data -- returns ciphertext, not plaintext
- Key confusion / ciphertext header tampering -- inner key ID authentication
- Weak nonce generation -- panics on entropy failure rather than degrading silently
- Compression oracle attacks -- compression is optional and can be disabled

### Not protected against:
- Compromise of the application itself (the application holds the keys)
- Frequency analysis on blind-indexed low-entropy fields
- Range queries or partial-match search on encrypted fields (only exact match is supported)
- Traffic analysis (ciphertext length correlates with plaintext length, modulo compression)

---

## Maturity and Status

The library is at version 1.0.3, promoted to stable in February 2026. It has comprehensive unit tests across all modules (cipher, blind indexing, search, compression, format, normalization, key derivation, rotation, helpers, errors), benchmark tests for performance-critical paths, and race-condition testing. The module is published as `github.com/ai8future/encryptedcol` and requires Go 1.24+.

---

## Summary of Business Goals

1. **Eliminate database as an attack surface** for sensitive data by ensuring plaintext never reaches the database.
2. **Maintain practical searchability** on encrypted fields through blind indexing, so encryption does not break core application workflows (login, dedup, lookup).
3. **Enable compliance** with data protection regulations that require encryption at rest and key rotation.
4. **Minimize operational burden** of key rotation with zero-downtime migration tooling and automatic cross-version search.
5. **Integrate with enterprise key management** via a pluggable provider interface.
6. **Be reusable** as a standalone Go module across multiple services and projects, with no database driver coupling.
7. **Preserve application semantics** (NULL handling, original casing, empty string distinction) so that encryption is transparent to business logic.
