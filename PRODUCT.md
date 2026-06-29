# What Is encryptedcol?

encryptedcol is a **Go library for client-side, column-level encryption** with searchable blind indexing, purpose-built for applications backed by PostgreSQL or Supabase. It encrypts sensitive fields — personally identifiable information (PII), financial data, health records, credentials — **before** they ever reach the database, so the data store holds only opaque ciphertext and opaque HMAC hashes. The result is a **zero-knowledge storage model**: a database dump, a rogue DBA, a leaked connection string, or a cloud-provider incident yields nothing intelligible.

Within **db_sql_suite** (Cliff's database-security and multi-tenant data-management suite), encryptedcol is the **column-confidentiality layer**. Its sibling `tablebox` handles multi-tenant data ingestion and querying; encryptedcol ships as an independent Go module with no database-driver dependency, so any Go service in or outside the suite can adopt it.

---

# Why Does It Exist?

### The Core Problem

Modern applications collect sensitive user data — emails, phone numbers, government IDs, medical records, financial identifiers. Compliance frameworks (General Data Protection Regulation (GDPR), Health Insurance Portability and Accountability Act (HIPAA), Payment Card Industry Data Security Standard (PCI-DSS), System and Organization Controls 2 (SOC 2)) and basic customer trust demand this data be protected at rest. The common approach — database-level Transparent Data Encryption (TDE) — has a fundamental weakness: **the database itself can still read the plaintext.** A SQL injection that reads data, a leaked connection string, a compromised admin, or a cloud incident exposes everything.

Client-side encryption removes that attack surface: data is encrypted in the application before the `INSERT` and decrypted after the `SELECT`. The database becomes a dumb byte store.

The naive version of this, however, makes data **unsearchable** — you cannot write `WHERE email = 'alice@example.com'` against random-looking ciphertext. That forces a painful choice: give up search (and scan/decrypt entire tables in the app) or give up encryption.

### The Business Goal / Business Case

encryptedcol exists to deliver **encrypted storage that stays practically searchable**, plus the operational tooling to run it for real:

1. **Eliminate the database as an attack surface** for sensitive data — plaintext never arrives there.
2. **Preserve core access patterns** (login lookup, deduplication, user search) via blind indexing, so encryption doesn't break workflows.
3. **Enable compliance** with regulations that mandate encryption at rest *and* periodic key rotation.
4. **Minimize the operational burden of key rotation** with zero-downtime migration tooling and automatic cross-version search.
5. **Integrate with enterprise key management** through a pluggable provider interface.
6. **Stay reusable** — a standalone Go module with no driver coupling, usable across many services.
7. **Preserve application semantics** (NULL handling, original casing, empty-string distinction) so encryption is transparent to business logic.

---

# Who Does It Serve?

The direct consumers are **Go services and their repository layers**; the indirect beneficiaries are the teams and platforms that depend on those services keeping data confidential.

- **Go application developers** on PostgreSQL or Supabase who handle sensitive user data.
- **Engineering teams under compliance frameworks** (GDPR, HIPAA, PCI-DSS, SOC 2) that require encryption of PII at rest with key-rotation capability.
- **SaaS platforms** that want a credible "we cannot read your data even if our database is breached" story.
- **Multi-project organizations** needing a single reusable encryption layer across services — the library is a standalone Go module with no database-driver dependency.

---

# Business Capabilities

### 1. Zero-Knowledge Column Encryption
Any column can be encrypted client-side. Plaintext becomes ciphertext on write and is reversed on read; the database stores `BYTEA` columns of opaque bytes. Supported payloads: strings, `int64`, JSON/structured data (via generics), raw binary, and nullable fields (`nil` passes through unchanged). **Business value:** even a full database dump or a compromised cloud account reveals nothing, satisfying the strongest reading of "encryption at rest" and sharply reducing breach impact.

### 2. Searchable Encryption via Blind Indexes
For fields that need exact-match search, the library computes a deterministic HMAC-SHA256 hash (the "blind index") alongside the ciphertext, stored in a separate `_idx` column and indexed with a standard PostgreSQL B-tree. The app computes the same HMAC for the search term: `WHERE email_idx = <hash>`. **Business value:** encrypted fields stay queryable for the most common access pattern (exact-match lookup) — login, deduplication, user search, and foreign-key-style lookups keep working without app-side full-table scans.

### 3. Input Normalization for Consistent Search
The same value gets typed many ways (`Alice@Example.COM`, ` alice@example.com `). Built-in normalizers canonicalize input *before* computing the blind index, so all variants match. **Business value:** search "just works" across natural input variation. **Key design point:** normalization is applied **only** to the blind index — the ciphertext always preserves the original input, so decryption returns the user's exact casing and formatting.

### 4. Zero-Downtime Key Rotation
Keys have a finite useful life (compliance, suspected compromise, offboarding). encryptedcol supports a three-phase, no-downtime rotation: (1) add the new key and make it the default for new writes while old data stays readable; (2) migrate existing rows by decrypting with the old key and re-encrypting with the new one, recomputing blind indexes; (3) deregister the old key once migration is complete. **Business value:** rotation becomes a routine, non-disruptive operation instead of a deferred compliance liability. Utilities: `NeedsRotation()` (header-only, no decryption), `ExtractKeyID()`, `RotateValue()`, `RotateStringIndexed()` / `RotateStringIndexedNormalized()`.

### 5. Automatic Cross-Version Search During Rotation
During the rotation window the table holds rows under multiple key versions, each producing a *different* blind index for the same plaintext. The `SearchCondition` builder automatically emits OR clauses per active key version: `(key_id = $1 AND email_idx = $2) OR (key_id = $3 AND email_idx = $4)`. **Business value:** search stays correct and complete throughout rotation — there is no window where lookups break.

### 6. External Key Management Integration
Keys belong in secrets managers, not config files. The `KeyProvider` interface (three methods: `GetKey`, `DefaultKeyID`, `ActiveKeyIDs`) integrates with HashiCorp Vault, AWS Key Management Service (KMS), Google Cloud KMS, Azure Key Vault, or any custom secrets store. A built-in `StaticKeyProvider` covers testing and simple deployments. **Business value:** the library adapts to existing secrets infrastructure rather than imposing its own key-storage model.

### 7. Transparent Compression for Large Payloads
Encrypted bytes are high-entropy and defeat PostgreSQL's internal TOAST compression — even for fields that would normally compress well (large JSON, text). encryptedcol applies zstd compression **before** encryption when it helps, recording the outcome in a flag byte and decompressing automatically on read. **Business value:** storage costs for large encrypted fields stay under control, with no application-level awareness required. Configurable: 1 KB default threshold, 10% minimum-savings requirement, or fully disabled.

### 8. NULL and Empty-String Semantics
The library preserves the database distinction between NULL (unknown/not set) and empty string (known-empty): `nil` in → `nil` out (no encryption overhead for absent values); empty strings are encrypted normally by default; optional `WithEmptyStringAsNull()` treats `""` as NULL. Pointer helpers (`SealStringPtr` / `OpenStringPtr`) map cleanly to nullable columns. **Business value:** the encryption layer does not corrupt database semantics — "no phone number" (NULL) stays distinct from "explicitly empty."

### 9. Tamper Detection
The ciphertext embeds the key ID twice: in the plaintext header (for key lookup without decryption) and inside the authenticated secretbox payload (cryptographically bound). On decrypt, both must match (verified in constant time). **Business value:** defense in depth against **key-confusion attacks** — an attacker with database write access cannot swap the header key ID to force decryption under the wrong key.

### 10. Secure Key-Material Lifecycle
Master keys are copied on input and zeroed from config after key derivation; derived encryption/HMAC keys are cached at init and zeroed on `Close()`; `StaticKeyProvider` deep-copies keys and offers its own `Close()`; and if the OS random source fails, the library **panics** rather than emit weak nonces. **Business value:** minimizes the window during which key material lives in memory, reducing exposure to memory-dump and core-dump scenarios.

---

# Business Logic and Rules / Key Design Decisions

| Decision | Rule | Why This Matters |
|---|---|---|
| **Cipher** | XSalsa20-Poly1305 (NaCl secretbox), 24-byte random nonces | Authenticated encryption with large random nonces; simpler and harder to misuse than AES-GCM (no nonce-reuse footgun at this size). |
| **Key derivation** | One 32-byte master key per `key_id`; HKDF-SHA256 derives separate encryption and HMAC keys, cached at init | A single managed secret per version; derived keys never recomputed per operation (zero per-op key-derivation cost). |
| **Key ID in header AND payload** | Inner key ID authenticated by secretbox; verified against outer header on decrypt | Prevents key-confusion attacks. **Do not remove the inner key ID "for efficiency."** |
| **Static HMAC blind index** | `HMAC(derivedKey, normalized_value)` — deterministic, no per-row salt | Deliberate, enabling **global search** across all rows with one query (cross-tenant lookups, "find by email anywhere"). The trade-off: blind indexes reveal equality. |
| **Blind-index entropy guidance** | Use blind indexes only on **high-entropy** fields (email, username, phone, UUID); never on low-entropy fields (status, boolean, enum) | Low-entropy indexes leak frequency/equality patterns to anyone with database read access. This is a usage rule the product documents, not a code bug to "fix." |
| **Normalization scope** | Normalizers affect **only** the blind index; ciphertext preserves the original input | Users get case-insensitive/format-agnostic search while seeing their exact original value on read. Same normalizer must be used on write and search. |
| **Compression** | Skip if disabled or `< threshold` (default 1 KB); only use result if it saves `≥ 10%`; `0x00`=none, `0x01`=zstd, `0x02`=snappy (reserved) | Avoids wasting cycles and avoids enlarging incompressible data; flag byte keeps the format forward-compatible. |
| **Zip-bomb cap** | Decompression rejected above **64 MB** (`ErrDecompressionFailed`) | A small compressed payload can't be used to exhaust memory. |
| **`crypto/rand` failure** | **Panic**, never return an ignorable error | An entropy failure is an unrecoverable cryptographic state; failing loud beats emitting weak nonces. **Do not change to return an error.** |
| **NULL vs empty string** | `nil` preserved both directions; empty string encrypted unless `WithEmptyStringAsNull()` | Encryption must not corrupt database semantics. |
| **`key_id` is per row, not per field** | All encrypted columns in a row share one `key_id TEXT` | Simplifies rotation (rotate the whole row) and search (one `key_id` condition per clause). |
| **Column-name validation** | Column names interpolated into SQL must match `^[A-Za-z_][A-Za-z0-9_]*$`, else **panic** | Blind-index search interpolates the column name; strict validation blocks SQL injection via column names. Values always go through `$N` parameters. |
| **Parameter limit** | Search panics if `paramOffset` is out of `1..65535` or key count would exceed the PostgreSQL parameter ceiling | Surfaces misuse early rather than producing a malformed query at runtime. |
| **Concurrency** | A `Cipher` is safe for concurrent use; one instance can serve the whole app | Construct once, share everywhere; `Close()` makes further use return `ErrCipherClosed` (or panic on `Seal`/`BlindIndex`). |

**Error contract** — all errors carry the `encryptedcol:` prefix and support `errors.Is()`:

| Error | Meaning |
|---|---|
| `ErrDecryptionFailed` | Secretbox authentication failed (wrong key or corrupted data) |
| `ErrKeyIDMismatch` | Inner/outer key ID disagree (tampering detected) |
| `ErrKeyNotFound` | Requested key ID not registered |
| `ErrInvalidKeySize` | Master key not exactly 32 bytes |
| `ErrWasNull` | Ciphertext was nil (database NULL) |
| `ErrDecompressionFailed` | Zstd decompression failed or exceeded the 64 MB cap |
| `ErrInvalidFormat` | Ciphertext byte layout malformed |
| `ErrNoKeys` | No keys provided to the constructor |
| `ErrDefaultKeyNotFound` | Specified default key ID not in the registry |
| `ErrInvalidKeyID` | Key ID empty or longer than 255 bytes |
| `ErrUnsupportedCompression` | Unknown/unsupported compression algorithm |
| `ErrCipherClosed` | Cipher used after `Close()` |

**Ciphertext format:**
```
[flag:1][keyIDLen:1][keyID:n][nonce:24][secretbox(innerKeyID + plaintext)]
```

---

# How to Think About Code Changes

This is a **cryptographic library**; correctness and backward compatibility are non-negotiable. Hard constraints:

- **Never break the ciphertext format.** Existing rows in production databases must keep decrypting. The flag byte and inner-key-ID layout are part of the on-disk contract.
- **Do not "fix" the intentional anti-patterns** documented in `AGENTS.md`: static HMAC blind indexes (they enable global search), the panic on `crypto/rand` failure, and the duplicated inner/outer key ID. Changing any of these requires explicit user approval and is a feature decision, not a bug fix.
- **Keep secrets handled correctly:** copy keys on input, zero them after derivation and on `Close()`, never log key material or plaintext, and use constant-time comparison for authentication checks.
- **No database-driver dependency.** The library deliberately knows nothing about `pgx`, `database/sql`, or any ORM — it returns bytes and SQL fragments. Driver wiring belongs in the consuming service, not here. (Schema and integration *guidance* lives in `README.md` / `INTEGRATION_GUIDE.md`, not in code.)
- **Validate before interpolating into SQL.** Anything placed directly into a query string (column names) must pass `isValidColumnName`; everything else must be a bound parameter.
- **Test like crypto code:** table-driven tests with `testify/require`, race testing, and benchmarks for hot paths. Coverage is high (~97%); new code should preserve that.
- **Versioning / commit discipline** (per `AGENTS.md`): bump `VERSION` and annotate `CHANGELOG.md` for any code change — but read `VERSION` only at the last moment to avoid collisions with parallel agents. (Documentation-only changes such as this file follow the doc-commit convention and do not bump `VERSION`.)

What belongs **here**: encryption/decryption, key derivation, blind indexing, normalization, compression, rotation helpers, the search-condition builder, and the key-provider interface. What belongs **elsewhere** (the consuming service or `tablebox`): database connections, migrations, transaction handling, HTTP/API surfaces, and tenancy/business logic.

---

# Current State / Status

- **Version:** 1.0.3 — stable (promoted to v1.0.0 in February 2026).
- **Module:** `github.com/ai8future/encryptedcol`, requires **Go 1.24+**.
- **Dependencies:** `golang.org/x/crypto` (secretbox + HKDF), `github.com/klauspost/compress` (zstd), `github.com/stretchr/testify` (tests only).
- **Quality:** comprehensive table-driven unit tests across every module (cipher, blind index, search, compression, format, normalization, key derivation, rotation, helpers, errors), benchmarks for hot paths, and race testing; line coverage ~97%.

**Built and working:** XSalsa20-Poly1305 encryption with NULL preservation; HKDF-SHA256 key derivation; HMAC-SHA256 blind indexing with normalizers; type-safe helpers (string, `int64`, JSON generics, pointer variants); multi-key rotation with zero-downtime tooling; cross-version search builder; zstd compression with zip-bomb protection; `KeyProvider` interface plus `StaticKeyProvider`; tamper detection via dual key-ID authentication; secure key-material zeroing.

**Explicitly not provided (by design):** range or partial-match (prefix/substring) search on encrypted fields — only exact match via blind index; protection against compromise of the application itself (it holds the keys); protection against frequency analysis on low-entropy blind-indexed fields; defense against traffic analysis (ciphertext length still correlates with plaintext length, modulo compression). The `snappy` compression flag is reserved in the format but not implemented.
