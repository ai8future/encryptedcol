Date Created: 2026-01-19_1945

# Codebase Study: encryptedcol

## 1. Overview
`encryptedcol` is a Go library designed for implementing client-side encryption for database columns, specifically targeting PostgreSQL and Supabase environments. Its primary goal is to enable "Zero-Knowledge" storage where the database server holds encrypted data but cannot decrypt it. It solves the common problem of searching encrypted data by implementing **blind indexing** (deterministic encryption) for exact-match queries.

The library emphasizes safety (authenticated encryption, key derivation), usability (seamless key rotation, type-safe helpers), and efficiency (compression, optimized search queries).

## 2. Architecture & Design

### 2.1. Cryptographic Primitives
The library relies on well-established primitives provided by `golang.org/x/crypto`:
*   **Encryption**: XSalsa20-Poly1305 (via `nacl/secretbox`). This provides authenticated encryption with a 24-byte nonce.
*   **Blind Indexing**: HMAC-SHA256. This creates a deterministic hash of the plaintext for searching.
*   **Key Derivation**: HKDF-SHA256. Used to derive separate encryption and blind-indexing sub-keys from a single 32-byte master key.
*   **Randomness**: `crypto/rand` for nonce generation.

**Motivation**: usage of `nacl/secretbox` suggests a preference for high-level, misuse-resistant primitives over raw AES-GCM. HKDF ensures cryptographic separation, preventing potential weaknesses if the same key were used for both encryption and HMAC.

### 2.2. Data Format
The ciphertext format is designed to be self-describing and rotation-friendly:

**Outer Layer**:
```
[flag:1][keyIDLen:1][keyID:n][nonce:24][encrypted_payload]
```
*   **Flag**: Indicates compression status (0x00=None, 0x01=Zstd).
*   **KeyID**: Identifies the key version used for encryption (unauthenticated at this layer, used for lookup).
*   **Nonce**: 24-byte random value.

**Inner Layer (Encrypted Payload)**:
```
[keyIDLen:1][keyID:n][plaintext]
```
*   **KeyID (Inner)**: Repeated inside the authenticated encryption envelope.
*   **Motivation**: This prevents **Key Substitution Attacks**. Without this check, an attacker could potentially trick the system into decrypting a ciphertext with the wrong key (if they could manipulate the outer KeyID), leading to garbage output or potential oracle attacks. The library explicitly checks `innerKeyID == outerKeyID`.

### 2.3. Key Management & Rotation
The library uses a multi-key architecture:
*   **Key ID**: A string identifier (e.g., "v1", "2023-rotation") associated with each master key.
*   **Default Key**: New encryptions use the `defaultKeyID`.
*   **Active Keys**: All registered keys are attempted for decryption (based on the ciphertext's header) and search queries.

**Rotation Mechanism**:
*   **Reads**: Automatic. The ciphertext header tells the library which key to use.
*   **Writes**: Always uses the current default key.
*   **Migration**: `RotateValue` decrypts with the old key and re-encrypts with the new default key.
*   **Search**: The `SearchCondition` generator constructs a query that checks *all* active keys via OR conditions: `(key_id = 'v1' AND idx = hash1) OR (key_id = 'v2' AND idx = hash2)`. This allows seamless searching during a migration window.

### 2.4. Compression
The library includes optional compression using `zstd` (via `github.com/klauspost/compress`).
*   **Threshold**: Only compresses if data > 1KB (configurable).
*   **Heuristic**: Checks if compression saves at least 10%. If not, it stores uncompressed to save CPU.
*   **Format**: The `flag` byte signals if the payload needs decompression.

## 3. Core Functionality

### 3.1. Initialization (`New`)
The entry point `New(opts...)` configures the `Cipher`.
*   It accepts functional options (`WithKey`, `WithDefaultKeyID`, `WithCompression...`).
*   It immediately derives sub-keys (encryption + HMAC) for all provided master keys and caches them in memory.
*   It clears the provided master keys from the config struct to minimize memory exposure.

### 3.2. Encryption (`Seal`) & Decryption (`Open`)
*   **Seal**: Formats inner plaintext -> Compresses (maybe) -> Generates Nonce -> Encrypts -> Formats outer ciphertext.
*   **Open**: Parses outer format -> Finds Key -> Decrypts -> Decompresses -> Verifies inner KeyID -> Returns plaintext.
*   **NULL Handling**: Explicitly preserves `nil` inputs as `nil` outputs, mapping to database NULLs.

### 3.3. Search (`BlindIndex` & `SearchCondition`)
*   **BlindIndex**: Computes HMAC(key_hmac, plaintext).
*   **Normalization**: Users can apply `Normalizer` functions (e.g., `NormalizeEmail`) before indexing. This enables case-insensitive search on encrypted data.
*   **Query Generation**: `SearchCondition` outputs a SQL fragment and arguments. It abstracts away the complexity of checking multiple key versions.

### 3.4. Interfaces
*   **KeyProvider**: An interface for dynamic key retrieval, allowing integration with external KMS (Vault, AWS KMS) instead of hardcoded keys.

## 4. Observations & Interactions

### 4.1. Database Interaction
The library is "database-agnostic" but "schema-aware".
*   It doesn't connect to the DB directly.
*   It assumes a schema with 3 columns for a searchable field:
    1.  `{col}_encrypted`: The actual ciphertext (BYTEA).
    2.  `{col}_idx`: The blind index (BYTEA).
    3.  `key_id`: The version of the key used (TEXT).
*   The `key_id` column is crucial for the compound index `(key_id, {col}_idx)` used by the generated SQL.

### 4.2. Usability
The library provides extensive helpers:
*   `SealString`/`OpenString`: Handles `[]byte` <-> `string` conversion.
*   `SealJSON`/`OpenJSON`: generic wrappers for struct serialization.
*   `SealInt64`: Binary encoding for integers.

### 4.3. Security Notes
*   **Deterministic Encryption**: Blind indexes leak equality. If two users have the same email, their blind indexes are identical. This is a known trade-off for searchability.
*   **Nonce Management**: Uses 24-byte random nonces (XSalsa20), which is safer against collisions than the 12-byte nonces often used with AES-GCM, allowing for safe random generation without counters.
*   **Memory Safety**: The code attempts to zero out master keys after derivation, though Go's garbage collection limits the guarantee of complete memory wiping.

## 5. Conclusion
`encryptedcol` is a well-structured, production-ready library. It addresses the specific complexities of encrypted search and key rotation with a thoughtful API. Its reliance on standard crypto primitives and focus on developer ergonomics (helpers, automatic rotation handling) make it a strong choice for Go applications requiring application-level encryption.
