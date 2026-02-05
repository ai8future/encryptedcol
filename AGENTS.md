# Agent Guidelines

- Whenever making code changes, ALWAYS increment the version and annotate the CHANGELOG. However, wait until the last second to read in the VERSION file in case other agents are working in the folder. This prevents conflicting version increment operations.

- Auto-commit and push code after every code change, but ONLY after you increment VERSION and annotate CHANGELOG. In the notes, mention what coding agent you are and what model you are using. If you are Claude Code, you would say Claude:Opus 4.5 (if you are using the Opus 4.5 model). If you are Codex, you would say: Codex:gpt-5.1-codex-max-high (if high is the reasoning level).

- Stay out of the _studies, _proposals, _rcodegen, _bugs_open, _bugs_fixed directories. Do not go into them or read from them unless specifically told to do so.

- When you fix a bug, write short details on that bug and store it in _bugs_fixed. Depending on the severity or complexity, decide if you think you should be very brief - or less brief. Give your bug file a good name but always prepend the date. For example: 2026-12-31-failed-to-check-values-bug.md is a perfect name. Always lowercase. Always include the date in the filename.

---

## Project Overview

`encryptedcol` is a Go library for client-side encrypted columns in PostgreSQL/Supabase with blind indexing support. Data is encrypted before it leaves the application, ensuring zero-knowledge storage.

## Architecture

### Core Components

- **cipher.go**: Core `Cipher` type with `Seal()`, `Open()`, and `BlindIndex()` methods
- **kdf.go**: HKDF-SHA256 key derivation (master key -> encryption + HMAC keys)
- **format.go**: Ciphertext format encoding/decoding (flag, key_id, nonce, data)
- **compress.go**: Zstd compression for large payloads
- **blindindex.go**: HMAC-SHA256 blind indexing for searchable encryption
- **normalize.go**: Input normalizers (email, username, phone)
- **search.go**: SQL search condition builder for multi-key queries
- **helpers.go**: Type-safe wrappers (SealString, OpenJSON, etc.)
- **options.go**: Configuration via functional options pattern
- **provider.go**: KeyProvider interface for external key management
- **rotate.go**: Key rotation helpers

### Key Design Decisions

1. **XSalsa20-Poly1305** (NaCl secretbox) - 24-byte nonces, simpler than AES-GCM
2. **Single master key per key_id** - HKDF derives encryption and HMAC keys internally
3. **Key ID authenticated** - embedded in both header AND payload (prevents key confusion)
4. **Compression before encryption** - flag byte indicates algorithm (0x00=none, 0x01=zstd)
5. **Normalizers for blind index** - NOT for encrypted value (preserve original)
6. **NULL vs empty string** - preserved by default, opt-in `WithEmptyStringAsNull()`

### Ciphertext Format

```
[flag:1][keyIDLen:1][keyID:n][nonce:24][secretbox(innerKeyID + plaintext)]
```

The inner key_id provides cryptographic binding (authenticated by secretbox).

## Coding Conventions

- Use `github.com/stretchr/testify/require` for test assertions
- Table-driven tests with `t.Run()` for all test cases
- Benchmark performance-critical paths with `testing.B`
- Error variables are package-level `var Err* = errors.New(...)`
- Buffer pooling via `sync.Pool` for compression work buffers
- Cache derived keys at initialization (never derive on each operation)

## Testing

```bash
go test -v ./...           # Run all tests
go test -race ./...        # Race detection
go test -cover ./...       # Coverage report
go test -bench=. ./...     # Benchmarks
```

## Dependencies

- `golang.org/x/crypto/nacl/secretbox` - XSalsa20-Poly1305 encryption
- `golang.org/x/crypto/hkdf` - Key derivation
- `github.com/klauspost/compress/zstd` - Compression
- `github.com/stretchr/testify` - Testing assertions

---

## ANTI-PATTERNS: DO NOT "FIX" THESE

The following patterns are **intentional design decisions**. Do not change them without explicit user approval.

### 1. Static HMAC Keys for Blind Indexes

**What it looks like:**
```go
// Current design - INTENTIONAL
blindIndex := HMAC(derivedKey, "alice@example.com")
```

**Why you might think it's a bug:**
An auditor might flag that static HMAC keys are vulnerable to rainbow table attacks on low-entropy fields. If you encrypt "Status" values like "Active", "Pending", "Disabled", an attacker with database access can see which rows share the same status without knowing the key.

**Why it's intentional:**
This enables **global search** - the ability to search for a value across ALL rows in the database with a single query. This is a critical feature for many use cases:
- "Find all orders with email alice@example.com"
- "Find user by username across the entire system"
- Multi-tenant systems that need cross-tenant search

**The alternative (context-aware blinding) breaks this:**
```go
// Context-aware - DO NOT implement without user approval
blindIndex := HMAC(key, tenantID + "alice@example.com")
```
This would require knowing the tenant_id BEFORE searching, making global lookups impossible.

**What users SHOULD do instead:**
1. Use blind indexes only for **high-entropy** fields (email, username, UUID)
2. Never use blind indexes for low-entropy fields (status, boolean flags, enums)
3. Document this limitation clearly in their application

**When to consider context-aware blinding:**
Only if the user explicitly requests it AND confirms they don't need global search. This would be a new feature, not a fix.

### 2. Panic on crypto/rand Failure

**What it looks like:**
```go
if _, err := rand.Read(nonce[:]); err != nil {
    panic("crypto/rand failed: " + err.Error())
}
```

**Why it's intentional:**
If the OS entropy source fails, the system is in an unrecoverable cryptographic state. Returning an error that might be ignored is MORE dangerous than panicking. This follows Go crypto library conventions.

**DO NOT change this to return an error.**

### 3. Key ID in Both Header AND Payload

**What it looks like:**
```
[outer: keyIDLen][outer: keyID]...[secretbox([inner: keyIDLen][inner: keyID][plaintext])]
```

**Why you might think it's redundant:**
The key ID appears twice - once in the plaintext header and once inside the encrypted payload.

**Why it's intentional:**
This prevents **key confusion attacks**. An attacker who can modify ciphertext headers could swap key IDs to cause decryption with the wrong key. The inner key ID (authenticated by secretbox) catches this tampering.

**DO NOT remove the inner key ID "for efficiency".**

- Stay out of the _studies, _proposals, _rcodegen, _bugs_open, _bugs_fixed directories. Do not go into them or read from them unless specifically told to do so.

- When you fix a bug, write short details on that bug and store it in _bugs_fixed. Depending on the severity or complexity, decide if you think you should be very brief - or less brief. Give your bug file a good name but always prepend the date. For example: 2026-12-31-failed-to-check-values-bug.md is a perfect name. Always lowercase. Always include the date in the filename.
