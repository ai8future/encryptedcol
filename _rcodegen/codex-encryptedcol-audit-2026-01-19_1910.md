Date Created: 2026-01-19 19:10:54 +0100
Date Updated: 2026-01-19
TOTAL_SCORE: 87/100

# encryptedcol Audit Report

## Scope & Method
- Static review of core library sources and tests; no runtime or fuzz testing performed.
- Files reviewed include `cipher.go`, `format.go`, `compress.go`, `blindindex.go`, `normalize.go`, `search.go`, `helpers.go`, `kdf.go`, `provider.go`, `rotate.go`, and tests.

## Executive Summary
The library follows solid cryptographic design choices (XSalsa20-Poly1305, HKDF-derived keys, authenticated inner key ID) and has good test coverage for core paths. The primary risks are around configuration footguns and stability (silent unsupported compression selection, nondeterministic key ordering in generated SQL, and a panic-based API surface). Security posture is strong overall, with one integrity-related metadata concern (compression flag is unauthenticated) that is low risk but worth tracking for a future format version.

## Findings (ordered by severity)

### Medium
1) Panic-based API can be used for denial-of-service if inputs are not fully trusted. (NOT FIXING)
- **Decision:** Per CLAUDE.md anti-patterns, panic is correct for programmer error. Column names are compile-time constants, not user input. Consistent with Go patterns (e.g., `regexp.MustCompile`).
- **Note:** paramOffset validation has been added (see Low #3).

### Low
~~2) Compression algorithm configuration is inconsistent with implementation.~~ (FIXED: 2026-01-19)
- **Status:** Now validates compression algorithm in `New()` and returns `ErrUnsupportedCompression` for unsupported values.

~~3) Search condition SQL/args ordering is nondeterministic.~~ (FIXED: 2026-01-19)
- **Status:** `ActiveKeyIDs()` now returns sorted key IDs. Also added `paramOffset < 1` validation.

4) Compression flag is not authenticated. (NOT FIXING - Future Version)
- The compression flag lives in the unauthenticated header. This is a format change that requires careful versioning for backward compatibility. Tracked for future format version.

## Security Notes (non-findings)
- Inner key ID authentication prevents key confusion attacks and is correctly enforced (`cipher.go`, `format.go`).
- HMAC-based blind indexes are deterministic by design; equality leakage is expected and documented. Use only with high-entropy fields.
- Random nonces are used; panic on `crypto/rand` failure follows Go crypto conventions.

## Test Gaps / Suggestions
- ~~Add a test for invalid `paramOffset`~~ (paramOffset validation added)
- Consider a fuzz test for `parseFormat`/`parseInnerPlaintext` to harden format parsing against malformed inputs.

## Patch-ready diffs

*All diffs in this report have been applied.*

