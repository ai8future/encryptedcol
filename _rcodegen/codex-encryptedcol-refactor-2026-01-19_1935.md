Date Created: 2026-01-19 19:35:38 +0100
Date Updated: 2026-01-19
TOTAL_SCORE: 88/100

# Encryptedcol Refactor Review

## Findings (ordered by severity)

~~1) Medium - Compression algorithm contract mismatch and silent fallback~~ (FIXED: 2026-01-19)
- Evidence: `compress.go:16-105`, `format.go:6-19`, `options.go:42-47`.
- **Status:** Now validates compression algorithm in `New()` and returns `ErrUnsupportedCompression` for unsupported values like "snappy".

~~2) Medium - Non-deterministic key ordering affects query shape~~ (FIXED: 2026-01-19)
- Evidence: `cipher.go:250-256`, `search.go:57-68`.
- **Status:** `ActiveKeyIDs()` now returns sorted key IDs in both `Cipher` and `StaticKeyProvider`.

3) Medium - `SearchCondition` panics on invalid column names (NOT FIXING)
- Evidence: `search.go:45-48`.
- **Decision:** Panic is correct for programmer error. Column names are compile-time constants, not user input. Consistent with Go standard library patterns (e.g., `regexp.MustCompile`).

~~4) Low - Duplicate decryption pipeline logic~~ (FIXED: 2026-01-19)
- Evidence: `cipher.go:152-243`.
- **Status:** Implemented `decryptAndVerify` helper that consolidates shared decryption, decompression, and key ID verification logic.

5) Low - Repeated `SealedValue` construction and NULL handling (NOT FIXING)
- Evidence: `helpers.go:60-115`, `rotate.go:36-83`.
- **Decision:** Adds indirection without meaningful benefit. Current pattern is clear and explicit.

6) Low - Duplicate normalizer implementations (NOT FIXING)
- Evidence: `normalize.go:12-26`.
- **Decision:** Separate functions are intentional for semantic clarity. Users import by name based on domain (email vs username). Future normalization rules may diverge.

~~7) Low - Ignored error in blind index computation~~ (FIXED: 2026-01-19)
- Evidence: `search.go:61-63`.
- **Status:** Now panics with context if `BlindIndexWithKey` returns an error (should never happen since key comes from `ActiveKeyIDs()`).

## Open Questions / Assumptions
- Should `SearchCondition` be safe for arbitrary input or is it intended as a "must" API that can panic on programmer errors?
- Is snappy intended to be supported soon, or should it be documented as "reserved" only?
- Do you want deterministic SQL generation for search conditions (stable key ordering), or is non-determinism acceptable for your use cases?

## Score Rationale
- Strengths: Clear API surface, strong inline documentation, conservative crypto choices, consistent NULL-handling semantics, and tests for major flows.
- Deductions: Configuration contract mismatch (compression), duplicated logic in key paths, and non-deterministic ordering in search SQL generation.

## Change Summary (no code changes made)
- This report is advisory only; no edits or patches were applied.
