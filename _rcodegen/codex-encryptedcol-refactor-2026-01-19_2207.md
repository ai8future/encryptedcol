Date Created: 2026-01-19 22:07:06 +0100
Date Updated: 2026-01-26 (Review complete: all items implemented or declined)
TOTAL_SCORE: 88/100

# encryptedcol Refactor Review (Quick Pass)

## Scope
- Fast pass focused on maintainability, duplication, and clarity in core library files and tests.
- No code changes proposed here; this is a refactor opportunity report only.

## Score Rationale (88/100)
- Strong structure and clear separation of concerns across cipher, format, compression, helpers, and rotation.
- Tests are extensive and table-driven; public API is coherent.
- Deductions mainly for small duplication pockets, a few ambiguous/unused config paths, and minor API/comment mismatches that could confuse future maintainers.

## Opportunities (Ordered by Impact)

### ~~1) Clarify or reconcile "snappy" support~~ ✅ CLARIFIED 2026-01-22
Added clarifying comment in compress.go explaining Snappy is reserved for future implementation to maintain forward compatibility in the ciphertext format.

### ~~2) Centralize `SealedValue` construction and NULL semantics~~ ✅ IMPLEMENTED 2026-01-22
Extracted `nullSealedValue()` helper method. Updated 5 call sites in helpers.go and rotate.go.

### ~~3) Consolidate search condition helpers~~ ❌ DECLINED 2026-01-26
**Reason:** The 4 SearchCondition methods are small (3-8 lines each), clear, and serve distinct purposes. Slight duplication aids readability over an abstracted internal method.

### ~~4) Trim config to runtime-only fields~~ ✅ NOT NEEDED 2026-01-26
**Reason:** After review, `cfg.keys` is already set to `nil` at cipher.go:100. The `defaultKeyID` field becomes an empty string after zeroing. No memory or confusion issue exists.

### ~~5) Reduce duplicate header parsing~~ ❌ DECLINED 2026-01-26
**Reason:** Only 2-3 call sites use `parseFormat()`. A typed header struct adds abstraction without benefit.

### ~~6) Unify default-key selection semantics~~ ✅ ALREADY FIXED 2026-01-26
**Reason:** Per git log "remove dead default key selection code" - the sorted fallback was removed. `defaultKeyID` is always set by first `WithKey()` call.

### ~~7) Normalize common normalizers~~ ❌ DECLINED 2026-01-26
**Reason:** They're identical by design but semantically distinct. Email normalization may need to diverge (e.g., handle `+` aliases). Aliasing creates coupling.

### ~~8) Optional: avoid panic in SearchCondition~~ ❌ DECLINED 2026-01-26
**Reason:** The panic is for programmer errors (invalid column names), not runtime errors. This is idiomatic Go and SQL injection prevention trumps caller convenience.

## ~~Small Test Maintainability Note~~ ❌ DECLINED 2026-01-26
**Reason:** Test boilerplate is acceptable and tests are readable. Adding helpers doesn't improve test clarity.

## Closing Thoughts
- The library is well-structured and already maintainable. The biggest quality gains come from consolidating small repeated patterns and clarifying the compression capabilities.
- The refactors above are small and low-risk, but they reduce cognitive load and make future extensions (e.g., additional compression or normalizers) more predictable.
