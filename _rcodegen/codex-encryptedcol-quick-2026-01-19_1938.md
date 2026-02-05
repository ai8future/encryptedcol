Date Created: 2026-01-19 19:38:47 +0100
Date Updated: 2026-01-19
TOTAL_SCORE: 92/100

## AUDIT
~~- A1: Active key iteration is non-deterministic~~ (FIXED: 2026-01-19)
  - **Status:** `ActiveKeyIDs()` now returns sorted key IDs.

~~- A2: `SearchCondition` accepts `paramOffset` <= 0~~ (FIXED: 2026-01-19)
  - **Status:** Now panics when `paramOffset < 1`.

## TESTS (Skipped per user request)
- T1: Add NULL-preservation tests for explicit-key APIs (`SealWithKey`, `OpenWithKey`).
- T2: Add deterministic ordering test for `ActiveKeyIDs` (paired with A1).
- T3: Add a panic test for invalid `paramOffset` (paired with A2).

## FIXES
~~- F1: `WithCompressionAlgorithm("snappy")` silently disables compression~~ (FIXED: 2026-01-19)
  - **Status:** Now validates compression algorithm in `New()` and returns `ErrUnsupportedCompression` for unsupported values.

## REFACTOR
- sync.Pool for compression buffers (NOT FIXING - YAGNI, current allocation pattern is fine)
- ~~Factor shared decrypt logic between `Open` and `OpenWithKey`~~ (FIXED: 2026-01-19 - implemented `decryptAndVerify` helper)
- closed flag for post-Close usage (NOT FIXING - YAGNI)
- Key ID validation helper (NOT FIXING - YAGNI)
