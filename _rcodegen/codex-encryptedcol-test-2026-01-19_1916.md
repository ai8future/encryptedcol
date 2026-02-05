Date Created: 2026-01-19 19:16:53 +0100
Date Updated: 2026-01-19
TOTAL_SCORE: 88/100

## Scope
Quick pass (<10%) using `coverage.out` + targeted file scan to spot unexercised branches. No code changes applied.

## Score Rationale
- Strong baseline tests and ~89.7% statement coverage.
- Several negative-path branches (format tampering, decompress failure, marshal/unmarshal errors, nil handling in specific helpers) are still untested.
- A few branches are only reachable via global manipulation or are effectively untriggerable without adding test hooks.

## Untested Areas Observed

### IMPLEMENTED (2026-01-19):
- ~~`cipher.go`: `SealWithKey` nil path~~ → `TestSealWithKey_NullPreservation`
- ~~`cipher.go`: `OpenWithKey` nil path~~ → `TestOpenWithKey_NullPreservation`
- ~~`cipher.go`: invalid flags~~ → `TestOpen_InvalidFlag`, `TestOpen_SnappyFlagUnsupported`
- ~~`helpers.go`: error propagation in `OpenString`/`OpenStringPtr`~~ → `TestOpenString_InvalidCiphertext`, `TestOpenStringPtr_InvalidCiphertext`
- ~~`helpers.go`: JSON marshal/unmarshal failures~~ → `TestSealJSON_MarshalError`, `TestOpenJSON_InvalidJSON`, `TestSealJSONIndexed_MarshalError`
- ~~`helpers.go`: `OpenInt64` invalid length~~ → `TestOpenInt64_InvalidLength`
- ~~`rotate.go`: `RotateStringIndexed`/`RotateStringIndexedNormalized` decryption failures~~ → `TestRotateStringIndexed_DecryptionError`, `TestRotateStringIndexedNormalized_DecryptionError`
- ~~`rotate.go`: `NeedsRotation` parse failure path~~ → `TestNeedsRotation_InvalidFormat`
- ~~`cipher.go`: `ActiveKeyIDs` deterministic ordering~~ → `TestActiveKeyIDs_Sorted`

### SKIPPED (dead weight - not implementing):
- `cipher.go`: `generateNonce` panic path - Requires mocking crypto/rand global, panic is intentional per CLAUDE.md
- `options.go`: `WithKey` map initialization when config starts nil - Tests unreachable internal code path
- `compress.go`: error handling when `initZstd` returns an error - Requires manipulating sync.Once globals, not triggerable in production
- `kdf.go`: `hkdfDerive` error propagation - Effectively unreachable with current implementation

## Proposed Tests (Summary)
- ~~Add targeted negative-path tests for `Open`/`OpenWithKey` and `SealWithKey` via crafted ciphertexts and flag tampering.~~ (IMPLEMENTED)
- Add panic assertion for `generateNonce` when `crypto/rand` fails (SKIPPED - manipulates globals, panic is intentional)
- ~~Add JSON marshal/unmarshal error tests and invalid length tests for numeric helpers.~~ (IMPLEMENTED)
- Add config option edge-case tests around `WithKey`. (SKIPPED - tests unreachable internal code)
- ~~Add rotation error tests and `NeedsRotation` invalid format case.~~ (IMPLEMENTED)
- Add compression init-error tests by temporarily setting `zstdErr` (SKIPPED - not triggerable in production)

## Patch-Ready Diffs

**Tests have been added directly to existing test files (2026-01-19).**

Coverage improved from 89.7% to 95.1%.

### Implemented Tests:
- `cipher_test.go`: `TestSealWithKey_NullPreservation`, `TestOpenWithKey_NullPreservation`, `TestOpen_InvalidFlag`, `TestOpen_SnappyFlagUnsupported`, `TestActiveKeyIDs_Sorted`
- `helpers_test.go`: `TestSealJSON_MarshalError`, `TestOpenJSON_InvalidJSON`, `TestSealJSONIndexed_MarshalError`, `TestOpenInt64_InvalidLength`, `TestOpenString_InvalidCiphertext`, `TestOpenStringPtr_InvalidCiphertext`
- `rotate_test.go`: `TestRotateStringIndexed_DecryptionError`, `TestRotateStringIndexedNormalized_DecryptionError`, `TestNeedsRotation_InvalidFormat`

### Skipped Tests (low value):
- `TestGenerateNonce_PanicsOnRandFailure` - Manipulates crypto/rand global, panic is intentional
- `TestWithKey_*` config tests - Unreachable internal code paths
- `TestCompress*_InitError` tests - Manipulates sync.Once globals
