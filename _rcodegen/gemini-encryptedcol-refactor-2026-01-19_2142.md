Date Created: Monday, January 19, 2026 at 9:42 PM
Date Updated: 2026-01-22 (Related implementations: nullSealedValue helper, sortedMapKeys utility)
TOTAL_SCORE: 93/100

# Codebase Refactoring Report: encryptedcol

## Executive Summary

The `encryptedcol` library demonstrates a high standard of software engineering. The codebase is clean, idiomatic, and adheres to cryptographic best practices. It successfully balances ease of use with security, providing a robust solution for client-side encrypted columns.

The architecture cleanly separates concerns between the main cipher logic, key derivation, serialization, and compression. Documentation is comprehensive, and the API is intuitive. The identified areas for improvement are minor and primarily focus on future-proofing for flexibility (e.g., database agnosticism) and memory optimization.

## Detailed Grading (93/100)

*   **Code Quality & Readability (29/30):** Variable naming is clear, functions are focused, and logic is easy to follow. Error handling is explicit and consistent.
*   **Architecture & Design (27/30):** Good separation of concerns. The use of functional options for configuration is excellent. The `KeyProvider` interface is a strong addition for integration.
*   **Security & Reliability (19/20):** Strong cryptographic choices (NaCl, HKDF, random nonces). Memory hygiene (zeroing keys) is attempted, though multiple copies exist briefly.
*   **Maintainability (18/20):** The codebase is small and well-organized. Adding new features (like new compression algos) would be straightforward.

## Key Findings & Recommendations

### 1. Hardcoded SQL Dialect in Search (Minor)
**Observation:** `search.go` generates SQL fragments using PostgreSQL-style parameter placeholders (`$1`, `$2`).
**Implication:** This tightly couples the library to PostgreSQL-compatible databases (like Supabase), limiting its use with MySQL (`?`) or SQL Server (`@p1`).
**Recommendation:** If broader database support is a goal, abstract the parameter placeholder generation into a `SQLDialect` interface or configuration option.

### 2. Global Compression State (Code Quality)
**Observation:** `compress.go` uses a global singleton (`zstdOnce`, `zstdEncoder`) for the zstd compressor.
**Implication:** While currently thread-safe, this prevents different `Cipher` instances from having different compression settings (e.g., one maximizing speed, another maximizing compression ratio).
**Recommendation:** Consider moving the compressor instance into the `Cipher` or `config` struct rather than relying on package-level globals.

### 3. Memory Hygiene & Key Copies (Security)
**Observation:** Keys are copied multiple times during initialization: from `KeyProvider` -> `WithKey` closure -> `config` struct -> `Cipher` struct.
**Implication:** While the `Close()` method correctly zeros out the final derived keys, the intermediate copies (especially in `config`) are garbage collected but not explicitly wiped immediately after use (though `New` does attempt to zero `cfg.keys`, the closures in `WithKey` might hold references).
**Recommendation:** This is a standard Go challenge. The current approach is "good enough" for most threat models, but minimizing copies where possible (e.g., passing `config` directly or using a builder that consumes keys) could strictly improve memory hygiene.

### 4. SearchCondition Panic (Robustness)
**Observation:** `SearchCondition` panics if the column name is invalid or `paramOffset` is < 1.
**Implication:** While these are likely programmer errors, libraries should generally avoid panicking unless the state is unrecoverable.
**Recommendation:** Change `SearchCondition` to return `(*SearchCondition, error)` to allow the caller to handle invalid inputs gracefully.

### 5. "God Struct" Tendency (Architecture)
**Observation:** The `Cipher` struct is becoming a central point for all functionality: encryption, decryption, key rotation, blind indexing, and SQL generation.
**Implication:** As features grow, `Cipher` could become bloated.
**Recommendation:** Consider splitting the SQL generation logic into a separate `QueryBuilder` or `Searcher` struct that wraps the `Cipher` (or just the necessary blind index logic), keeping the core `Cipher` focused purely on data transformation.

## Conclusion

The codebase is in excellent shape. The suggested refactorings are optimizations rather than critical fixes. The primary recommendation is to maintain the current high standards while considering the SQL abstraction if the library's scope expands.
