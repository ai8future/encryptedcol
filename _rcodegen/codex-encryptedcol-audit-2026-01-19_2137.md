Date Created: 2026-01-19 21:38:03 +0100
TOTAL_SCORE: 88/100

Encryptedcol Audit Report

Scope
- Time-boxed review of core crypto/compression, blind index/search helpers, and public documentation.

Score Rationale
- Strong crypto primitives (XSalsa20-Poly1305, HKDF), key confusion mitigation, and solid test coverage.
- Deductions for unbounded decompression risk, panic-based search API, and minor doc/comment mismatches.

Findings (ordered by severity)
1) MEDIUM: Unbounded zstd decompression can lead to memory/CPU DoS
- Evidence: `compress.go:57` uses `DecodeAll` without limits; `cipher.go:175` calls `decompress` on every Open/OpenWithKey.
- Impact: if ciphertext can be supplied by an untrusted source (or corrupted storage), a decompression bomb can exhaust resources.
- Recommendation: add a size limit or explicitly document mitigation (disable compression for untrusted ciphertext).
- Patch: Diff A.

2) MEDIUM: `SearchCondition` panics on invalid input (availability/DoS risk)
- Evidence: `search.go:53` panics on invalid column name; `search.go:58` panics on invalid paramOffset.
- Impact: if column names or offsets are influenced by untrusted input, a panic can crash the process or request handler.
- Recommendation: add safe variants that return errors (keep existing panic behavior for backward compatibility).
- Patch: Diff B.

3) LOW: Compression docs/comments imply snappy support that is not implemented
- Evidence: `options.go:42` says snappy supported; `format.go:6` describes snappy flag; `cipher.go:81` rejects non-zstd.
- Impact: user confusion and misconfiguration.
- Recommendation: clarify docs/comments to mark snappy as reserved/unimplemented.
- Patch: Diff C.

4) LOW: Concurrency note is slightly misleading around Close
- Evidence: `cipher.go:10` claims concurrent safety; `cipher.go:257` zeroes key material and nils map.
- Impact: concurrent Close with other methods can race/panic.
- Recommendation: document that Close must not be called concurrently with other methods.
- Patch: Diff C.

5) INFO: Blind indexes are deterministic; high-entropy guidance should be explicit
- Evidence: README lacks warning on low-entropy fields.
- Impact: users may inadvertently enable frequency analysis on low-entropy values.
- Recommendation: add guidance to docs.
- Patch: Diff A.

Testing
- Not run (audit only).

Patch-Ready Diffs
Diff A: Security guidance (README, doc.go)
```diff
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@
 rows, _ := db.Query(query, cond.Args...)
 ```
+
+Security notes:
+- Blind indexes are deterministic; use them only for high-entropy fields (email, username, UUID).
+- Avoid blind indexes for low-entropy fields (status, booleans, enums).
+- If ciphertext might come from untrusted sources, consider disabling compression via `WithCompressionDisabled` to reduce decompression DoS risk.
 
 ## Normalizers
@@
 ```

diff --git a/doc.go b/doc.go
--- a/doc.go
+++ b/doc.go
@@
 //\tcond := cipher.SearchConditionStringNormalized("email", "alice@example.com", 1, encryptedcol.NormalizeEmail)
 //\tquery := fmt.Sprintf("SELECT * FROM users WHERE %s", cond.SQL)
 //\trows, _ := db.Query(query, cond.Args...)
+//
+// Security notes:
+//   - Blind indexes are deterministic; use them only for high-entropy fields (email, username, UUID).
+//   - Avoid blind indexes for low-entropy fields (status, booleans, enums).
+//   - If ciphertext may come from untrusted sources, consider disabling compression.
 //
 // # Normalization
```

Diff B: Safe search APIs (errors.go, search.go)
```diff
diff --git a/errors.go b/errors.go
--- a/errors.go
+++ b/errors.go
@@
 	// ErrInvalidFormat indicates the ciphertext format is malformed.
 	ErrInvalidFormat = errors.New("encryptedcol: invalid ciphertext format")
+
+	// ErrInvalidColumnName indicates a column name failed validation for SQL interpolation.
+	ErrInvalidColumnName = errors.New("encryptedcol: invalid column name")
+
+	// ErrInvalidParamOffset indicates the parameter offset is less than 1.
+	ErrInvalidParamOffset = errors.New("encryptedcol: invalid param offset")
 
 	// ErrNoKeys indicates no keys were provided to the cipher.
 	ErrNoKeys = errors.New("encryptedcol: no keys provided")
diff --git a/search.go b/search.go
--- a/search.go
+++ b/search.go
@@
-// SearchCondition generates a SQL WHERE clause for blind index search
-// across all active key versions.
+// SearchCondition generates a SQL WHERE clause for blind index search
+// across all active key versions.
+// Panics on invalid column names or parameter offsets; use SearchConditionSafe for errors.
@@
 func (c *Cipher) SearchConditionNormalized(column string, plaintext []byte, paramOffset int, norm Normalizer) *SearchCondition {
 	if plaintext == nil {
 		return &SearchCondition{
 			SQL:  "FALSE",
 			Args: nil,
 		}
 	}
 	normalized := norm(string(plaintext))
 	return c.SearchCondition(column, []byte(normalized), paramOffset)
 }
+
+// SearchConditionSafe generates a SQL WHERE clause for blind index search
+// across all active key versions, returning errors instead of panicking.
+func (c *Cipher) SearchConditionSafe(column string, plaintext []byte, paramOffset int) (*SearchCondition, error) {
+	if !isValidColumnName(column) {
+		return nil, fmt.Errorf("%w: %s", ErrInvalidColumnName, column)
+	}
+
+	if paramOffset < 1 {
+		return nil, fmt.Errorf("%w: %d", ErrInvalidParamOffset, paramOffset)
+	}
+
+	if plaintext == nil {
+		return &SearchCondition{
+			SQL:  "FALSE", // NULL values can't match
+			Args: nil,
+		}, nil
+	}
+
+	ids := c.ActiveKeyIDs()
+	parts := make([]string, 0, len(ids))
+	args := make([]interface{}, 0, len(ids)*2)
+
+	for _, keyID := range ids {
+		idxHash, err := c.BlindIndexWithKey(keyID, plaintext)
+		if err != nil {
+			return nil, err
+		}
+
+		part := fmt.Sprintf("(key_id = $%d AND %s_idx = $%d)", paramOffset, column, paramOffset+1)
+		parts = append(parts, part)
+		args = append(args, keyID, idxHash)
+		paramOffset += 2
+	}
+
+	return &SearchCondition{
+		SQL:  strings.Join(parts, " OR "),
+		Args: args,
+	}, nil
+}
+
+// SearchConditionStringSafe is a convenience method for string values.
+func (c *Cipher) SearchConditionStringSafe(column string, plaintext string, paramOffset int) (*SearchCondition, error) {
+	return c.SearchConditionSafe(column, []byte(plaintext), paramOffset)
+}
+
+// SearchConditionStringNormalizedSafe generates a search condition with normalization.
+// The plaintext is normalized before computing blind indexes.
+func (c *Cipher) SearchConditionStringNormalizedSafe(column string, plaintext string, paramOffset int, norm Normalizer) (*SearchCondition, error) {
+	normalized := norm(plaintext)
+	return c.SearchConditionSafe(column, []byte(normalized), paramOffset)
+}
+
+// SearchConditionNormalizedSafe generates a search condition for bytes with a string normalizer.
+// Converts bytes to string, normalizes, then computes blind indexes.
+func (c *Cipher) SearchConditionNormalizedSafe(column string, plaintext []byte, paramOffset int, norm Normalizer) (*SearchCondition, error) {
+	if plaintext == nil {
+		return &SearchCondition{
+			SQL:  "FALSE",
+			Args: nil,
+		}, nil
+	}
+	normalized := norm(string(plaintext))
+	return c.SearchConditionSafe(column, []byte(normalized), paramOffset)
+}
```

Diff C: Docs/comment clarifications (cipher.go, options.go, format.go)
```diff
diff --git a/cipher.go b/cipher.go
--- a/cipher.go
+++ b/cipher.go
@@
-// Cipher provides encryption, decryption, and blind indexing for database columns.
-// It is safe for concurrent use.
+// Cipher provides encryption, decryption, and blind indexing for database columns.
+// It is safe for concurrent use (do not call Close concurrently with other methods).
@@

diff --git a/options.go b/options.go
--- a/options.go
+++ b/options.go
@@
-// WithCompressionAlgorithm sets the compression algorithm to use.
-// Supported values: "zstd" (default), "snappy".
+// WithCompressionAlgorithm sets the compression algorithm to use.
+// Supported values: "zstd" (default). "snappy" is reserved but not implemented.
 func WithCompressionAlgorithm(algo string) Option {
 	return func(c *config) {
 		c.compressionAlgorithm = algo
 	}
 }

diff --git a/format.go b/format.go
--- a/format.go
+++ b/format.go
@@
 // Flag byte values:
 //   0x00 = no compression
 //   0x01 = zstd compressed
-//   0x02 = snappy compressed
+//   0x02 = reserved (snappy not implemented)
```
