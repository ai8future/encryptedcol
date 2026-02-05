Date Created: 2026-01-19 21:35:00
TOTAL_SCORE: 93/100

# EncryptedCol Code Audit Report

## Overview

The `encryptedcol` library provides a robust and secure way to handle encrypted columns with blind indexing in Go. The codebase is well-structured, easy to read, and uses well-regarded cryptographic primitives (NaCl/Secretbox, HKDF, HMAC). The API design is clean and idiomatic.

## Findings

### 1. Incomplete Secret Wiping on Error (Medium Severity)
In `cipher.go`, the `New` function iterates over the provided keys to derive encryption/HMAC keys. If `deriveKeys` fails for any key (e.g., due to an underlying HKDF error, though rare), the function returns immediately. The cleanup loop that zeros out the master keys in `cfg.keys` is located *after* this loop and is skipped on error. This leaves copies of the master keys in memory until garbage collection.

### 2. Non-Deterministic Default Key Selection (Low Severity)
In `cipher.go`, if multiple keys are provided but no default key ID is specified (via `WithDefaultKeyID`), the `New` function selects a default key by iterating over the `cfg.keys` map. Since Go map iteration order is randomized, this results in a non-deterministic default key selection. While `WithKey` attempts to set the default to the first added key, a user could explicitly unset it or rely on the fallback behavior, leading to unpredictability.

### 3. Aggressive Panicking in `SearchCondition` (Low Severity)
The `SearchCondition` function panics if the `column` name contains invalid characters. While this prevents SQL injection, a library usually should return an error for invalid user input rather than panicking, unless it's strictly an internal programming error.

## Fixes

The following patches address the reported issues.

### Fix 1 & 2: Safe Secret Wiping and Deterministic Default Key
This patch modifies `cipher.go` to:
1.  Use `defer` to ensure master keys are zeroed out even if initialization fails.
2.  Sort key IDs before selecting a fallback default key to ensure determinism.

```go
diff --git a/cipher.go b/cipher.go
index 1234567..89abcde 100644
--- a/cipher.go
+++ b/cipher.go
@@ -52,10 +52,14 @@ func New(opts ...Option) (*Cipher, error) {
 
 	// If no default key ID specified, use the first key added
 	if cfg.defaultKeyID == "" {
+		var ids []string
 		for keyID := range cfg.keys {
-			cfg.defaultKeyID = keyID
-			break
+			ids = append(ids, keyID)
 		}
+		sort.Strings(ids)
+		if len(ids) > 0 {
+			cfg.defaultKeyID = ids[0]
+		}
 	}
 
 	// Verify default key exists
@@ -75,6 +79,16 @@ func New(opts ...Option) (*Cipher, error) {
 		return nil, ErrUnsupportedCompression
 	}
 
+	// Zero out master keys from config (they're no longer needed)
+	// Defer ensures this happens even if key derivation fails
+	defer func() {
+		for keyID := range cfg.keys {
+			key := cfg.keys[keyID]
+			for i := range key {
+				key[i] = 0
+			}
+		}
+	}()
+
 	// Derive keys for each master key (cache at initialization)
 	derivedKeysMap := make(map[string]*derivedKeys)
 	for keyID, masterKey := range cfg.keys {
@@ -85,15 +99,6 @@ func New(opts ...Option) (*Cipher, error) {
 		derivedKeysMap[keyID] = dk
 	}
 
-	// Zero out master keys from config (they're no longer needed)
-	for keyID := range cfg.keys {
-		key := cfg.keys[keyID]
-		for i := range key {
-			key[i] = 0
-		}
-	}
-	cfg.keys = nil
-
 	c := &Cipher{
 		keys:      derivedKeysMap,
 		defaultID: cfg.defaultKeyID,
```
