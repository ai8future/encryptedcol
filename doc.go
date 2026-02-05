// Package encryptedcol provides client-side encrypted columns for PostgreSQL/Supabase
// with blind indexing support for searchable encryption.
//
// Data is encrypted before it leaves the application, ensuring zero-knowledge storage
// where the database cannot read the plaintext. Blind indexes enable exact-match
// queries on encrypted fields without revealing the plaintext to the database.
//
// # Encryption
//
// The package uses XSalsa20-Poly1305 (NaCl secretbox) for authenticated encryption
// with 24-byte random nonces. Keys are derived from a 32-byte master key using
// HKDF-SHA256, providing cryptographic separation between encryption and HMAC keys.
//
// # Basic Usage
//
//	cipher, err := encryptedcol.New(
//	    encryptedcol.WithKey("v1", masterKey), // 32-byte key
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Encrypt
//	ciphertext := cipher.SealString("sensitive data")
//
//	// Decrypt
//	plaintext, err := cipher.OpenString(ciphertext)
//
// # Searchable Encryption
//
// For fields that require exact-match search, use blind indexes:
//
//	// Encrypt with blind index (for INSERT)
//	sealed := cipher.SealStringIndexedNormalized("alice@example.com", encryptedcol.NormalizeEmail)
//	// Use sealed.Ciphertext for the encrypted column
//	// Use sealed.BlindIndex for the _idx column
//	// Use sealed.KeyID for the key_id column
//
//	// Search (for SELECT)
//	cond := cipher.SearchConditionStringNormalized("email", "alice@example.com", 1, encryptedcol.NormalizeEmail)
//	query := fmt.Sprintf("SELECT * FROM users WHERE %s", cond.SQL)
//	rows, _ := db.Query(query, cond.Args...)
//
// # Normalization
//
// Normalizers transform input before computing blind indexes, enabling
// case-insensitive or format-agnostic searches:
//
//   - NormalizeEmail: lowercase + trim (for email addresses)
//   - NormalizeUsername: lowercase + trim (for usernames)
//   - NormalizePhone: digits only (for phone numbers)
//   - NormalizeNone: identity (for exact match)
//
// IMPORTANT: Use the same normalizer on both write and search.
//
// # Key Rotation
//
// Multiple key versions are supported for seamless key rotation:
//
//	cipher, _ := encryptedcol.New(
//	    encryptedcol.WithKey("v1", oldKey),
//	    encryptedcol.WithKey("v2", newKey),
//	    encryptedcol.WithDefaultKeyID("v2"), // New encryptions use v2
//	)
//
//	// Rotate existing data
//	newCiphertext, _ := cipher.RotateValue(oldCiphertext)
//
// # NULL Handling
//
// NULL values are preserved:
//   - cipher.Seal(nil) returns nil
//   - cipher.Open(nil) returns nil, nil
//
// Empty strings are encrypted by default. Use WithEmptyStringAsNull() to treat
// empty strings as NULL.
//
// # Database Schema
//
// Recommended column structure for encrypted fields:
//
//	-- Non-searchable encrypted field
//	notes_encrypted BYTEA
//
//	-- Searchable encrypted field
//	email_encrypted BYTEA
//	email_idx BYTEA
//	CREATE INDEX idx_users_email ON users (key_id, email_idx);
//
//	-- Key version tracking
//	key_id TEXT NOT NULL
package encryptedcol
