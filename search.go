package encryptedcol

import (
	"fmt"
	"strings"
)

// maxParamNumber is the PostgreSQL maximum parameter number.
const maxParamNumber = 65535

// isValidColumnName checks if a column name is safe for SQL interpolation.
// Must start with letter or underscore, followed by alphanumeric/underscore.
func isValidColumnName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 {
			// First character: letter or underscore only (PostgreSQL requirement)
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_') {
				return false
			}
		} else {
			// Subsequent characters: alphanumeric or underscore
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '_') {
				return false
			}
		}
	}
	return true
}

// SearchCondition holds a SQL WHERE clause fragment and its arguments
// for blind index searches across multiple key versions.
type SearchCondition struct {
	SQL  string        // SQL fragment like "(key_id = $1 AND email_idx = $2) OR ..."
	Args []interface{} // Interleaved key_ids and blind indexes
}

// SearchCondition generates a SQL WHERE clause for blind index search
// across all active key versions.
//
// The generated SQL uses OR conditions for each key version:
//
//	(key_id = $1 AND {column}_idx = $2) OR (key_id = $3 AND {column}_idx = $4)
//
// paramOffset specifies the starting parameter number ($1, $2, etc.).
// Use this when composing with other WHERE conditions.
//
// Example:
//
//	cond := cipher.SearchCondition("email", []byte("alice@example.com"), 1)
//	query := fmt.Sprintf("SELECT * FROM users WHERE %s", cond.SQL)
//	rows, _ := db.Query(query, cond.Args...)
func (c *Cipher) SearchCondition(column string, plaintext []byte, paramOffset int) *SearchCondition {
	if !isValidColumnName(column) {
		panic("encryptedcol: invalid column name (must start with letter/underscore, contain only alphanumeric/underscore)")
	}

	if paramOffset < 1 || paramOffset > maxParamNumber {
		panic(fmt.Sprintf("encryptedcol: invalid paramOffset (must be 1-%d)", maxParamNumber))
	}

	if plaintext == nil {
		return &SearchCondition{
			SQL:  "FALSE", // NULL values can't match
			Args: nil,
		}
	}

	ids := c.ActiveKeyIDs()

	// Check that parameters won't exceed PostgreSQL limit
	maxParam := paramOffset + (len(ids) * 2) - 1
	if maxParam > maxParamNumber {
		panic(fmt.Sprintf("encryptedcol: too many keys (%d) would exceed PostgreSQL parameter limit", len(ids)))
	}

	parts := make([]string, 0, len(ids))
	args := make([]interface{}, 0, len(ids)*2)

	for _, keyID := range ids {
		idxHash, err := c.BlindIndexWithKey(keyID, plaintext)
		if err != nil {
			// This should never happen since keyID comes from ActiveKeyIDs()
			panic("encryptedcol: internal error: " + err.Error())
		}

		part := fmt.Sprintf("(key_id = $%d AND %s_idx = $%d)", paramOffset, column, paramOffset+1)
		parts = append(parts, part)
		args = append(args, keyID, idxHash)
		paramOffset += 2
	}

	return &SearchCondition{
		SQL:  strings.Join(parts, " OR "),
		Args: args,
	}
}

// SearchConditionString is a convenience method for string values.
func (c *Cipher) SearchConditionString(column string, plaintext string, paramOffset int) *SearchCondition {
	return c.SearchCondition(column, []byte(plaintext), paramOffset)
}

// SearchConditionStringNormalized generates a search condition with normalization.
// The plaintext is normalized before computing blind indexes.
//
// IMPORTANT: Use the SAME normalizer that was used when storing the data.
//
// Example:
//
//	cond := cipher.SearchConditionStringNormalized("email", "ALICE@Example.COM", 1, NormalizeEmail)
//	// Normalizes to "alice@example.com" before computing blind indexes
func (c *Cipher) SearchConditionStringNormalized(column string, plaintext string, paramOffset int, norm Normalizer) *SearchCondition {
	normalized := norm(plaintext)
	return c.SearchCondition(column, []byte(normalized), paramOffset)
}

// SearchConditionNormalized generates a search condition for bytes with a string normalizer.
// Converts bytes to string, normalizes, then computes blind indexes.
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
