package encryptedcol

import "strings"

// Normalizer transforms input strings into a canonical form before computing blind indexes.
// This enables case-insensitive or format-agnostic searches.
//
// IMPORTANT: Use the SAME normalizer on both write and search.
// Mixing normalizers breaks lookups.
type Normalizer func(string) string

// NormalizeEmail normalizes email addresses for case-insensitive lookup.
// Applies: lowercase + trim whitespace.
//
// Example: " Alice@Example.COM " -> "alice@example.com"
var NormalizeEmail Normalizer = func(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// NormalizeUsername normalizes usernames for case-insensitive lookup.
// Applies: lowercase + trim whitespace.
//
// Example: " JohnDoe " -> "johndoe"
var NormalizeUsername Normalizer = func(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// NormalizePhone normalizes phone numbers by extracting ASCII digits only.
// Removes all non-digit characters (only keeps 0-9).
//
// Example: "(555) 123-4567" -> "5551234567"
// Example: "+1-555-123-4567" -> "15551234567"
var NormalizePhone Normalizer = func(s string) string {
	var digits strings.Builder
	digits.Grow(len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits.WriteRune(r)
		}
	}
	return digits.String()
}

// NormalizeNone is an identity normalizer that returns the input unchanged.
// Use for exact-match (case-sensitive) searches.
var NormalizeNone Normalizer = func(s string) string {
	return s
}

// NormalizeTrim normalizes by trimming leading and trailing whitespace only.
// Preserves case.
var NormalizeTrim Normalizer = func(s string) string {
	return strings.TrimSpace(s)
}

// NormalizeLower normalizes to lowercase only (no trim).
var NormalizeLower Normalizer = func(s string) string {
	return strings.ToLower(s)
}
