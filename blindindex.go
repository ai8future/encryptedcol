package encryptedcol

import (
	"crypto/hmac"
	"crypto/sha256"
)

// BlindIndex computes an HMAC-SHA256 blind index using the default key.
// This enables searchable encryption via exact-match queries.
// Returns nil if plaintext is nil (NULL preservation).
//
// The blind index is deterministic: same plaintext + same key = same index.
// This allows database lookups without exposing the plaintext.
func (c *Cipher) BlindIndex(plaintext []byte) []byte {
	if c.closed.Load() {
		panic("encryptedcol: use of closed Cipher")
	}
	if plaintext == nil {
		return nil
	}
	return c.computeHMAC(c.defaultID, plaintext)
}

// BlindIndexWithKey computes an HMAC-SHA256 blind index using a specific key.
// Returns nil if plaintext is nil (NULL preservation).
func (c *Cipher) BlindIndexWithKey(keyID string, plaintext []byte) ([]byte, error) {
	if c.closed.Load() {
		return nil, ErrCipherClosed
	}
	if plaintext == nil {
		return nil, nil
	}
	keys, ok := c.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return computeHMACWithKey(&keys.hmac, plaintext), nil
}

// BlindIndexes computes HMAC blind indexes for all active key versions.
// This is useful for search queries that need to match across key rotations.
// Returns a map of keyID -> blind index.
// Returns nil if plaintext is nil (NULL preservation).
func (c *Cipher) BlindIndexes(plaintext []byte) map[string][]byte {
	if c.closed.Load() {
		panic("encryptedcol: use of closed Cipher")
	}
	if plaintext == nil {
		return nil
	}

	indexes := make(map[string][]byte, len(c.keys))
	for keyID := range c.keys {
		indexes[keyID] = c.computeHMAC(keyID, plaintext)
	}
	return indexes
}

// BlindIndexString computes a blind index for a string value.
// Convenience method that converts string to bytes.
func (c *Cipher) BlindIndexString(s string) []byte {
	return c.BlindIndex([]byte(s))
}

// computeHMAC computes HMAC-SHA256 using the specified key's HMAC key.
func (c *Cipher) computeHMAC(keyID string, data []byte) []byte {
	keys := c.keys[keyID]
	return computeHMACWithKey(&keys.hmac, data)
}

// computeHMACWithKey computes HMAC-SHA256 with the given key.
func computeHMACWithKey(key *[32]byte, data []byte) []byte {
	h := hmac.New(sha256.New, key[:])
	h.Write(data)
	return h.Sum(nil)
}
