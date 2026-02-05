package encryptedcol

import (
	"encoding/binary"
	"encoding/json"
)

// SealedValue holds encrypted data with its blind index for searchable fields.
type SealedValue struct {
	Ciphertext []byte // Encrypted data
	BlindIndex []byte // HMAC for searchable encryption
	KeyID      string // Key version used
}

// nullSealedValue returns a SealedValue representing NULL.
func (c *Cipher) nullSealedValue() *SealedValue {
	return &SealedValue{KeyID: c.defaultID}
}

// SealString encrypts a string value.
// Empty string is encrypted (not treated as NULL) by default.
// Returns nil only if configured with WithEmptyStringAsNull and s is "".
func (c *Cipher) SealString(s string) []byte {
	if c.config.emptyStringAsNull && s == "" {
		return nil
	}
	return c.Seal([]byte(s))
}

// OpenString decrypts to a string value.
// Returns empty string and ErrWasNull if ciphertext is nil.
func (c *Cipher) OpenString(ciphertext []byte) (string, error) {
	if ciphertext == nil {
		return "", ErrWasNull
	}
	plaintext, err := c.Open(ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// SealStringPtr encrypts a string pointer.
// Returns nil if s is nil (NULL preservation).
func (c *Cipher) SealStringPtr(s *string) []byte {
	if s == nil {
		return nil
	}
	return c.SealString(*s)
}

// OpenStringPtr decrypts to a string pointer.
// Returns nil if ciphertext is nil (NULL preservation).
func (c *Cipher) OpenStringPtr(ciphertext []byte) (*string, error) {
	if ciphertext == nil {
		return nil, nil
	}
	s, err := c.OpenString(ciphertext)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// SealStringIndexed encrypts a string and computes its blind index.
// Use for searchable encrypted fields.
func (c *Cipher) SealStringIndexed(s string) *SealedValue {
	if c.config.emptyStringAsNull && s == "" {
		return c.nullSealedValue()
	}
	return &SealedValue{
		Ciphertext: c.Seal([]byte(s)),
		BlindIndex: c.BlindIndex([]byte(s)),
		KeyID:      c.defaultID,
	}
}

// SealStringIndexedNormalized encrypts a string and computes a normalized blind index.
// The original string is preserved in the ciphertext; only the blind index is normalized.
//
// Example:
//
//	sealed := cipher.SealStringIndexedNormalized("Alice@Example.COM", NormalizeEmail)
//	// sealed.Ciphertext contains "Alice@Example.COM" (original)
//	// sealed.BlindIndex = HMAC("alice@example.com") (normalized)
func (c *Cipher) SealStringIndexedNormalized(s string, norm Normalizer) *SealedValue {
	if c.config.emptyStringAsNull && s == "" {
		return c.nullSealedValue()
	}
	normalized := norm(s)
	return &SealedValue{
		Ciphertext: c.Seal([]byte(s)),                // Original preserved
		BlindIndex: c.BlindIndex([]byte(normalized)), // Normalized for search
		KeyID:      c.defaultID,
	}
}

// SealIndexed encrypts bytes and computes blind index.
func (c *Cipher) SealIndexed(plaintext []byte) *SealedValue {
	if plaintext == nil {
		return c.nullSealedValue()
	}
	return &SealedValue{
		Ciphertext: c.Seal(plaintext),
		BlindIndex: c.BlindIndex(plaintext),
		KeyID:      c.defaultID,
	}
}

// SealJSON encrypts a JSON-serializable value.
func SealJSON[T any](c *Cipher, data T) ([]byte, error) {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return c.Seal(jsonBytes), nil
}

// OpenJSON decrypts and unmarshals JSON data.
func OpenJSON[T any](c *Cipher, ciphertext []byte) (T, error) {
	var zero T
	if ciphertext == nil {
		return zero, ErrWasNull
	}

	plaintext, err := c.Open(ciphertext)
	if err != nil {
		return zero, err
	}

	var result T
	if err := json.Unmarshal(plaintext, &result); err != nil {
		return zero, err
	}
	return result, nil
}

// SealJSONIndexed encrypts JSON data and computes its blind index.
// The blind index is computed on the JSON serialization.
func SealJSONIndexed[T any](c *Cipher, data T) (*SealedValue, error) {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return &SealedValue{
		Ciphertext: c.Seal(jsonBytes),
		BlindIndex: c.BlindIndex(jsonBytes),
		KeyID:      c.defaultID,
	}, nil
}

// SealInt64 encrypts an int64 value.
func (c *Cipher) SealInt64(n int64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(n))
	return c.Seal(buf)
}

// OpenInt64 decrypts to an int64 value.
func (c *Cipher) OpenInt64(ciphertext []byte) (int64, error) {
	if ciphertext == nil {
		return 0, ErrWasNull
	}

	plaintext, err := c.Open(ciphertext)
	if err != nil {
		return 0, err
	}

	if len(plaintext) != 8 {
		return 0, ErrInvalidFormat
	}

	return int64(binary.BigEndian.Uint64(plaintext)), nil
}

// WasNull returns true if the ciphertext represents a NULL value.
func (c *Cipher) WasNull(ciphertext []byte) bool {
	return ciphertext == nil
}
