package encryptedcol

// RotateValue re-encrypts a ciphertext with the current default key.
// Use this during key rotation to migrate existing encrypted data.
//
// Returns nil if oldCiphertext is nil (NULL stays NULL).
// Returns error if decryption fails.
func (c *Cipher) RotateValue(oldCiphertext []byte) ([]byte, error) {
	if oldCiphertext == nil {
		return nil, nil
	}

	plaintext, err := c.Open(oldCiphertext)
	if err != nil {
		return nil, err
	}

	return c.Seal(plaintext), nil
}

// RotateBlindIndex recomputes a blind index with the current default key.
// Use this during key rotation when you have access to the plaintext.
//
// Returns nil if plaintext is nil (NULL stays NULL).
func (c *Cipher) RotateBlindIndex(plaintext []byte) []byte {
	if plaintext == nil {
		return nil
	}
	return c.BlindIndex(plaintext)
}

// RotateStringIndexed re-encrypts a string and recomputes its blind index.
// Useful for rotating searchable encrypted fields.
//
// Returns nil values if ciphertext is nil (NULL stays NULL).
func (c *Cipher) RotateStringIndexed(oldCiphertext []byte) (*SealedValue, error) {
	if oldCiphertext == nil {
		return c.nullSealedValue(), nil
	}

	plaintext, err := c.Open(oldCiphertext)
	if err != nil {
		return nil, err
	}

	return &SealedValue{
		Ciphertext: c.Seal(plaintext),
		BlindIndex: c.BlindIndex(plaintext),
		KeyID:      c.defaultID,
	}, nil
}

// RotateStringIndexedNormalized re-encrypts and recomputes normalized blind index.
// The ciphertext is re-encrypted as-is; the blind index uses the normalizer.
//
// IMPORTANT: Use the same normalizer that was used originally.
func (c *Cipher) RotateStringIndexedNormalized(oldCiphertext []byte, norm Normalizer) (*SealedValue, error) {
	if oldCiphertext == nil {
		return c.nullSealedValue(), nil
	}

	plaintext, err := c.Open(oldCiphertext)
	if err != nil {
		return nil, err
	}

	// Normalize for blind index
	normalized := norm(string(plaintext))

	return &SealedValue{
		Ciphertext: c.Seal(plaintext),
		BlindIndex: c.BlindIndex([]byte(normalized)),
		KeyID:      c.defaultID,
	}, nil
}

// NeedsRotation checks if a ciphertext was encrypted with an old key.
// Returns true if the key_id in the ciphertext differs from the default key.
// Returns false for nil ciphertext (NULL values don't need rotation).
//
// Note: Returns false if the ciphertext format is invalid. Use ExtractKeyID
// if you need to detect malformed ciphertext.
func (c *Cipher) NeedsRotation(ciphertext []byte) bool {
	if ciphertext == nil {
		return false
	}

	_, keyID, _, _, err := parseFormat(ciphertext)
	if err != nil {
		return false // Can't determine, assume doesn't need rotation
	}

	return keyID != c.defaultID
}

// ExtractKeyID extracts the key_id from a ciphertext without decrypting.
// Returns empty string and nil error for nil ciphertext.
func (c *Cipher) ExtractKeyID(ciphertext []byte) (string, error) {
	if ciphertext == nil {
		return "", nil
	}

	_, keyID, _, _, err := parseFormat(ciphertext)
	if err != nil {
		return "", err
	}

	return keyID, nil
}
