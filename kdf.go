package encryptedcol

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Info strings for HKDF derivation - distinct strings ensure separate keys
const (
	infoEncryption = "encryptedcol-encryption"
	infoBlindIndex = "encryptedcol-blind-index"
)

// derivedKeys holds the encryption and HMAC keys derived from a master key.
// These are cached at initialization to avoid repeated HKDF derivation.
type derivedKeys struct {
	encryption [32]byte // XSalsa20-Poly1305 key
	hmac       [32]byte // HMAC-SHA256 key for blind indexes
}

// deriveKeys derives encryption and HMAC keys from a master key using HKDF-SHA256.
// The master key must be exactly 32 bytes.
//
// The derivation uses distinct info strings to ensure cryptographic separation:
//   - Encryption key: HKDF(masterKey, info="encryptedcol-encryption")
//   - HMAC key: HKDF(masterKey, info="encryptedcol-blind-index")
func deriveKeys(masterKey []byte) (*derivedKeys, error) {
	if len(masterKey) != 32 {
		return nil, ErrInvalidKeySize
	}

	keys := &derivedKeys{}

	// Derive encryption key
	if err := hkdfDerive(masterKey, infoEncryption, keys.encryption[:]); err != nil {
		return nil, err
	}

	// Derive HMAC key for blind indexes
	if err := hkdfDerive(masterKey, infoBlindIndex, keys.hmac[:]); err != nil {
		return nil, err
	}

	return keys, nil
}

// hkdfDerive performs HKDF-SHA256 key derivation with the given info string.
// No salt is used (nil salt means HKDF uses a zero-filled salt of HashLen bytes).
func hkdfDerive(masterKey []byte, info string, out []byte) error {
	reader := hkdf.New(sha256.New, masterKey, nil, []byte(info))
	_, err := io.ReadFull(reader, out)
	return err
}
