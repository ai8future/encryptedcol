package encryptedcol

// Ciphertext format:
// [flag:1][keyIDLen:1][keyID:n][nonce:24][secretbox(innerKeyID + plaintext)]
//
// Flag byte values:
//   0x00 = no compression
//   0x01 = zstd compressed
//   0x02 = snappy compressed
//
// Inner plaintext format (before encryption):
// [keyIDLen:1][keyID:n][actualPlaintext]
//
// The inner key_id provides cryptographic binding (authenticated by secretbox).

const (
	flagNoCompression byte = 0x00
	flagZstd          byte = 0x01
	flagSnappy        byte = 0x02

	nonceSize = 24
)

// formatCiphertext assembles the outer ciphertext format.
// Returns: [flag:1][keyIDLen:1][keyID:n][nonce:24][ciphertext]
func formatCiphertext(flag byte, keyID string, nonce [24]byte, ciphertext []byte) []byte {
	keyIDBytes := []byte(keyID)
	keyIDLen := len(keyIDBytes)

	// Total size: 1 (flag) + 1 (keyIDLen) + len(keyID) + 24 (nonce) + len(ciphertext)
	totalSize := 1 + 1 + keyIDLen + nonceSize + len(ciphertext)
	result := make([]byte, 0, totalSize)

	result = append(result, flag)
	result = append(result, byte(keyIDLen))
	result = append(result, keyIDBytes...)
	result = append(result, nonce[:]...)
	result = append(result, ciphertext...)

	return result
}

// parseFormat parses the outer ciphertext format.
// Returns flag, keyID, nonce, encrypted data (secretbox ciphertext), and error.
func parseFormat(data []byte) (flag byte, keyID string, nonce [24]byte, ciphertext []byte, err error) {
	// Minimum size: flag(1) + keyIDLen(1) + keyID(1 min) + nonce(24) + some ciphertext
	minSize := 1 + 1 + 1 + nonceSize + 1
	if len(data) < minSize {
		err = ErrInvalidFormat
		return
	}

	flag = data[0]
	keyIDLen := int(data[1])

	// Validate keyIDLen
	if keyIDLen == 0 || keyIDLen > 255 {
		err = ErrInvalidFormat
		return
	}

	// Check we have enough data for keyID + nonce + at least 1 byte ciphertext
	headerSize := 1 + 1 + keyIDLen + nonceSize
	if len(data) < headerSize+1 {
		err = ErrInvalidFormat
		return
	}

	keyID = string(data[2 : 2+keyIDLen])
	copy(nonce[:], data[2+keyIDLen:2+keyIDLen+nonceSize])
	ciphertext = data[headerSize:]

	return
}

// formatInnerPlaintext prepends the key_id to the plaintext.
// This inner key_id is authenticated by secretbox encryption.
// Returns: [keyIDLen:1][keyID:n][plaintext]
func formatInnerPlaintext(keyID string, plaintext []byte) []byte {
	keyIDBytes := []byte(keyID)
	keyIDLen := len(keyIDBytes)

	totalSize := 1 + keyIDLen + len(plaintext)
	result := make([]byte, 0, totalSize)

	result = append(result, byte(keyIDLen))
	result = append(result, keyIDBytes...)
	result = append(result, plaintext...)

	return result
}

// parseInnerPlaintext extracts the key_id and actual plaintext from the inner format.
// Returns keyID, plaintext, and error.
func parseInnerPlaintext(data []byte) (keyID string, plaintext []byte, err error) {
	if len(data) < 2 {
		err = ErrInvalidFormat
		return
	}

	keyIDLen := int(data[0])
	if keyIDLen == 0 || keyIDLen > 255 {
		err = ErrInvalidFormat
		return
	}

	if len(data) < 1+keyIDLen {
		err = ErrInvalidFormat
		return
	}

	keyID = string(data[1 : 1+keyIDLen])
	plaintext = data[1+keyIDLen:]

	return
}
