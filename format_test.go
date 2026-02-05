package encryptedcol

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFormatCiphertext_RoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		flag       byte
		keyID      string
		nonce      [24]byte
		ciphertext []byte
	}{
		{
			name:       "basic",
			flag:       flagNoCompression,
			keyID:      "v1",
			nonce:      [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24},
			ciphertext: []byte("encrypted data here"),
		},
		{
			name:       "zstd flag",
			flag:       flagZstd,
			keyID:      "key-v2",
			nonce:      [24]byte{},
			ciphertext: []byte{0x01, 0x02, 0x03},
		},
		{
			name:       "snappy flag",
			flag:       flagSnappy,
			keyID:      "k",
			nonce:      [24]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
			ciphertext: []byte("x"),
		},
		{
			name:       "long keyID",
			flag:       flagNoCompression,
			keyID:      "this-is-a-very-long-key-id-for-testing",
			nonce:      [24]byte{},
			ciphertext: []byte("data"),
		},
		{
			name:       "binary ciphertext",
			flag:       flagNoCompression,
			keyID:      "v1",
			nonce:      [24]byte{},
			ciphertext: []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatted := formatCiphertext(tt.flag, tt.keyID, tt.nonce, tt.ciphertext)

			flag, keyID, nonce, ciphertext, err := parseFormat(formatted)
			require.NoError(t, err)
			require.Equal(t, tt.flag, flag)
			require.Equal(t, tt.keyID, keyID)
			require.Equal(t, tt.nonce, nonce)
			require.True(t, bytes.Equal(tt.ciphertext, ciphertext))
		})
	}
}

func TestParseFormat_MalformedInput(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short - 1 byte", []byte{0x00}},
		{"too short - no nonce", []byte{0x00, 0x02, 'v', '1'}},
		{"too short - partial nonce", []byte{0x00, 0x02, 'v', '1', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"keyIDLen 0", append([]byte{0x00, 0x00}, make([]byte, 30)...)},
		{"keyIDLen exceeds data", []byte{0x00, 0x10, 'v', '1', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, _, err := parseFormat(tt.data)
			require.ErrorIs(t, err, ErrInvalidFormat)
		})
	}
}

func TestFormatInnerPlaintext_RoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		keyID     string
		plaintext []byte
	}{
		{
			name:      "basic",
			keyID:     "v1",
			plaintext: []byte("hello world"),
		},
		{
			name:      "empty plaintext",
			keyID:     "v1",
			plaintext: []byte{},
		},
		{
			name:      "single char keyID",
			keyID:     "k",
			plaintext: []byte("data"),
		},
		{
			name:      "binary plaintext",
			keyID:     "v2",
			plaintext: []byte{0x00, 0x01, 0x02, 0xff},
		},
		{
			name:      "long keyID",
			keyID:     "this-is-a-long-key-identifier",
			plaintext: []byte("test"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatted := formatInnerPlaintext(tt.keyID, tt.plaintext)

			keyID, plaintext, err := parseInnerPlaintext(formatted)
			require.NoError(t, err)
			require.Equal(t, tt.keyID, keyID)
			require.True(t, bytes.Equal(tt.plaintext, plaintext))
		})
	}
}

func TestParseInnerPlaintext_MalformedInput(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short - 1 byte", []byte{0x02}},
		{"keyIDLen 0", []byte{0x00, 'x'}},
		{"keyIDLen exceeds data", []byte{0x10, 'v', '1'}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseInnerPlaintext(tt.data)
			require.ErrorIs(t, err, ErrInvalidFormat)
		})
	}
}

func TestFormatCiphertext_Structure(t *testing.T) {
	// Verify the exact byte layout
	flag := byte(0x01)
	keyID := "v1"
	nonce := [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
	ciphertext := []byte("ct")

	result := formatCiphertext(flag, keyID, nonce, ciphertext)

	// Expected: [0x01][0x02]['v']['1'][nonce:24]['c']['t']
	require.Equal(t, byte(0x01), result[0], "flag byte")
	require.Equal(t, byte(0x02), result[1], "keyIDLen byte")
	require.Equal(t, []byte("v1"), result[2:4], "keyID bytes")
	require.Equal(t, nonce[:], result[4:28], "nonce bytes")
	require.Equal(t, []byte("ct"), result[28:], "ciphertext bytes")
}

func TestFormatInnerPlaintext_Structure(t *testing.T) {
	// Verify the exact byte layout
	keyID := "v1"
	plaintext := []byte("hello")

	result := formatInnerPlaintext(keyID, plaintext)

	// Expected: [0x02]['v']['1']['h']['e']['l']['l']['o']
	require.Equal(t, byte(0x02), result[0], "keyIDLen byte")
	require.Equal(t, []byte("v1"), result[1:3], "keyID bytes")
	require.Equal(t, []byte("hello"), result[3:], "plaintext bytes")
}

func TestFlagConstants(t *testing.T) {
	// Verify flag constants are distinct and expected values
	require.Equal(t, flagNoCompression, byte(0x00))
	require.Equal(t, flagZstd, byte(0x01))
	require.Equal(t, flagSnappy, byte(0x02))

	// All flags should be distinct
	flags := []byte{flagNoCompression, flagZstd, flagSnappy}
	seen := make(map[byte]bool)
	for _, f := range flags {
		require.False(t, seen[f], "duplicate flag value: %d", f)
		seen[f] = true
	}
}
