package encryptedcol

import (
	"crypto/rand"
	"crypto/subtle"
	"sort"
	"sync/atomic"

	"golang.org/x/crypto/nacl/secretbox"
)

// Cipher provides encryption, decryption, and blind indexing for database columns.
// It is safe for concurrent use.
type Cipher struct {
	keys      map[string]*derivedKeys // keyID -> derived keys (cached)
	defaultID string                  // default key ID for new encryptions
	config    *config                 // configuration options
	closed    atomic.Bool             // true after Close() called
}

// config holds cipher configuration options.
type config struct {
	keys                 map[string][]byte // keyID -> master key (32 bytes)
	defaultKeyID         string
	compressionThreshold int
	compressionAlgorithm string
	compressionDisabled  bool
	emptyStringAsNull    bool
}

// defaultConfig returns the default configuration.
func defaultConfig() *config {
	return &config{
		keys:                 make(map[string][]byte),
		compressionThreshold: defaultCompressionThreshold,
		compressionAlgorithm: compressionAlgorithmZstd,
	}
}

// sortedMapKeys returns map keys sorted alphabetically.
func sortedMapKeys[V any](m map[string]V) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// New creates a new Cipher with the given options.
// At least one key must be provided via WithKey option.
//
// Example:
//
//	cipher, err := encryptedcol.New(
//	    encryptedcol.WithKey("v1", masterKey1),
//	    encryptedcol.WithKey("v2", masterKey2),
//	    encryptedcol.WithDefaultKeyID("v2"),
//	)
func New(opts ...Option) (*Cipher, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	if len(cfg.keys) == 0 {
		return nil, ErrNoKeys
	}

	// Note: defaultKeyID is always set by the first WithKey() call.
	// If using NewWithProvider(), it's set explicitly via WithDefaultKeyID().

	// Verify default key exists
	if _, ok := cfg.keys[cfg.defaultKeyID]; !ok {
		return nil, ErrDefaultKeyNotFound
	}

	// Validate key IDs (must fit in single byte length field)
	for keyID := range cfg.keys {
		if len(keyID) == 0 || len(keyID) > 255 {
			return nil, ErrInvalidKeyID
		}
	}

	// Validate compression algorithm
	if cfg.compressionAlgorithm != "" &&
		cfg.compressionAlgorithm != compressionAlgorithmZstd {
		return nil, ErrUnsupportedCompression
	}

	// Zero out master keys from config (they're no longer needed)
	// Defer ensures this happens even if key derivation fails
	defer func() {
		for keyID := range cfg.keys {
			key := cfg.keys[keyID]
			for i := range key {
				key[i] = 0
			}
		}
		cfg.keys = nil // Clear reference to prevent accidental access
	}()

	// Derive keys for each master key (cache at initialization)
	derivedKeysMap := make(map[string]*derivedKeys)
	for keyID, masterKey := range cfg.keys {
		dk, err := deriveKeys(masterKey)
		if err != nil {
			return nil, err
		}
		derivedKeysMap[keyID] = dk
	}

	c := &Cipher{
		keys:      derivedKeysMap,
		defaultID: cfg.defaultKeyID,
		config:    cfg,
	}

	return c, nil
}

// Seal encrypts plaintext using the default key.
// Returns ciphertext with embedded key_id, or nil if plaintext is nil (NULL preservation).
//
// The ciphertext format is:
// [flag:1][keyIDLen:1][keyID:n][nonce:24][secretbox(innerKeyID + plaintext)]
func (c *Cipher) Seal(plaintext []byte) []byte {
	if c.closed.Load() {
		panic("encryptedcol: use of closed Cipher")
	}
	if plaintext == nil {
		return nil // NULL preservation
	}
	return c.sealWithKeyID(c.defaultID, plaintext)
}

// SealWithKey encrypts plaintext using a specific key version.
func (c *Cipher) SealWithKey(keyID string, plaintext []byte) ([]byte, error) {
	if c.closed.Load() {
		return nil, ErrCipherClosed
	}
	if _, ok := c.keys[keyID]; !ok {
		return nil, ErrKeyNotFound
	}
	if plaintext == nil {
		return nil, nil // NULL preservation
	}
	return c.sealWithKeyID(keyID, plaintext), nil
}

// sealWithKeyID performs the actual encryption.
func (c *Cipher) sealWithKeyID(keyID string, plaintext []byte) []byte {
	keys := c.keys[keyID]

	// Format inner plaintext with key_id for authentication
	innerPlaintext := formatInnerPlaintext(keyID, plaintext)

	// Maybe compress
	toEncrypt, flag := maybeCompress(
		innerPlaintext,
		c.config.compressionThreshold,
		c.config.compressionAlgorithm,
		c.config.compressionDisabled,
	)

	// Generate nonce
	nonce := generateNonce()

	// Encrypt with secretbox
	encrypted := secretbox.Seal(nil, toEncrypt, &nonce, &keys.encryption)

	// Format outer ciphertext
	return formatCiphertext(flag, keyID, nonce, encrypted)
}

// decryptAndVerify decrypts ciphertext with the given key and verifies the inner key ID.
// This is the shared decryption logic used by Open() and OpenWithKey().
func (c *Cipher) decryptAndVerify(keys *derivedKeys, encrypted []byte, nonce *[24]byte, flag byte, expectedKeyID string) ([]byte, error) {
	// Decrypt
	decrypted, ok := secretbox.Open(nil, encrypted, nonce, &keys.encryption)
	if !ok {
		return nil, ErrDecryptionFailed
	}

	// Decompress if needed
	decompressed, err := decompress(decrypted, flag)
	if err != nil {
		return nil, err
	}

	// Parse inner plaintext and verify key_id
	innerKeyID, actualPlaintext, err := parseInnerPlaintext(decompressed)
	if err != nil {
		return nil, err
	}

	// Verify inner key_id matches expected (constant-time for defense-in-depth)
	if subtle.ConstantTimeCompare([]byte(innerKeyID), []byte(expectedKeyID)) != 1 {
		return nil, ErrKeyIDMismatch
	}

	return actualPlaintext, nil
}

// Open decrypts ciphertext, auto-detecting the key from embedded key_id.
// Returns nil, nil if ciphertext is nil (NULL preservation).
func (c *Cipher) Open(ciphertext []byte) ([]byte, error) {
	if c.closed.Load() {
		return nil, ErrCipherClosed
	}
	if ciphertext == nil {
		return nil, nil // NULL preservation
	}

	// Parse outer format
	flag, outerKeyID, nonce, encrypted, err := parseFormat(ciphertext)
	if err != nil {
		return nil, err
	}

	// Get the encryption key
	keys, ok := c.keys[outerKeyID]
	if !ok {
		return nil, ErrKeyNotFound
	}

	return c.decryptAndVerify(keys, encrypted, &nonce, flag, outerKeyID)
}

// OpenWithKey decrypts ciphertext using a specific key.
// This can be used when the key_id is stored separately.
func (c *Cipher) OpenWithKey(keyID string, ciphertext []byte) ([]byte, error) {
	if c.closed.Load() {
		return nil, ErrCipherClosed
	}
	if ciphertext == nil {
		return nil, nil
	}

	keys, ok := c.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Parse outer format
	flag, outerKeyID, nonce, encrypted, err := parseFormat(ciphertext)
	if err != nil {
		return nil, err
	}

	// Verify outer key_id matches expected key
	if outerKeyID != keyID {
		return nil, ErrKeyIDMismatch
	}

	return c.decryptAndVerify(keys, encrypted, &nonce, flag, keyID)
}

// DefaultKeyID returns the current default key identifier.
func (c *Cipher) DefaultKeyID() string {
	return c.defaultID
}

// ActiveKeyIDs returns all registered key identifiers, sorted alphabetically.
func (c *Cipher) ActiveKeyIDs() []string {
	return sortedMapKeys(c.keys)
}

// Close zeros out all key material from memory.
// Call this when the Cipher is no longer needed to reduce key exposure window.
// After calling Close, the Cipher is no longer usable.
func (c *Cipher) Close() {
	c.closed.Store(true)
	for _, dk := range c.keys {
		for i := range dk.encryption {
			dk.encryption[i] = 0
		}
		for i := range dk.hmac {
			dk.hmac[i] = 0
		}
	}
	c.keys = nil
}

// generateNonce generates a cryptographically secure random 24-byte nonce.
// Panics if the system's random source fails (unrecoverable).
func generateNonce() [24]byte {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return nonce
}
