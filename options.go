package encryptedcol

// Option is a functional option for configuring a Cipher.
type Option func(*config)

// WithKey registers a master key with the given key ID.
// The master key must be exactly 32 bytes.
// Multiple keys can be registered for key rotation support.
// The key is copied internally; the caller may zero the original after calling New().
func WithKey(keyID string, masterKey []byte) Option {
	return func(c *config) {
		if c.keys == nil {
			c.keys = make(map[string][]byte)
		}
		// Copy the key so we control its lifecycle
		keyCopy := make([]byte, len(masterKey))
		copy(keyCopy, masterKey)
		c.keys[keyID] = keyCopy
		// Set as default if first key
		if c.defaultKeyID == "" {
			c.defaultKeyID = keyID
		}
	}
}

// WithDefaultKeyID sets the default key ID for new encryptions.
// The key must be registered via WithKey.
func WithDefaultKeyID(keyID string) Option {
	return func(c *config) {
		c.defaultKeyID = keyID
	}
}

// WithCompressionThreshold sets the minimum size in bytes before compression is attempted.
// Default is 1024 (1KB). Data smaller than this will not be compressed.
// Must be > 0; a threshold of 0 could cause issues with empty data.
func WithCompressionThreshold(bytes int) Option {
	return func(c *config) {
		c.compressionThreshold = bytes
	}
}

// WithCompressionAlgorithm sets the compression algorithm to use.
// Currently only "zstd" (default) is supported.
// "snappy" is reserved for future implementation.
func WithCompressionAlgorithm(algo string) Option {
	return func(c *config) {
		c.compressionAlgorithm = algo
	}
}

// WithCompressionDisabled disables compression entirely.
// Use this for data that is already compressed or won't benefit from compression.
func WithCompressionDisabled() Option {
	return func(c *config) {
		c.compressionDisabled = true
	}
}

// WithEmptyStringAsNull configures the cipher to treat empty strings as NULL.
// By default, empty strings are preserved (encrypted to ciphertext).
// With this option, SealString("") returns nil instead of ciphertext.
func WithEmptyStringAsNull() Option {
	return func(c *config) {
		c.emptyStringAsNull = true
	}
}
