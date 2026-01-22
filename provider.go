package encryptedcol

// KeyProvider is an interface for dynamic key retrieval.
// Implement this interface to integrate with external key management systems
// like HashiCorp Vault, AWS KMS, or other secrets managers.
type KeyProvider interface {
	// GetKey retrieves a master key by its ID.
	// Returns the 32-byte master key or an error if not found.
	GetKey(keyID string) ([]byte, error)

	// DefaultKeyID returns the key ID to use for new encryptions.
	DefaultKeyID() string

	// ActiveKeyIDs returns all key IDs that should be considered for
	// blind index search queries. During key rotation, this should
	// include both old and new keys.
	ActiveKeyIDs() []string
}

// NewWithProvider creates a new Cipher using a KeyProvider.
// Keys are fetched from the provider at initialization time and cached.
func NewWithProvider(provider KeyProvider) (*Cipher, error) {
	activeIDs := provider.ActiveKeyIDs()
	if len(activeIDs) == 0 {
		return nil, ErrNoKeys
	}

	// Fetch all active keys from provider
	keys := make(map[string][]byte)
	for _, keyID := range activeIDs {
		key, err := provider.GetKey(keyID)
		if err != nil {
			return nil, err
		}
		keys[keyID] = key
	}

	defaultID := provider.DefaultKeyID()
	if _, ok := keys[defaultID]; !ok {
		return nil, ErrDefaultKeyNotFound
	}

	// Build options from fetched keys
	opts := make([]Option, 0, len(keys)+1)
	for keyID, key := range keys {
		opts = append(opts, WithKey(keyID, key))
	}
	opts = append(opts, WithDefaultKeyID(defaultID))

	return New(opts...)
}

// StaticKeyProvider is a simple in-memory implementation of KeyProvider.
// Useful for testing or simple deployments without external key management.
type StaticKeyProvider struct {
	keys      map[string][]byte
	defaultID string
}

// NewStaticKeyProvider creates a StaticKeyProvider with the given keys.
// Keys are deep-copied to prevent external modification.
func NewStaticKeyProvider(defaultKeyID string, keys map[string][]byte) *StaticKeyProvider {
	// Deep-copy all keys to prevent external modification
	keysCopy := make(map[string][]byte, len(keys))
	for id, key := range keys {
		keyCopy := make([]byte, len(key))
		copy(keyCopy, key)
		keysCopy[id] = keyCopy
	}
	return &StaticKeyProvider{
		keys:      keysCopy,
		defaultID: defaultKeyID,
	}
}

// GetKey implements KeyProvider.
func (p *StaticKeyProvider) GetKey(keyID string) ([]byte, error) {
	key, ok := p.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	// Return a copy to prevent external modification
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return keyCopy, nil
}

// DefaultKeyID implements KeyProvider.
func (p *StaticKeyProvider) DefaultKeyID() string {
	return p.defaultID
}

// ActiveKeyIDs implements KeyProvider.
func (p *StaticKeyProvider) ActiveKeyIDs() []string {
	return sortedMapKeys(p.keys)
}

// Close zeros out all key material from memory.
// After calling Close, the provider should not be used.
func (p *StaticKeyProvider) Close() {
	for _, key := range p.keys {
		for i := range key {
			key[i] = 0
		}
	}
	p.keys = nil
}
