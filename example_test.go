package encryptedcol_test

import (
	"fmt"

	"github.com/ai8future/encryptedcol"
)

func Example() {
	// Create a 32-byte master key (in production, load from secure storage)
	masterKey := []byte("01234567890123456789012345678901")

	// Initialize cipher
	cipher, err := encryptedcol.New(
		encryptedcol.WithKey("v1", masterKey),
	)
	if err != nil {
		panic(err)
	}

	// Encrypt a string
	ciphertext := cipher.SealString("Hello, World!")

	// Decrypt
	plaintext, err := cipher.OpenString(ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println(plaintext)
	// Output: Hello, World!
}

func Example_searchableEncryption() {
	masterKey := []byte("01234567890123456789012345678901")

	cipher, _ := encryptedcol.New(
		encryptedcol.WithKey("v1", masterKey),
	)

	// Encrypt with blind index for searchable field
	// Use normalization for case-insensitive email lookup
	sealed := cipher.SealStringIndexedNormalized("Alice@Example.COM", encryptedcol.NormalizeEmail)

	// The ciphertext preserves the original case
	decrypted, _ := cipher.OpenString(sealed.Ciphertext)
	fmt.Println("Decrypted:", decrypted)

	// Generate search condition (normalized, so case-insensitive)
	cond := cipher.SearchConditionStringNormalized("email", "alice@example.com", 1, encryptedcol.NormalizeEmail)
	fmt.Println("SQL:", cond.SQL)

	// Output:
	// Decrypted: Alice@Example.COM
	// SQL: (key_id = $1 AND email_idx = $2)
}

func Example_keyRotation() {
	oldKey := []byte("old-key-must-be-32-bytes-long!!!")
	newKey := []byte("new-key-must-be-32-bytes-long!!!")

	// Phase 1: Encrypt with old key
	cipher1, _ := encryptedcol.New(encryptedcol.WithKey("v1", oldKey))
	oldCiphertext := cipher1.SealString("secret data")

	// Phase 2: Add new key, make it default (both keys available)
	cipher2, _ := encryptedcol.New(
		encryptedcol.WithKey("v1", oldKey),
		encryptedcol.WithKey("v2", newKey),
		encryptedcol.WithDefaultKeyID("v2"),
	)

	// Can still read old data
	data, _ := cipher2.OpenString(oldCiphertext)
	fmt.Println("Old data:", data)

	// Check if rotation needed
	fmt.Println("Needs rotation:", cipher2.NeedsRotation(oldCiphertext))

	// Rotate to new key
	newCiphertext, _ := cipher2.RotateValue(oldCiphertext)

	// Verify new key is used
	keyID, _ := cipher2.ExtractKeyID(newCiphertext)
	fmt.Println("New key ID:", keyID)

	// Output:
	// Old data: secret data
	// Needs rotation: true
	// New key ID: v2
}

func Example_jsonEncryption() {
	masterKey := []byte("01234567890123456789012345678901")
	cipher, _ := encryptedcol.New(encryptedcol.WithKey("v1", masterKey))

	// Encrypt a struct as JSON
	type Metadata struct {
		Tags   []string `json:"tags"`
		Source string   `json:"source"`
	}

	original := Metadata{
		Tags:   []string{"important", "vip"},
		Source: "api",
	}

	ciphertext, _ := encryptedcol.SealJSON(cipher, original)

	// Decrypt back to struct
	decrypted, _ := encryptedcol.OpenJSON[Metadata](cipher, ciphertext)

	fmt.Println("Tags:", decrypted.Tags)
	fmt.Println("Source:", decrypted.Source)

	// Output:
	// Tags: [important vip]
	// Source: api
}

func Example_nullHandling() {
	masterKey := []byte("01234567890123456789012345678901")
	cipher, _ := encryptedcol.New(encryptedcol.WithKey("v1", masterKey))

	// NULL is preserved
	ciphertext := cipher.Seal(nil)
	fmt.Println("Seal(nil):", ciphertext)

	plaintext, err := cipher.Open(nil)
	fmt.Println("Open(nil):", plaintext, err)

	// Empty string is encrypted (not NULL)
	ctEmpty := cipher.SealString("")
	fmt.Println("Empty string encrypted:", ctEmpty != nil)

	// Output:
	// Seal(nil): []
	// Open(nil): [] <nil>
	// Empty string encrypted: true
}
