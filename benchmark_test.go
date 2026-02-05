package encryptedcol

import (
	"strings"
	"testing"
)

var (
	benchCipher      *Cipher
	benchMultiCipher *Cipher
)

func init() {
	benchCipher, _ = New(WithKey("v1", testKey("v1")))
	benchMultiCipher, _ = New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
		WithKey("v3", testKey("v3")),
	)
}

// Seal benchmarks at various payload sizes

func BenchmarkSeal_100B(b *testing.B) {
	data := []byte(strings.Repeat("x", 100))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchCipher.Seal(data)
	}
}

func BenchmarkSeal_1KB(b *testing.B) {
	data := []byte(strings.Repeat("x", 1024))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchCipher.Seal(data)
	}
}

func BenchmarkSeal_10KB(b *testing.B) {
	data := []byte(strings.Repeat("x", 10*1024))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchCipher.Seal(data)
	}
}

func BenchmarkSeal_100KB(b *testing.B) {
	data := []byte(strings.Repeat("x", 100*1024))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchCipher.Seal(data)
	}
}

func BenchmarkSeal_1MB(b *testing.B) {
	data := []byte(strings.Repeat("x", 1024*1024))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchCipher.Seal(data)
	}
}

// Open benchmarks at various payload sizes

func BenchmarkOpen_100B(b *testing.B) {
	data := []byte(strings.Repeat("x", 100))
	ciphertext := benchCipher.Seal(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchCipher.Open(ciphertext)
	}
}

func BenchmarkOpen_1KB(b *testing.B) {
	data := []byte(strings.Repeat("x", 1024))
	ciphertext := benchCipher.Seal(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchCipher.Open(ciphertext)
	}
}

func BenchmarkOpen_10KB(b *testing.B) {
	data := []byte(strings.Repeat("x", 10*1024))
	ciphertext := benchCipher.Seal(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchCipher.Open(ciphertext)
	}
}

func BenchmarkOpen_100KB(b *testing.B) {
	data := []byte(strings.Repeat("x", 100*1024))
	ciphertext := benchCipher.Seal(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchCipher.Open(ciphertext)
	}
}

func BenchmarkOpen_1MB(b *testing.B) {
	data := []byte(strings.Repeat("x", 1024*1024))
	ciphertext := benchCipher.Seal(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchCipher.Open(ciphertext)
	}
}

// BlindIndex benchmarks

func BenchmarkBlindIndex_Short(b *testing.B) {
	data := []byte("alice@example.com")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchCipher.BlindIndex(data)
	}
}

func BenchmarkBlindIndex_Long(b *testing.B) {
	data := []byte(strings.Repeat("x", 10*1024))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchCipher.BlindIndex(data)
	}
}

func BenchmarkBlindIndexes_3Keys(b *testing.B) {
	data := []byte("alice@example.com")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchMultiCipher.BlindIndexes(data)
	}
}

// SearchCondition benchmarks

func BenchmarkSearchCondition_1Key(b *testing.B) {
	data := []byte("alice@example.com")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchCipher.SearchCondition("email", data, 1)
	}
}

func BenchmarkSearchCondition_3Keys(b *testing.B) {
	data := []byte("alice@example.com")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchMultiCipher.SearchCondition("email", data, 1)
	}
}

func BenchmarkSearchConditionNormalized(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchCipher.SearchConditionStringNormalized("email", "Alice@Example.COM", 1, NormalizeEmail)
	}
}

// Helper benchmarks

func BenchmarkSealString(b *testing.B) {
	s := "alice@example.com"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchCipher.SealString(s)
	}
}

func BenchmarkOpenString(b *testing.B) {
	ciphertext := benchCipher.SealString("alice@example.com")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchCipher.OpenString(ciphertext)
	}
}

func BenchmarkSealStringIndexed(b *testing.B) {
	s := "alice@example.com"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchCipher.SealStringIndexed(s)
	}
}

func BenchmarkSealStringIndexedNormalized(b *testing.B) {
	s := "Alice@Example.COM"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchCipher.SealStringIndexedNormalized(s, NormalizeEmail)
	}
}

// Compression benchmarks

func BenchmarkSeal_Compressible_2KB(b *testing.B) {
	// Highly compressible data
	data := []byte(strings.Repeat("hello world ", 200))
	cipher, _ := New(
		WithKey("v1", testKey("v1")),
		WithCompressionThreshold(1024),
	)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.Seal(data)
	}
}

func BenchmarkSeal_NoCompression_2KB(b *testing.B) {
	data := []byte(strings.Repeat("hello world ", 200))
	cipher, _ := New(
		WithKey("v1", testKey("v1")),
		WithCompressionDisabled(),
	)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.Seal(data)
	}
}

// Normalizer benchmarks

func BenchmarkNormalizeEmail(b *testing.B) {
	s := "  Alice@Example.COM  "
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NormalizeEmail(s)
	}
}

func BenchmarkNormalizePhone(b *testing.B) {
	s := "+1 (555) 123-4567"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NormalizePhone(s)
	}
}

// Rotation benchmarks

func BenchmarkRotateValue(b *testing.B) {
	cipher, _ := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
		WithDefaultKeyID("v2"),
	)
	oldCiphertext, _ := cipher.SealWithKey("v1", []byte("secret data"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.RotateValue(oldCiphertext)
	}
}

func BenchmarkNeedsRotation(b *testing.B) {
	cipher, _ := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
		WithDefaultKeyID("v2"),
	)
	oldCiphertext, _ := cipher.SealWithKey("v1", []byte("secret data"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.NeedsRotation(oldCiphertext)
	}
}
