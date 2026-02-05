package encryptedcol

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSealString_OpenString(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	tests := []struct {
		name string
		s    string
	}{
		{"simple", "hello world"},
		{"empty", ""},
		{"unicode", "こんにちは"},
		{"special chars", "!@#$%^&*()"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext := cipher.SealString(tt.s)
			result, err := cipher.OpenString(ciphertext)
			require.NoError(t, err)
			require.Equal(t, tt.s, result)
		})
	}
}

func TestOpenString_Null(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	result, err := cipher.OpenString(nil)
	require.ErrorIs(t, err, ErrWasNull)
	require.Equal(t, "", result)
}

func TestSealStringPtr_OpenStringPtr(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	s := "hello"
	ciphertext := cipher.SealStringPtr(&s)
	result, err := cipher.OpenStringPtr(ciphertext)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, s, *result)
}

func TestSealStringPtr_Null(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	ciphertext := cipher.SealStringPtr(nil)
	require.Nil(t, ciphertext)

	result, err := cipher.OpenStringPtr(nil)
	require.NoError(t, err)
	require.Nil(t, result)
}

func TestSealStringIndexed(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	sealed := cipher.SealStringIndexed("test@example.com")

	require.NotNil(t, sealed.Ciphertext)
	require.NotNil(t, sealed.BlindIndex)
	require.Equal(t, "v1", sealed.KeyID)
	require.Len(t, sealed.BlindIndex, 32)

	// Verify ciphertext decrypts correctly
	result, err := cipher.OpenString(sealed.Ciphertext)
	require.NoError(t, err)
	require.Equal(t, "test@example.com", result)
}

func TestSealStringIndexedNormalized(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	sealed := cipher.SealStringIndexedNormalized("Alice@Example.COM", NormalizeEmail)

	require.NotNil(t, sealed.Ciphertext)
	require.NotNil(t, sealed.BlindIndex)

	// Ciphertext should preserve original
	result, err := cipher.OpenString(sealed.Ciphertext)
	require.NoError(t, err)
	require.Equal(t, "Alice@Example.COM", result)

	// Blind index should be normalized
	expectedIndex := cipher.BlindIndexString("alice@example.com")
	require.True(t, bytes.Equal(sealed.BlindIndex, expectedIndex))
}

func TestSealStringIndexed_EmptyStringAsNull(t *testing.T) {
	cipher, _ := New(
		WithKey("v1", testKey("v1")),
		WithEmptyStringAsNull(),
	)

	sealed := cipher.SealStringIndexed("")

	require.Nil(t, sealed.Ciphertext)
	require.Nil(t, sealed.BlindIndex)
}

func TestSealIndexed(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	data := []byte("test data")
	sealed := cipher.SealIndexed(data)

	require.NotNil(t, sealed.Ciphertext)
	require.NotNil(t, sealed.BlindIndex)

	decrypted, err := cipher.Open(sealed.Ciphertext)
	require.NoError(t, err)
	require.True(t, bytes.Equal(data, decrypted))
}

func TestSealIndexed_Null(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	sealed := cipher.SealIndexed(nil)

	require.Nil(t, sealed.Ciphertext)
	require.Nil(t, sealed.BlindIndex)
}

func TestSealJSON_OpenJSON(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	type TestData struct {
		Name  string   `json:"name"`
		Tags  []string `json:"tags"`
		Count int      `json:"count"`
	}

	original := TestData{
		Name:  "test",
		Tags:  []string{"a", "b", "c"},
		Count: 42,
	}

	ciphertext, err := SealJSON(cipher, original)
	require.NoError(t, err)
	require.NotNil(t, ciphertext)

	result, err := OpenJSON[TestData](cipher, ciphertext)
	require.NoError(t, err)
	require.Equal(t, original, result)
}

func TestSealJSON_Null(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	type TestData struct {
		Name string `json:"name"`
	}

	_, err := OpenJSON[TestData](cipher, nil)
	require.ErrorIs(t, err, ErrWasNull)
}

func TestSealJSONIndexed(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	type TestData struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	data := TestData{ID: "123", Name: "test"}

	sealed, err := SealJSONIndexed(cipher, data)
	require.NoError(t, err)
	require.NotNil(t, sealed.Ciphertext)
	require.NotNil(t, sealed.BlindIndex)
}

func TestSealInt64_OpenInt64(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	tests := []int64{
		0,
		1,
		-1,
		42,
		-42,
		1 << 62,
		-(1 << 62),
		9223372036854775807,  // max int64
		-9223372036854775808, // min int64
	}

	for _, n := range tests {
		ciphertext := cipher.SealInt64(n)
		require.NotNil(t, ciphertext)

		result, err := cipher.OpenInt64(ciphertext)
		require.NoError(t, err)
		require.Equal(t, n, result)
	}
}

func TestOpenInt64_Null(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	result, err := cipher.OpenInt64(nil)
	require.ErrorIs(t, err, ErrWasNull)
	require.Equal(t, int64(0), result)
}

func TestWasNull(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	require.True(t, cipher.WasNull(nil))
	require.False(t, cipher.WasNull([]byte{}))
	require.False(t, cipher.WasNull(cipher.Seal([]byte("test"))))
}

func TestSealString_EmptyStringAsNull(t *testing.T) {
	// Without option
	cipher1, _ := New(WithKey("v1", testKey("v1")))
	ct1 := cipher1.SealString("")
	require.NotNil(t, ct1, "empty string should encrypt by default")

	// With option
	cipher2, _ := New(
		WithKey("v1", testKey("v1")),
		WithEmptyStringAsNull(),
	)
	ct2 := cipher2.SealString("")
	require.Nil(t, ct2, "empty string should be null with option")

	// Non-empty string should still work
	ct3 := cipher2.SealString("hello")
	require.NotNil(t, ct3)
}

func TestSealStringIndexedNormalized_EmptyString(t *testing.T) {
	cipher, _ := New(
		WithKey("v1", testKey("v1")),
		WithEmptyStringAsNull(),
	)

	sealed := cipher.SealStringIndexedNormalized("", NormalizeEmail)

	require.Nil(t, sealed.Ciphertext)
	require.Nil(t, sealed.BlindIndex)
}

func TestSealedValue_KeyIDSet(t *testing.T) {
	cipher, _ := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
		WithDefaultKeyID("v2"),
	)

	sealed := cipher.SealStringIndexed("test")
	require.Equal(t, "v2", sealed.KeyID)
}

func TestSealJSON_MarshalError(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	// Channels cannot be marshaled to JSON
	_, err := SealJSON(cipher, make(chan int))
	require.Error(t, err)
}

func TestOpenJSON_InvalidJSON(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	// Encrypt something that isn't valid JSON for target type
	ciphertext := cipher.Seal([]byte("not valid json"))
	_, err := OpenJSON[map[string]any](cipher, ciphertext)
	require.Error(t, err)
}

func TestOpenJSON_TypeMismatch(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	// Test various type mismatches
	tests := []struct {
		name       string
		encrypted  string
		targetType string
		wantErr    bool
	}{
		{
			name:       "string to int",
			encrypted:  `"hello"`,
			targetType: "int",
			wantErr:    true,
		},
		{
			name:       "number to string slice",
			encrypted:  `123`,
			targetType: "[]string",
			wantErr:    true,
		},
		{
			name:       "object to slice",
			encrypted:  `{"key": "value"}`,
			targetType: "[]int",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext := cipher.Seal([]byte(tt.encrypted))

			switch tt.targetType {
			case "int":
				_, err := OpenJSON[int](cipher, ciphertext)
				if tt.wantErr {
					require.Error(t, err)
				}
			case "[]string":
				_, err := OpenJSON[[]string](cipher, ciphertext)
				if tt.wantErr {
					require.Error(t, err)
				}
			case "[]int":
				_, err := OpenJSON[[]int](cipher, ciphertext)
				if tt.wantErr {
					require.Error(t, err)
				}
			}
		})
	}
}

func TestOpenJSON_StructFieldMismatch(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	type SourceStruct struct {
		Name string `json:"name"`
		Age  string `json:"age"` // string in source
	}

	type TargetStruct struct {
		Name string `json:"name"`
		Age  int    `json:"age"` // int in target
	}

	// Seal a struct where Age is a string
	source := SourceStruct{Name: "test", Age: "not a number"}
	ciphertext, err := SealJSON(cipher, source)
	require.NoError(t, err)

	// Try to decode into struct where Age is int
	_, err = OpenJSON[TargetStruct](cipher, ciphertext)
	require.Error(t, err, "should fail when string cannot be decoded to int")
}

func TestSealJSONIndexed_MarshalError(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	_, err := SealJSONIndexed(cipher, make(chan int))
	require.Error(t, err)
}

func TestOpenInt64_InvalidLength(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	// Encrypt only 4 bytes (int64 needs 8)
	ciphertext := cipher.Seal([]byte{0x01, 0x02, 0x03, 0x04})
	_, err := cipher.OpenInt64(ciphertext)
	require.ErrorIs(t, err, ErrInvalidFormat)
}

func TestOpenString_InvalidCiphertext(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	_, err := cipher.OpenString([]byte{0x00})
	require.ErrorIs(t, err, ErrInvalidFormat)
}

func TestOpenStringPtr_InvalidCiphertext(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	result, err := cipher.OpenStringPtr([]byte{0x00})
	require.ErrorIs(t, err, ErrInvalidFormat)
	require.Nil(t, result)
}
