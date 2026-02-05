package encryptedcol

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"alice@example.com", "alice@example.com"},
		{"Alice@Example.COM", "alice@example.com"},
		{" alice@example.com ", "alice@example.com"},
		{" ALICE@EXAMPLE.COM ", "alice@example.com"},
		{"", ""},
		{"  ", ""},
		{"MixedCase@Domain.Org", "mixedcase@domain.org"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizeEmail(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeUsername(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"johndoe", "johndoe"},
		{"JohnDoe", "johndoe"},
		{" JohnDoe ", "johndoe"},
		{"", ""},
		{"  ", ""},
		{"ALLCAPS", "allcaps"},
		{"user_name_123", "user_name_123"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizeUsername(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizePhone(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"5551234567", "5551234567"},
		{"555-123-4567", "5551234567"},
		{"(555) 123-4567", "5551234567"},
		{"+1-555-123-4567", "15551234567"},
		{"+1 (555) 123-4567", "15551234567"},
		{"555.123.4567", "5551234567"},
		{"", ""},
		{"abc", ""},
		{"555-abc-1234", "5551234"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizePhone(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeNone(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"alice@example.com", "alice@example.com"},
		{"Alice@Example.COM", "Alice@Example.COM"},
		{" alice@example.com ", " alice@example.com "},
		{"", ""},
		{"  ", "  "},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizeNone(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeTrim(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"alice", "alice"},
		{" alice ", "alice"},
		{"  alice  ", "alice"},
		{"Alice", "Alice"},
		{" Alice ", "Alice"},
		{"", ""},
		{"  ", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizeTrim(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeLower(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"alice", "alice"},
		{"Alice", "alice"},
		{"ALICE", "alice"},
		{" Alice ", " alice "},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizeLower(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizer_WithBlindIndex(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	// Same email, different cases
	email1 := "Alice@Example.COM"
	email2 := "alice@example.com"

	// Without normalization, indexes differ
	idx1 := cipher.BlindIndexString(email1)
	idx2 := cipher.BlindIndexString(email2)
	require.NotEqual(t, idx1, idx2, "without normalization, indexes should differ")

	// With normalization, indexes match
	idx1Normalized := cipher.BlindIndexString(NormalizeEmail(email1))
	idx2Normalized := cipher.BlindIndexString(NormalizeEmail(email2))
	require.Equal(t, idx1Normalized, idx2Normalized, "with normalization, indexes should match")
}

func TestNormalizePhone_Unicode(t *testing.T) {
	// Test with unicode digits (should only extract ASCII digits)
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"arabic digits", "٥٥٥", ""}, // Arabic-Indic digits should not be included as ASCII digits
		{"mixed", "555-١٢٣", "555"},  // Only ASCII digits
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizePhone(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeEmail_Unicode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Ågård@example.com", "ågård@example.com"},
		{"用户@example.com", "用户@example.com"},
		{"MÜNCHEN@EXAMPLE.COM", "münchen@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizeEmail(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}
