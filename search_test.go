package encryptedcol

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSearchCondition_SingleKey(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	cond := cipher.SearchCondition("email", []byte("test@example.com"), 1)

	require.Equal(t, "(key_id = $1 AND email_idx = $2)", cond.SQL)
	require.Len(t, cond.Args, 2)
	require.Equal(t, "v1", cond.Args[0])
	require.Len(t, cond.Args[1].([]byte), 32) // HMAC-SHA256
}

func TestSearchCondition_MultipleKeys(t *testing.T) {
	cipher, _ := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
	)

	cond := cipher.SearchCondition("email", []byte("test@example.com"), 1)

	// Should have OR conditions for both keys
	require.Contains(t, cond.SQL, "OR")
	require.Len(t, cond.Args, 4) // 2 keys * (keyID + index)

	// Verify structure
	parts := strings.Split(cond.SQL, " OR ")
	require.Len(t, parts, 2)
}

func TestSearchCondition_ParamOffset(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	// Start at $3 (e.g., $1 and $2 used by other conditions)
	cond := cipher.SearchCondition("email", []byte("test@example.com"), 3)

	require.Equal(t, "(key_id = $3 AND email_idx = $4)", cond.SQL)
}

func TestSearchCondition_ParamOffset_MultiKey(t *testing.T) {
	cipher, _ := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
	)

	cond := cipher.SearchCondition("email", []byte("test@example.com"), 3)

	// Should use $3, $4, $5, $6
	require.Contains(t, cond.SQL, "$3")
	require.Contains(t, cond.SQL, "$4")
	require.Contains(t, cond.SQL, "$5")
	require.Contains(t, cond.SQL, "$6")
}

func TestSearchCondition_Null(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	cond := cipher.SearchCondition("email", nil, 1)

	require.Equal(t, "FALSE", cond.SQL)
	require.Nil(t, cond.Args)
}

func TestSearchConditionString(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	cond1 := cipher.SearchCondition("email", []byte("test@example.com"), 1)
	cond2 := cipher.SearchConditionString("email", "test@example.com", 1)

	require.Equal(t, cond1.SQL, cond2.SQL)
	require.Equal(t, cond1.Args[0], cond2.Args[0])
	require.True(t, bytes.Equal(cond1.Args[1].([]byte), cond2.Args[1].([]byte)))
}

func TestSearchConditionStringNormalized(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	// Different case emails should produce same search condition when normalized
	cond1 := cipher.SearchConditionStringNormalized("email", "Alice@Example.COM", 1, NormalizeEmail)
	cond2 := cipher.SearchConditionStringNormalized("email", "alice@example.com", 1, NormalizeEmail)

	// SQL structure should be the same
	require.Equal(t, cond1.SQL, cond2.SQL)

	// Blind indexes should match (because both normalized to same value)
	require.True(t, bytes.Equal(cond1.Args[1].([]byte), cond2.Args[1].([]byte)))
}

func TestSearchConditionStringNormalized_DifferentFromNonNormalized(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	condNormalized := cipher.SearchConditionStringNormalized("email", "Alice@Example.COM", 1, NormalizeEmail)
	condNonNormalized := cipher.SearchConditionString("email", "Alice@Example.COM", 1)

	// Blind indexes should differ (one normalized, one not)
	require.False(t, bytes.Equal(condNormalized.Args[1].([]byte), condNonNormalized.Args[1].([]byte)))
}

func TestSearchCondition_CompositionExample(t *testing.T) {
	cipher, _ := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
	)

	// Simulating: SELECT * FROM users WHERE tenant_id = $1 AND status = $2 AND (email search)
	emailCond := cipher.SearchConditionString("email", "alice@example.com", 3)

	fullQuery := "SELECT * FROM users WHERE tenant_id = $1 AND status = $2 AND (" + emailCond.SQL + ")"

	// Should have placeholders for all args
	require.Contains(t, fullQuery, "$1")
	require.Contains(t, fullQuery, "$2")
	require.Contains(t, fullQuery, "$3")
	require.Contains(t, fullQuery, "$4")

	// Args would be: tenantID, status, key_id, index, key_id, index
	allArgs := append([]interface{}{"tenant-123", "active"}, emailCond.Args...)
	require.Len(t, allArgs, 6)
}

func TestSearchConditionNormalized(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	plaintext := []byte("  ALICE@Example.COM  ")
	cond := cipher.SearchConditionNormalized("email", plaintext, 1, NormalizeEmail)

	// Should be normalized (lowercase + trimmed)
	expected := cipher.SearchConditionString("email", "alice@example.com", 1)
	require.True(t, bytes.Equal(cond.Args[1].([]byte), expected.Args[1].([]byte)))
}

func TestSearchConditionNormalized_Null(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	cond := cipher.SearchConditionNormalized("email", nil, 1, NormalizeEmail)

	require.Equal(t, "FALSE", cond.SQL)
	require.Nil(t, cond.Args)
}

func TestSearchCondition_ColumnName(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	tests := []struct {
		column   string
		expected string
	}{
		{"email", "email_idx"},
		{"name", "name_idx"},
		{"phone", "phone_idx"},
	}

	for _, tt := range tests {
		t.Run(tt.column, func(t *testing.T) {
			cond := cipher.SearchCondition(tt.column, []byte("test"), 1)
			require.Contains(t, cond.SQL, tt.expected)
		})
	}
}

func TestSearchCondition_InvalidColumnName(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	tests := []struct {
		name   string
		column string
	}{
		{"sql injection", "email; DROP TABLE users; --"},
		{"empty", ""},
		{"special chars", "email$1"},
		{"spaces", "email name"},
		{"quotes", "email'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Panics(t, func() {
				cipher.SearchCondition(tt.column, []byte("test"), 1)
			})
		})
	}
}

func TestSearchCondition_ValidColumnNames(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	validNames := []string{
		"email",
		"Email",
		"EMAIL",
		"email_address",
		"user_email_2",
		"Col123",
		"_private",
		"a",
	}

	for _, col := range validNames {
		t.Run(col, func(t *testing.T) {
			require.NotPanics(t, func() {
				cipher.SearchCondition(col, []byte("test"), 1)
			})
		})
	}
}

func TestSearchCondition_InvalidParamOffset(t *testing.T) {
	cipher, _ := New(WithKey("v1", testKey("v1")))

	tests := []struct {
		name   string
		offset int
	}{
		{"zero", 0},
		{"negative", -1},
		{"negative large", -100},
		{"exceeds max", maxParamNumber + 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Panics(t, func() {
				cipher.SearchCondition("email", []byte("test"), tt.offset)
			})
		})
	}
}

func TestSearchCondition_MaxParamOverflow(t *testing.T) {
	// Create cipher with many keys to test overflow protection
	cipher, _ := New(
		WithKey("v1", testKey("v1")),
		WithKey("v2", testKey("v2")),
		WithKey("v3", testKey("v3")),
	)

	// With 3 keys, we need 6 parameters (2 per key: key_id + index)
	// If paramOffset is 65532, then maxParam would be 65532 + 5 = 65537 > 65535
	require.Panics(t, func() {
		cipher.SearchCondition("email", []byte("test"), maxParamNumber-4)
	})

	// But offset 65530 should work: 65530 + 5 = 65535 (exactly at limit)
	require.NotPanics(t, func() {
		cipher.SearchCondition("email", []byte("test"), maxParamNumber-5)
	})
}
