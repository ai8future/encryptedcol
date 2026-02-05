# rcodegen Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix remaining valid issues from rcodegen audit/fix/quick reports.

**Architecture:** Two small defensive validation fixes in search.go to prevent invalid SQL generation.

**Tech Stack:** Go, PostgreSQL SQL generation

---

## Summary of Reports Processed

| Report | Status |
|--------|--------|
| codex-encryptedcol-audit-2026-01-19_1910.md | Processed |
| codex-encryptedcol-fix-2026-01-19_1927.md | Processed |
| codex-encryptedcol-quick-2026-01-19_1938.md | Processed |

## Items NOT Implementing

| Item | Source | Rationale |
|------|--------|-----------|
| Panic-based API DoS concern | audit #1 | Per CLAUDE.md: panic is correct for programmer error. Column names are compile-time constants. |
| Compression flag unauthenticated | audit #4 | Future format version change, not actionable now |
| sync.Pool for compression buffers | quick REFACTOR | YAGNI - current allocation pattern is fine |
| closed flag for post-Close | quick REFACTOR | YAGNI |
| Key ID validation helper | quick REFACTOR | YAGNI |
| Test suggestions | all | User requested to skip test suggestions |

---

## Task 1: Fix Column Name Validation

**Files:**
- Modify: `search.go:10-21`

**Problem:** `isValidColumnName()` allows column names starting with digits (e.g., `"123column"`), which produces invalid SQL in PostgreSQL since unquoted identifiers cannot start with digits.

**Step 1: Update isValidColumnName to reject leading digits**

Change from:
```go
func isValidColumnName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	return true
}
```

To:
```go
// isValidColumnName checks if a column name is safe for SQL interpolation.
// Must start with letter or underscore, followed by alphanumeric/underscore.
func isValidColumnName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 {
			// First character: letter or underscore only
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_') {
				return false
			}
		} else {
			// Subsequent characters: alphanumeric or underscore
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '_') {
				return false
			}
		}
	}
	return true
}
```

**Step 2: Update panic message**

Change:
```go
panic("encryptedcol: invalid column name (must be alphanumeric/underscore only): " + column)
```

To:
```go
panic("encryptedcol: invalid column name (must start with letter/underscore, contain only alphanumeric/underscore): " + column)
```

**Step 3: Run tests**

Run: `go test ./... -run TestSearchCondition`
Expected: All tests pass (existing tests use valid column names like "email")

**Step 4: Commit**

```bash
git add search.go
git commit -m "fix: reject column names starting with digits in SearchCondition"
```

---

## Task 2: Add paramOffset Validation

**Files:**
- Modify: `search.go:45-48`

**Problem:** `paramOffset <= 0` produces invalid SQL placeholders (`$0`, `$-1`) causing runtime SQL errors.

**Step 1: Add paramOffset validation after column name check**

Add after line 48:
```go
if paramOffset < 1 {
	panic("encryptedcol: invalid paramOffset (must be >= 1)")
}
```

**Step 2: Run tests**

Run: `go test ./... -run TestSearchCondition`
Expected: All tests pass (existing tests use paramOffset >= 1)

**Step 3: Commit**

```bash
git add search.go
git commit -m "fix: validate paramOffset >= 1 in SearchCondition"
```

---

## Task 3: Update rcodegen Reports

After implementing fixes, update each report to remove fixed items and add "Date Updated".

---

## Verification

```bash
go test -v ./...      # All tests pass
go test -race ./...   # Race detection
```
