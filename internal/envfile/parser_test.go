package envfile

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseSupportsMVPGrammar(t *testing.T) {
	content := "\ufeff  # comment\r\n" +
		"FOO=bar\r\n" +
		" EMPTY =   \r\n" +
		"SINGLE='literal # value'\r\n" +
		"DOUBLE=\"line\\nvalue\\tquoted\\\\\"\r\n" +
		"PLACEHOLDER=kvn_aaaaaaaaaaaaaaaaaaaa\r\n"

	parsed, err := Parse(".env", content)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	wantEntries := []Entry{
		{Key: "FOO", Value: "bar", Line: 2},
		{Key: "EMPTY", Value: "", Line: 3},
		{Key: "SINGLE", Value: "literal # value", Line: 4},
		{Key: "DOUBLE", Value: "line\nvalue\tquoted\\", Line: 5},
		{Key: "PLACEHOLDER", Value: "kvn_aaaaaaaaaaaaaaaaaaaa", Line: 6},
	}
	if !reflect.DeepEqual(parsed.Entries, wantEntries) {
		t.Fatalf("Entries = %#v, want %#v", parsed.Entries, wantEntries)
	}
	if got := parsed.Values["FOO"]; got != "bar" {
		t.Fatalf("Values[FOO] = %q, want %q", got, "bar")
	}
	if len(parsed.PlaceholderCandidates) != 1 || parsed.PlaceholderCandidates[0].Key != "PLACEHOLDER" {
		t.Fatalf("PlaceholderCandidates = %#v, want PLACEHOLDER candidate", parsed.PlaceholderCandidates)
	}
	if len(parsed.Warnings) != 0 {
		t.Fatalf("Warnings = %#v, want none", parsed.Warnings)
	}
}

func TestParseDetectsWarningsInFileOrder(t *testing.T) {
	content := strings.Join([]string{
		"OPENAI_API_KEY=sk-live",
		"AUTH_TOKEN=abc123",
		"PLACEHOLDER_TOKEN=kvn_aaaaaaaaaaaaaaaaaaaa",
		"PASSWORD = hunter2",
	}, "\n")

	parsed, err := Parse(".env", content)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(parsed.Warnings) != 3 {
		t.Fatalf("len(Warnings) = %d, want 3", len(parsed.Warnings))
	}

	want := []Warning{
		{Key: "OPENAI_API_KEY", Line: 1, Message: "warning: OPENAI_API_KEY appears to contain a plaintext secret; use a kenv placeholder instead"},
		{Key: "AUTH_TOKEN", Line: 2, Message: "warning: AUTH_TOKEN appears to contain a plaintext secret; use a kenv placeholder instead"},
		{Key: "PASSWORD", Line: 4, Message: "warning: PASSWORD appears to contain a plaintext secret; use a kenv placeholder instead"},
	}
	if !reflect.DeepEqual(parsed.Warnings, want) {
		t.Fatalf("Warnings = %#v, want %#v", parsed.Warnings, want)
	}
}

func TestParseRejectsInvalidSyntax(t *testing.T) {
	testCases := []struct {
		name    string
		content string
		wantErr string
	}{
		{name: "duplicate key", content: "FOO=one\nFOO=two\n", wantErr: "invalid env syntax at .env:2: duplicate key \"FOO\" (first defined at line 1)"},
		{name: "invalid key", content: "BAD-KEY=value\n", wantErr: "invalid env syntax at .env:1: invalid key \"BAD-KEY\""},
		{name: "export syntax", content: "export FOO=bar\n", wantErr: "invalid env syntax at .env:1: unsupported export syntax"},
		{name: "bad escape", content: "FOO=\"bad\\x\"\n", wantErr: "invalid env syntax at .env:1: unsupported escape sequence in double-quoted value"},
		{name: "trailing characters", content: "FOO='bar' nope\n", wantErr: "invalid env syntax at .env:1: unexpected trailing characters after quoted value"},
		{name: "missing closing quote", content: "FOO='bar\n", wantErr: "invalid env syntax at .env:1: missing closing quote"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(".env", tc.content)
			if err == nil {
				t.Fatal("Parse() error = nil, want error")
			}
			if err.Error() != tc.wantErr {
				t.Fatalf("Parse() error = %q, want %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestParseFileIncludesPathInReadError(t *testing.T) {
	_, err := ParseFile(filepath.Join(t.TempDir(), "missing.env"))
	if err == nil {
		t.Fatal("ParseFile() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "read env file") {
		t.Fatalf("ParseFile() error = %q, want read env file prefix", err.Error())
	}
}

func TestSyntaxErrorType(t *testing.T) {
	_, err := Parse(".env", "BAD KEY=value\n")
	if err == nil {
		t.Fatal("Parse() error = nil, want error")
	}

	var syntaxErr *SyntaxError
	if !errors.As(err, &syntaxErr) {
		t.Fatalf("Parse() error = %T, want *SyntaxError", err)
	}
	if syntaxErr.Path != ".env" || syntaxErr.Line != 1 {
		t.Fatalf("SyntaxError = %#v, want path .env line 1", syntaxErr)
	}
}

func TestParseFileReadsContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	parsed, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile() error = %v", err)
	}
	if got := parsed.Values["FOO"]; got != "bar" {
		t.Fatalf("Values[FOO] = %q, want %q", got, "bar")
	}
}
