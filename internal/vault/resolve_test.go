package vault

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestResolvePlaceholdersReturnsResolvedMapping(t *testing.T) {
	v := Vault{
		Version: CurrentVersion,
		Credentials: []Credential{
			testCredential("github.com/tk-425/kenv", "kenv", "/tmp/kenv", "OPENAI_API_KEY", "kvn_aaaaaaaaaaaaaaaaaaaa", "sk-openai"),
			testCredential("github.com/tk-425/kenv", "kenv", "/tmp/kenv", "ANTHROPIC_API_KEY", "kvn_bbbbbbbbbbbbbbbbbbbb", "sk-anthropic"),
		},
	}

	resolved, err := ResolvePlaceholders(v, []string{
		"kvn_aaaaaaaaaaaaaaaaaaaa",
		"kvn_bbbbbbbbbbbbbbbbbbbb",
		"kvn_aaaaaaaaaaaaaaaaaaaa",
	})
	if err != nil {
		t.Fatalf("ResolvePlaceholders() error = %v", err)
	}

	want := map[string]string{
		"kvn_aaaaaaaaaaaaaaaaaaaa": "sk-openai",
		"kvn_bbbbbbbbbbbbbbbbbbbb": "sk-anthropic",
	}
	if !reflect.DeepEqual(resolved, want) {
		t.Fatalf("ResolvePlaceholders() = %#v, want %#v", resolved, want)
	}
}

func TestResolvePlaceholdersReturnsEmptyMappingForEmptyInput(t *testing.T) {
	resolved, err := ResolvePlaceholders(Vault{Version: CurrentVersion}, nil)
	if err != nil {
		t.Fatalf("ResolvePlaceholders() error = %v, want nil", err)
	}
	if len(resolved) != 0 {
		t.Fatalf("len(ResolvePlaceholders()) = %d, want 0", len(resolved))
	}
}

func TestResolvePlaceholdersReturnsOrderedDeduplicatedUnknowns(t *testing.T) {
	v := Vault{
		Version: CurrentVersion,
		Credentials: []Credential{
			testCredential("github.com/tk-425/kenv", "kenv", "/tmp/kenv", "OPENAI_API_KEY", "kvn_aaaaaaaaaaaaaaaaaaaa", "sk-openai"),
		},
	}

	_, err := ResolvePlaceholders(v, []string{
		"kvn_missingmissingaaaa",
		"kvn_aaaaaaaaaaaaaaaaaaaa",
		"kvn_othermissingbbbbbb",
		"kvn_missingmissingaaaa",
	})
	if err == nil {
		t.Fatal("ResolvePlaceholders() error = nil, want unknown placeholders error")
	}

	var unknownErr *UnknownPlaceholdersError
	if !errors.As(err, &unknownErr) {
		t.Fatalf("ResolvePlaceholders() error = %T, want *UnknownPlaceholdersError", err)
	}

	wantUnknown := []string{
		"kvn_missingmissingaaaa",
		"kvn_othermissingbbbbbb",
	}
	if !reflect.DeepEqual(unknownErr.Unknown, wantUnknown) {
		t.Fatalf("Unknown = %#v, want %#v", unknownErr.Unknown, wantUnknown)
	}
	if got := err.Error(); got != "unknown placeholder(s): kvn_missingmissingaaaa, kvn_othermissingbbbbbb" {
		t.Fatalf("Error() = %q, want ordered unknown placeholders", got)
	}
	if strings.Contains(err.Error(), "sk-openai") {
		t.Fatalf("Error() unexpectedly exposed secret: %q", err.Error())
	}
}

func TestResolvePlaceholdersReturnsNilMapOnUnknowns(t *testing.T) {
	v := Vault{
		Version: CurrentVersion,
		Credentials: []Credential{
			testCredential("github.com/tk-425/kenv", "kenv", "/tmp/kenv", "OPENAI_API_KEY", "kvn_aaaaaaaaaaaaaaaaaaaa", "sk-openai"),
		},
	}

	resolved, err := ResolvePlaceholders(v, []string{
		"kvn_aaaaaaaaaaaaaaaaaaaa",
		"kvn_missingmissingaaaa",
	})
	if err == nil {
		t.Fatal("ResolvePlaceholders() error = nil, want error")
	}
	if resolved != nil {
		t.Fatalf("ResolvePlaceholders() map = %#v, want nil on unknown placeholders", resolved)
	}
}
