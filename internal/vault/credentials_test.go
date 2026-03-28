package vault

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestAddScopedCredentialAddsCanonicalCredential(t *testing.T) {
	v := Vault{Version: CurrentVersion}
	now := time.Date(2026, time.March, 27, 12, 0, 0, 0, time.UTC)
	scope := Scope{ID: "github.com/tk-425/kenv", Label: "kenv", Path: "/tmp/kenv", GitBacked: true}

	credential, err := AddScopedCredential(&v, scope, "  OPENAI_API_KEY  ", "sk-test-secret", now)
	if err != nil {
		t.Fatalf("AddScopedCredential() error = %v", err)
	}

	if credential.ScopeID != scope.ID || credential.ScopeLabel != scope.Label || credential.ScopePath != scope.Path {
		t.Fatalf("scope metadata = %#v, want %#v", credential, scope)
	}
	if credential.EnvKey != "OPENAI_API_KEY" {
		t.Fatalf("EnvKey = %q, want OPENAI_API_KEY", credential.EnvKey)
	}
	if credential.Secret != "sk-test-secret" {
		t.Fatalf("Secret = %q, want sk-test-secret", credential.Secret)
	}
	if !credential.CreatedAt.Equal(now) {
		t.Fatalf("CreatedAt = %v, want %v", credential.CreatedAt, now)
	}
	if !placeholderPattern.MatchString(credential.Placeholder) {
		t.Fatalf("Placeholder = %q, want format %q", credential.Placeholder, placeholderPattern.String())
	}
}

func TestAddScopedCredentialRejectsDuplicateScopedEnvKey(t *testing.T) {
	v := testVault()
	scope := Scope{ID: "github.com/tk-425/kenv", Label: "kenv", Path: "/tmp/kenv", GitBacked: true}

	_, err := AddScopedCredential(&v, scope, " OPENAI_API_KEY ", "new-secret", time.Now())
	if !errors.Is(err, ErrCredentialExists) {
		t.Fatalf("AddScopedCredential() error = %v, want ErrCredentialExists", err)
	}
}

func TestListCredentialsInScopeReturnsCopy(t *testing.T) {
	credentials, err := ListCredentialsInScope(testVault(), "github.com/tk-425/kenv")
	if err != nil {
		t.Fatalf("ListCredentialsInScope() error = %v", err)
	}
	if len(credentials) != 1 {
		t.Fatalf("len(ListCredentialsInScope()) = %d, want 1", len(credentials))
	}

	credentials[0].EnvKey = "mutated"
	if testVault().Credentials[0].EnvKey != "OPENAI_API_KEY" {
		t.Fatal("ListCredentialsInScope() returned alias to vault slice")
	}
}

func TestGetCredentialByScopeAndEnvKey(t *testing.T) {
	credential, err := GetCredentialByScopeAndEnvKey(testVault(), " github.com/tk-425/kenv ", " OPENAI_API_KEY ")
	if err != nil {
		t.Fatalf("GetCredentialByScopeAndEnvKey() error = %v", err)
	}
	if credential.EnvKey != "OPENAI_API_KEY" {
		t.Fatalf("EnvKey = %q, want OPENAI_API_KEY", credential.EnvKey)
	}
}

func TestRemoveCredentialByScopeAndEnvKey(t *testing.T) {
	v := Vault{
		Version: CurrentVersion,
		Credentials: []Credential{
			testCredential("github.com/tk-425/kenv", "kenv", "/tmp/kenv", "OPENAI_API_KEY", "kvn_1234567890abcdefghij", "first-secret"),
			testCredential("github.com/tk-425/other", "other", "/tmp/other", "OPENAI_API_KEY", "kvn_abcdefghij1234567890", "second-secret"),
		},
	}

	if err := RemoveCredentialByScopeAndEnvKey(&v, "github.com/tk-425/kenv", "OPENAI_API_KEY"); err != nil {
		t.Fatalf("RemoveCredentialByScopeAndEnvKey() error = %v", err)
	}
	if len(v.Credentials) != 1 {
		t.Fatalf("len(Credentials) = %d, want 1", len(v.Credentials))
	}
	if v.Credentials[0].ScopeID != "github.com/tk-425/other" {
		t.Fatalf("remaining credential scope = %q, want github.com/tk-425/other", v.Credentials[0].ScopeID)
	}
}

func TestFindLocalScopeCredentialsByPath(t *testing.T) {
	v := Vault{
		Version: CurrentVersion,
		Credentials: []Credential{
			testCredential("local:abc", "kenv", "/tmp/kenv", "OPENAI_API_KEY", "kvn_1234567890abcdefghij", "first-secret"),
			testCredential("github.com/tk-425/kenv", "kenv", "/tmp/kenv", "ANTHROPIC_API_KEY", "kvn_abcdefghij1234567890", "second-secret"),
		},
	}

	got, err := FindLocalScopeCredentialsByPath(v, "/tmp/kenv")
	if err != nil {
		t.Fatalf("FindLocalScopeCredentialsByPath() error = %v", err)
	}
	if len(got) != 1 || got[0].ScopeID != "local:abc" {
		t.Fatalf("matches = %#v, want one local-scope credential", got)
	}
}

func TestMigrateLocalScopeToGitScope(t *testing.T) {
	v := Vault{
		Version: CurrentVersion,
		Credentials: []Credential{
			testCredential("local:abc", "kenv", "/tmp/kenv", "OPENAI_API_KEY", "kvn_1234567890abcdefghij", "first-secret"),
		},
	}

	err := MigrateLocalScopeToGitScope(&v, Scope{ID: "github.com/tk-425/kenv", Label: "kenv", Path: "/tmp/kenv", GitBacked: true})
	if err != nil {
		t.Fatalf("MigrateLocalScopeToGitScope() error = %v", err)
	}
	if v.Credentials[0].ScopeID != "github.com/tk-425/kenv" {
		t.Fatalf("ScopeID = %q, want github.com/tk-425/kenv", v.Credentials[0].ScopeID)
	}
}

func TestMigrateLocalScopeToGitScopeRejectsConflict(t *testing.T) {
	v := Vault{
		Version: CurrentVersion,
		Credentials: []Credential{
			testCredential("local:abc", "kenv", "/tmp/kenv", "OPENAI_API_KEY", "kvn_1234567890abcdefghij", "first-secret"),
			testCredential("github.com/tk-425/kenv", "kenv", "/tmp/kenv", "OPENAI_API_KEY", "kvn_abcdefghij1234567890", "second-secret"),
		},
	}

	err := MigrateLocalScopeToGitScope(&v, Scope{ID: "github.com/tk-425/kenv", Label: "kenv", Path: "/tmp/kenv", GitBacked: true})
	if !errors.Is(err, ErrScopeMigrationConflict) {
		t.Fatalf("MigrateLocalScopeToGitScope() error = %v, want ErrScopeMigrationConflict", err)
	}
}

func TestGenerateUniquePlaceholderRetriesCollision(t *testing.T) {
	originalReader := placeholderRandomReader
	placeholderRandomReader = bytes.NewReader(append(bytes.Repeat([]byte{27}, placeholderBodyLength), bytes.Repeat([]byte{28}, placeholderBodyLength)...))
	t.Cleanup(func() { placeholderRandomReader = originalReader })

	existing := []Credential{
		testCredential("github.com/tk-425/kenv", "kenv", "/tmp/kenv", "OPENAI_API_KEY", placeholderPrefix+strings.Repeat("1", placeholderBodyLength), "secret"),
	}

	placeholder, err := generateUniquePlaceholder(existing)
	if err != nil {
		t.Fatalf("generateUniquePlaceholder() error = %v", err)
	}
	if placeholder != placeholderPrefix+strings.Repeat("2", placeholderBodyLength) {
		t.Fatalf("generateUniquePlaceholder() = %q, want %q", placeholder, placeholderPrefix+strings.Repeat("2", placeholderBodyLength))
	}
}

func TestAddScopedCredentialGeneratedPlaceholderMatchesContract(t *testing.T) {
	v := Vault{Version: CurrentVersion}
	scope := Scope{ID: "github.com/tk-425/kenv", Label: "kenv", Path: "/tmp/kenv", GitBacked: true}

	credential, err := AddScopedCredential(&v, scope, "SERVICE_TOKEN", "secret", time.Now())
	if err != nil {
		t.Fatalf("AddScopedCredential() error = %v", err)
	}

	pattern := regexp.MustCompile(`^kvn_[a-z0-9]{20}$`)
	if !pattern.MatchString(credential.Placeholder) {
		t.Fatalf("Placeholder = %q, want Step 5 format", credential.Placeholder)
	}
}
