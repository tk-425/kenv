package vault

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestAddCredentialAddsCanonicalCredential(t *testing.T) {
	vault := Vault{Version: CurrentVersion}
	now := time.Date(2026, time.March, 27, 12, 0, 0, 0, time.UTC)

	credential, err := AddCredential(&vault, "  openai  ", "sk-test-secret", now)
	if err != nil {
		t.Fatalf("AddCredential() error = %v", err)
	}

	if credential.Name != "openai" {
		t.Fatalf("Name = %q, want %q", credential.Name, "openai")
	}
	if credential.Secret != "sk-test-secret" {
		t.Fatalf("Secret = %q, want %q", credential.Secret, "sk-test-secret")
	}
	if !credential.CreatedAt.Equal(now) {
		t.Fatalf("CreatedAt = %v, want %v", credential.CreatedAt, now)
	}
	if !placeholderPattern.MatchString(credential.Placeholder) {
		t.Fatalf("Placeholder = %q, want format %q", credential.Placeholder, placeholderPattern.String())
	}

	got, err := GetCredentialByName(vault, "openai")
	if err != nil {
		t.Fatalf("GetCredentialByName() error = %v", err)
	}
	if got != credential {
		t.Fatalf("GetCredentialByName() = %+v, want %+v", got, credential)
	}
}

func TestAddCredentialRejectsDuplicateTrimEquivalentName(t *testing.T) {
	vault := Vault{
		Version: CurrentVersion,
		Credentials: []Credential{
			{
				Name:        "openai",
				Placeholder: "kvn_1234567890abcdefghij",
				Secret:      "existing-secret",
				CreatedAt:   time.Date(2026, time.March, 26, 0, 0, 0, 0, time.UTC),
			},
		},
	}

	_, err := AddCredential(&vault, "  openai  ", "new-secret", time.Now())
	if !errors.Is(err, ErrCredentialExists) {
		t.Fatalf("AddCredential() error = %v, want ErrCredentialExists", err)
	}
}

func TestAddCredentialRejectsInvalidName(t *testing.T) {
	vault := Vault{Version: CurrentVersion}

	_, err := AddCredential(&vault, "   ", "secret", time.Now())
	if !errors.Is(err, ErrInvalidCredentialName) {
		t.Fatalf("AddCredential() error = %v, want ErrInvalidCredentialName", err)
	}
}

func TestListCredentialsReturnsCopy(t *testing.T) {
	vault := testVault()

	credentials := ListCredentials(vault)
	if len(credentials) != 1 {
		t.Fatalf("len(ListCredentials()) = %d, want 1", len(credentials))
	}

	credentials[0].Name = "mutated"

	if vault.Credentials[0].Name != "openai" {
		t.Fatalf("ListCredentials() returned alias to vault slice")
	}
	if credentials[0].Placeholder != "kvn_1234567890abcdefghij" {
		t.Fatalf("Placeholder = %q, want %q", credentials[0].Placeholder, "kvn_1234567890abcdefghij")
	}
	if credentials[0].CreatedAt.IsZero() {
		t.Fatal("CreatedAt unexpectedly zero")
	}
}

func TestListCredentialsRedactsSecret(t *testing.T) {
	vault := testVault()

	credentials := ListCredentials(vault)
	if len(credentials) != 1 {
		t.Fatalf("len(ListCredentials()) = %d, want 1", len(credentials))
	}

	if _, ok := any(credentials[0]).(Credential); ok {
		t.Fatal("ListCredentials() returned Credential instead of redacted metadata")
	}
}

func TestGetCredentialByNameRejectsInvalidName(t *testing.T) {
	_, err := GetCredentialByName(testVault(), "   ")
	if !errors.Is(err, ErrInvalidCredentialName) {
		t.Fatalf("GetCredentialByName() error = %v, want ErrInvalidCredentialName", err)
	}
}

func TestGetCredentialByNameReturnsNotFound(t *testing.T) {
	_, err := GetCredentialByName(testVault(), "anthropic")
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("GetCredentialByName() error = %v, want ErrCredentialNotFound", err)
	}
}

func TestGetCredentialByNameNormalizesInput(t *testing.T) {
	credential, err := GetCredentialByName(testVault(), " openai ")
	if err != nil {
		t.Fatalf("GetCredentialByName() error = %v", err)
	}

	if credential.Name != "openai" {
		t.Fatalf("Name = %q, want %q", credential.Name, "openai")
	}
}

func TestRemoveCredentialRemovesExistingCredential(t *testing.T) {
	vault := Vault{
		Version: CurrentVersion,
		Credentials: []Credential{
			{
				Name:        "openai",
				Placeholder: "kvn_1234567890abcdefghij",
				Secret:      "first-secret",
				CreatedAt:   time.Date(2026, time.March, 26, 0, 0, 0, 0, time.UTC),
			},
			{
				Name:        "anthropic",
				Placeholder: "kvn_abcdefghij1234567890",
				Secret:      "second-secret",
				CreatedAt:   time.Date(2026, time.March, 26, 1, 0, 0, 0, time.UTC),
			},
		},
	}

	if err := RemoveCredential(&vault, " openai "); err != nil {
		t.Fatalf("RemoveCredential() error = %v", err)
	}

	if len(vault.Credentials) != 1 {
		t.Fatalf("len(Credentials) = %d, want 1", len(vault.Credentials))
	}
	if vault.Credentials[0].Name != "anthropic" {
		t.Fatalf("remaining credential = %q, want %q", vault.Credentials[0].Name, "anthropic")
	}
}

func TestRemoveCredentialReturnsNotFound(t *testing.T) {
	vault := testVault()

	err := RemoveCredential(&vault, "anthropic")
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("RemoveCredential() error = %v, want ErrCredentialNotFound", err)
	}
}

func TestGenerateUniquePlaceholderRetriesCollision(t *testing.T) {
	originalReader := placeholderRandomReader
	placeholderRandomReader = bytes.NewReader(append(bytes.Repeat([]byte{27}, placeholderBodyLength), bytes.Repeat([]byte{28}, placeholderBodyLength)...))
	t.Cleanup(func() {
		placeholderRandomReader = originalReader
	})

	existing := []Credential{
		{
			Name:        "openai",
			Placeholder: placeholderPrefix + strings.Repeat("1", placeholderBodyLength),
			Secret:      "secret",
			CreatedAt:   time.Now(),
		},
	}

	placeholder, err := generateUniquePlaceholder(existing)
	if err != nil {
		t.Fatalf("generateUniquePlaceholder() error = %v", err)
	}

	if placeholder != placeholderPrefix+strings.Repeat("2", placeholderBodyLength) {
		t.Fatalf("generateUniquePlaceholder() = %q, want %q", placeholder, placeholderPrefix+strings.Repeat("2", placeholderBodyLength))
	}
}

func TestGenerateUniquePlaceholderReturnsExhaustedAfterCollisions(t *testing.T) {
	originalReader := placeholderRandomReader
	placeholderRandomReader = bytes.NewReader(bytes.Repeat([]byte{27}, placeholderBodyLength*maxPlaceholderAttempts))
	t.Cleanup(func() {
		placeholderRandomReader = originalReader
	})

	existing := []Credential{
		{
			Name:        "openai",
			Placeholder: placeholderPrefix + strings.Repeat("1", placeholderBodyLength),
			Secret:      "secret",
			CreatedAt:   time.Now(),
		},
	}

	_, err := generateUniquePlaceholder(existing)
	if !errors.Is(err, ErrPlaceholderGenerationExhausted) {
		t.Fatalf("generateUniquePlaceholder() error = %v, want ErrPlaceholderGenerationExhausted", err)
	}
}

func TestAddCredentialGeneratedPlaceholderMatchesContract(t *testing.T) {
	vault := Vault{Version: CurrentVersion}

	credential, err := AddCredential(&vault, "service", "secret", time.Now())
	if err != nil {
		t.Fatalf("AddCredential() error = %v", err)
	}

	pattern := regexp.MustCompile(`^kvn_[a-z0-9]{20}$`)
	if !pattern.MatchString(credential.Placeholder) {
		t.Fatalf("Placeholder = %q, want Step 5 format", credential.Placeholder)
	}
}
