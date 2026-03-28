package vault

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestEncryptDecryptVaultRoundTrip(t *testing.T) {
	vault := testVault()

	ciphertext, err := EncryptVault(vault, "correct horse battery staple")
	if err != nil {
		t.Fatalf("EncryptVault() error = %v", err)
	}

	got, err := DecryptVault(ciphertext, "correct horse battery staple")
	if err != nil {
		t.Fatalf("DecryptVault() error = %v", err)
	}

	if got.Version != vault.Version {
		t.Fatalf("Version = %d, want %d", got.Version, vault.Version)
	}
	if len(got.Credentials) != 1 {
		t.Fatalf("len(Credentials) = %d, want 1", len(got.Credentials))
	}

	credential := got.Credentials[0]
	want := vault.Credentials[0]
	if credential.ScopeID != want.ScopeID {
		t.Fatalf("ScopeID = %q, want %q", credential.ScopeID, want.ScopeID)
	}
	if credential.EnvKey != want.EnvKey {
		t.Fatalf("EnvKey = %q, want %q", credential.EnvKey, want.EnvKey)
	}
	if credential.Placeholder != want.Placeholder {
		t.Fatalf("Placeholder = %q, want %q", credential.Placeholder, want.Placeholder)
	}
	if credential.Secret != want.Secret {
		t.Fatalf("Secret = %q, want %q", credential.Secret, want.Secret)
	}
	if !credential.CreatedAt.Equal(want.CreatedAt) {
		t.Fatalf("CreatedAt = %v, want %v", credential.CreatedAt, want.CreatedAt)
	}
}

func TestDecryptVaultReturnsUnlockFailedForWrongPassphrase(t *testing.T) {
	vault := testVault()

	ciphertext, err := EncryptVault(vault, "correct horse battery staple")
	if err != nil {
		t.Fatalf("EncryptVault() error = %v", err)
	}

	_, err = DecryptVault(ciphertext, "wrong passphrase")
	if !errors.Is(err, ErrUnlockFailed) {
		t.Fatalf("DecryptVault() error = %v, want ErrUnlockFailed", err)
	}
}

func TestDecryptVaultRejectsCorruptedCiphertext(t *testing.T) {
	vault := testVault()

	ciphertext, err := EncryptVault(vault, "correct horse battery staple")
	if err != nil {
		t.Fatalf("EncryptVault() error = %v", err)
	}

	ciphertext[len(ciphertext)/2] ^= 0xff

	_, err = DecryptVault(ciphertext, "correct horse battery staple")
	if err == nil {
		t.Fatal("DecryptVault() error = nil, want error")
	}
	if errors.Is(err, ErrUnlockFailed) {
		t.Fatalf("DecryptVault() error = %v, want corruption/invalid-data failure", err)
	}
}

func TestDecryptVaultRejectsInvalidVaultPayload(t *testing.T) {
	ciphertext, err := encryptPlaintext([]byte("not-json"), "correct horse battery staple")
	if err != nil {
		t.Fatalf("encryptPlaintext() error = %v", err)
	}

	_, err = DecryptVault(ciphertext, "correct horse battery staple")
	if !errors.Is(err, ErrInvalidVaultData) {
		t.Fatalf("DecryptVault() error = %v, want ErrInvalidVaultData", err)
	}
}

func TestDecryptVaultRejectsUnsupportedVaultVersion(t *testing.T) {
	ciphertext, err := encryptPlaintext([]byte(`{"version":99,"credentials":[]}`), "correct horse battery staple")
	if err != nil {
		t.Fatalf("encryptPlaintext() error = %v", err)
	}

	_, err = DecryptVault(ciphertext, "correct horse battery staple")
	if !errors.Is(err, ErrUnsupportedVaultVersion) {
		t.Fatalf("DecryptVault() error = %v, want ErrUnsupportedVaultVersion", err)
	}
}

func TestDecryptVaultRejectsDuplicateCredentialNames(t *testing.T) {
	ciphertext, err := encryptPlaintext([]byte(`{"version":1,"credentials":[{"scope_id":"github.com/tk-425/kenv","scope_label":"kenv","scope_path":"/tmp/kenv","env_key":"OPENAI_API_KEY","placeholder":"kvn_1234567890abcdefghij","secret":"a","created_at":"2026-03-26T00:00:00Z"},{"scope_id":"github.com/tk-425/kenv","scope_label":"kenv","scope_path":"/tmp/kenv","env_key":"OPENAI_API_KEY","placeholder":"kvn_abcdefghij1234567890","secret":"b","created_at":"2026-03-26T00:00:00Z"}]}`), "correct horse battery staple")
	if err != nil {
		t.Fatalf("encryptPlaintext() error = %v", err)
	}

	_, err = DecryptVault(ciphertext, "correct horse battery staple")
	if !errors.Is(err, ErrInvalidVaultData) {
		t.Fatalf("DecryptVault() error = %v, want ErrInvalidVaultData", err)
	}
}

func TestDecryptVaultRejectsTrimEquivalentCredentialNames(t *testing.T) {
	ciphertext, err := encryptPlaintext([]byte(`{"version":1,"credentials":[{"scope_id":"github.com/tk-425/kenv","scope_label":"kenv","scope_path":"/tmp/kenv","env_key":"OPENAI_API_KEY","placeholder":"kvn_1234567890abcdefghij","secret":"a","created_at":"2026-03-26T00:00:00Z"},{"scope_id":" github.com/tk-425/kenv ","scope_label":"kenv","scope_path":"/tmp/kenv","env_key":" OPENAI_API_KEY ","placeholder":"kvn_abcdefghij1234567890","secret":"b","created_at":"2026-03-26T00:00:00Z"}]}`), "correct horse battery staple")
	if err != nil {
		t.Fatalf("encryptPlaintext() error = %v", err)
	}

	_, err = DecryptVault(ciphertext, "correct horse battery staple")
	if !errors.Is(err, ErrInvalidVaultData) {
		t.Fatalf("DecryptVault() error = %v, want ErrInvalidVaultData", err)
	}
}

func TestDecryptVaultRejectsDuplicatePlaceholders(t *testing.T) {
	ciphertext, err := encryptPlaintext([]byte(`{"version":1,"credentials":[{"scope_id":"github.com/tk-425/kenv","scope_label":"kenv","scope_path":"/tmp/kenv","env_key":"OPENAI_API_KEY","placeholder":"kvn_1234567890abcdefghij","secret":"a","created_at":"2026-03-26T00:00:00Z"},{"scope_id":"github.com/tk-425/other","scope_label":"other","scope_path":"/tmp/other","env_key":"ANTHROPIC_API_KEY","placeholder":"kvn_1234567890abcdefghij","secret":"b","created_at":"2026-03-26T00:00:00Z"}]}`), "correct horse battery staple")
	if err != nil {
		t.Fatalf("encryptPlaintext() error = %v", err)
	}

	_, err = DecryptVault(ciphertext, "correct horse battery staple")
	if !errors.Is(err, ErrInvalidVaultData) {
		t.Fatalf("DecryptVault() error = %v, want ErrInvalidVaultData", err)
	}
}

func TestDecryptVaultRejectsEmptyCredentialFields(t *testing.T) {
	testCases := []string{
		`{"version":1,"credentials":[{"scope_id":"","scope_label":"kenv","scope_path":"/tmp/kenv","env_key":"OPENAI_API_KEY","placeholder":"kvn_1234567890abcdefghij","secret":"a","created_at":"2026-03-26T00:00:00Z"}]}`,
		`{"version":1,"credentials":[{"scope_id":"github.com/tk-425/kenv","scope_label":"kenv","scope_path":"/tmp/kenv","env_key":"OPENAI_API_KEY","placeholder":"","secret":"a","created_at":"2026-03-26T00:00:00Z"}]}`,
	}

	for _, plaintext := range testCases {
		ciphertext, err := encryptPlaintext([]byte(plaintext), "correct horse battery staple")
		if err != nil {
			t.Fatalf("encryptPlaintext() error = %v", err)
		}

		_, err = DecryptVault(ciphertext, "correct horse battery staple")
		if !errors.Is(err, ErrInvalidVaultData) {
			t.Fatalf("DecryptVault() error = %v, want ErrInvalidVaultData", err)
		}
	}
}

func TestDecryptVaultRejectsMalformedPlaceholders(t *testing.T) {
	testCases := []string{
		`{"version":1,"credentials":[{"scope_id":"github.com/tk-425/kenv","scope_label":"kenv","scope_path":"/tmp/kenv","env_key":"OPENAI_API_KEY","placeholder":"${OPENAI_API_KEY}","secret":"a","created_at":"2026-03-26T00:00:00Z"}]}`,
		`{"version":1,"credentials":[{"scope_id":"github.com/tk-425/kenv","scope_label":"kenv","scope_path":"/tmp/kenv","env_key":"OPENAI_API_KEY","placeholder":"kvn_ABCDEF1234567890abcd","secret":"a","created_at":"2026-03-26T00:00:00Z"}]}`,
		`{"version":1,"credentials":[{"scope_id":"github.com/tk-425/kenv","scope_label":"kenv","scope_path":"/tmp/kenv","env_key":"OPENAI_API_KEY","placeholder":"kvn_short","secret":"a","created_at":"2026-03-26T00:00:00Z"}]}`,
	}

	for _, plaintext := range testCases {
		ciphertext, err := encryptPlaintext([]byte(plaintext), "correct horse battery staple")
		if err != nil {
			t.Fatalf("encryptPlaintext() error = %v", err)
		}

		_, err = DecryptVault(ciphertext, "correct horse battery staple")
		if !errors.Is(err, ErrInvalidVaultData) {
			t.Fatalf("DecryptVault() error = %v, want ErrInvalidVaultData", err)
		}
	}
}

func TestEncryptVaultCiphertextDiffersFromPlaintext(t *testing.T) {
	vault := testVault()

	ciphertext, err := EncryptVault(vault, "correct horse battery staple")
	if err != nil {
		t.Fatalf("EncryptVault() error = %v", err)
	}

	plaintext, err := marshalVault(vault)
	if err != nil {
		t.Fatalf("marshalVault() error = %v", err)
	}

	if string(ciphertext) == string(plaintext) {
		t.Fatal("ciphertext unexpectedly matches plaintext")
	}
	if strings.Contains(string(ciphertext), vault.Credentials[0].Secret) {
		t.Fatal("ciphertext unexpectedly contains plaintext secret")
	}
}

func TestMarshalVaultNormalizesNilCredentials(t *testing.T) {
	vault := Vault{Version: CurrentVersion}

	plaintext, err := marshalVault(vault)
	if err != nil {
		t.Fatalf("marshalVault() error = %v", err)
	}

	if strings.Contains(string(plaintext), `"credentials":null`) {
		t.Fatalf("marshalVault() produced null credentials: %s", plaintext)
	}
	if !strings.Contains(string(plaintext), `"credentials":[]`) {
		t.Fatalf("marshalVault() did not normalize empty credentials: %s", plaintext)
	}
}

func encryptPlaintext(plaintext []byte, passphrase string) ([]byte, error) {
	recipient, err := newScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}

	return encryptWithRecipient(plaintext, recipient)
}

func testVault() Vault {
	return Vault{
		Version: CurrentVersion,
		Credentials: []Credential{
			testCredential("github.com/tk-425/kenv", "kenv", "/tmp/kenv", "OPENAI_API_KEY", "kvn_1234567890abcdefghij", "sk-test-secret"),
		},
	}
}

func testCredential(scopeID, scopeLabel, scopePath, envKey, placeholder, secret string) Credential {
	return Credential{
		ScopeID:     scopeID,
		ScopeLabel:  scopeLabel,
		ScopePath:   scopePath,
		EnvKey:      envKey,
		Placeholder: placeholder,
		Secret:      secret,
		CreatedAt:   time.Date(2026, time.March, 26, 0, 0, 0, 0, time.UTC),
	}
}
