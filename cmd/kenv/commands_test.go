package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/tk-425/kenv/internal/vault"
)

func TestRunInitCreatesEncryptedVault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	reset := stubCLIEnv(t, cliStubOptions{
		stdout:                &stdoutBuf,
		stderr:                &stderrBuf,
		promptPassphraseTwice: func(string, string) (string, error) { return "correct horse battery staple", nil },
	})
	defer reset()

	if got := runInit(nil); got != 0 {
		t.Fatalf("runInit() = %d, want 0", got)
	}

	ciphertext, err := vault.LoadCiphertext()
	if err != nil {
		t.Fatalf("LoadCiphertext() error = %v", err)
	}

	decrypted, err := vault.DecryptVault(ciphertext, "correct horse battery staple")
	if err != nil {
		t.Fatalf("DecryptVault() error = %v", err)
	}

	if decrypted.Version != vault.CurrentVersion {
		t.Fatalf("decrypted.Version = %d, want %d", decrypted.Version, vault.CurrentVersion)
	}
	if len(decrypted.Credentials) != 0 {
		t.Fatalf("len(decrypted.Credentials) = %d, want 0", len(decrypted.Credentials))
	}
	if got := stdoutBuf.String(); got != "vault initialized\n" {
		t.Fatalf("stdout = %q, want %q", got, "vault initialized\n")
	}
	if stderrBuf.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderrBuf.String())
	}
}

func TestRunInitFailsWhenVaultAlreadyExists(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	createTestVault(t, "existing-passphrase", nil)

	var stderrBuf bytes.Buffer
	promptCalled := false
	reset := stubCLIEnv(t, cliStubOptions{
		stderr: &stderrBuf,
		promptPassphraseTwice: func(string, string) (string, error) {
			promptCalled = true
			return "new-passphrase", nil
		},
	})
	defer reset()

	if got := runInit(nil); got != 1 {
		t.Fatalf("runInit() = %d, want 1", got)
	}
	if got := stderrBuf.String(); got != "vault already exists\n" {
		t.Fatalf("stderr = %q, want %q", got, "vault already exists\n")
	}
	if promptCalled {
		t.Fatal("promptPassphraseTwice() called, want existing vault failure before prompting")
	}
}

func TestRunAddStoresSecretAndPrintsPlaceholderOnly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	createTestVault(t, "vault-passphrase", nil)

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	reset := stubCLIEnv(t, cliStubOptions{
		stdout:           &stdoutBuf,
		stderr:           &stderrBuf,
		promptPassphrase: func(string) (string, error) { return "vault-passphrase", nil },
		promptSecret:     func(string) (string, error) { return "sk-live-secret", nil },
		now:              func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})
	defer reset()

	if got := runAdd([]string{"openai"}); got != 0 {
		t.Fatalf("runAdd() = %d, want 0", got)
	}

	decrypted := decryptTestVault(t, "vault-passphrase")
	if len(decrypted.Credentials) != 1 {
		t.Fatalf("len(decrypted.Credentials) = %d, want 1", len(decrypted.Credentials))
	}

	credential := decrypted.Credentials[0]
	placeholderOutput := strings.TrimSpace(stdoutBuf.String())
	if credential.Name != "openai" {
		t.Fatalf("credential.Name = %q, want %q", credential.Name, "openai")
	}
	if credential.Secret != "sk-live-secret" {
		t.Fatalf("credential.Secret = %q, want %q", credential.Secret, "sk-live-secret")
	}
	if placeholderOutput != credential.Placeholder {
		t.Fatalf("stdout placeholder = %q, want %q", placeholderOutput, credential.Placeholder)
	}
	if strings.Contains(stdoutBuf.String(), credential.Secret) {
		t.Fatalf("stdout unexpectedly contains secret: %q", stdoutBuf.String())
	}
	if strings.Contains(stderrBuf.String(), credential.Secret) {
		t.Fatalf("stderr unexpectedly contains secret: %q", stderrBuf.String())
	}
}

func TestRunAddFailsWhenVaultMissing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	var stderrBuf bytes.Buffer
	promptCalled := false
	reset := stubCLIEnv(t, cliStubOptions{
		stderr: &stderrBuf,
		promptPassphrase: func(string) (string, error) {
			promptCalled = true
			return "vault-passphrase", nil
		},
	})
	defer reset()

	if got := runAdd([]string{"openai"}); got != 1 {
		t.Fatalf("runAdd() = %d, want 1", got)
	}
	if got := stderrBuf.String(); got != "vault does not exist; run `kenv init` first\n" {
		t.Fatalf("stderr = %q", got)
	}
	if promptCalled {
		t.Fatal("promptPassphrase() called, want missing vault failure before prompting")
	}
}

func TestRunAddFailsWhenPromptRequiresTTY(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	createTestVault(t, "vault-passphrase", nil)

	var stderrBuf bytes.Buffer
	reset := stubCLIEnv(t, cliStubOptions{
		stderr:           &stderrBuf,
		promptPassphrase: func(string) (string, error) { return "", vault.ErrPromptRequiresTTY },
	})
	defer reset()

	if got := runAdd([]string{"openai"}); got != 1 {
		t.Fatalf("runAdd() = %d, want 1", got)
	}
	if got := stderrBuf.String(); got != vault.ErrPromptRequiresTTY.Error()+"\n" {
		t.Fatalf("stderr = %q, want %q", got, vault.ErrPromptRequiresTTY.Error()+"\n")
	}
}

func TestRunShowPrintsPlaceholderOnly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	createTestVault(t, "vault-passphrase", []vault.Credential{
		{
			Name:        "openai",
			Placeholder: "kvn_aaaaaaaaaaaaaaaaaaaa",
			Secret:      "sk-secret",
			CreatedAt:   time.Unix(1700000000, 0).UTC(),
		},
	})

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	reset := stubCLIEnv(t, cliStubOptions{
		stdout:           &stdoutBuf,
		stderr:           &stderrBuf,
		promptPassphrase: func(string) (string, error) { return "vault-passphrase", nil },
	})
	defer reset()

	if got := runShow([]string{"openai"}); got != 0 {
		t.Fatalf("runShow() = %d, want 0", got)
	}
	if got := stdoutBuf.String(); got != "kvn_aaaaaaaaaaaaaaaaaaaa\n" {
		t.Fatalf("stdout = %q, want %q", got, "kvn_aaaaaaaaaaaaaaaaaaaa\n")
	}
	if strings.Contains(stdoutBuf.String(), "sk-secret") {
		t.Fatalf("stdout unexpectedly contains secret: %q", stdoutBuf.String())
	}
	if stderrBuf.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderrBuf.String())
	}
}

func TestRunListPrintsRedactedMetadataOnly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	createTestVault(t, "vault-passphrase", []vault.Credential{
		{
			Name:        "openai",
			Placeholder: "kvn_aaaaaaaaaaaaaaaaaaaa",
			Secret:      "sk-openai-secret",
			CreatedAt:   time.Unix(1700000000, 0).UTC(),
		},
		{
			Name:        "anthropic",
			Placeholder: "kvn_bbbbbbbbbbbbbbbbbbbb",
			Secret:      "sk-anthropic-secret",
			CreatedAt:   time.Unix(1700000001, 0).UTC(),
		},
	})

	var stdoutBuf bytes.Buffer
	reset := stubCLIEnv(t, cliStubOptions{
		stdout:           &stdoutBuf,
		promptPassphrase: func(string) (string, error) { return "vault-passphrase", nil },
	})
	defer reset()

	if got := runList(nil); got != 0 {
		t.Fatalf("runList() = %d, want 0", got)
	}

	output := stdoutBuf.String()
	if !strings.Contains(output, "openai\tkvn_aaaaaaaaaaaaaaaaaaaa\n") {
		t.Fatalf("stdout = %q, want openai metadata line", output)
	}
	if !strings.Contains(output, "anthropic\tkvn_bbbbbbbbbbbbbbbbbbbb\n") {
		t.Fatalf("stdout = %q, want anthropic metadata line", output)
	}
	if strings.Contains(output, "sk-openai-secret") || strings.Contains(output, "sk-anthropic-secret") {
		t.Fatalf("stdout unexpectedly contains secret values: %q", output)
	}
}

func TestRunRemoveDeletesCredentialAndPersistsVault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	createTestVault(t, "vault-passphrase", []vault.Credential{
		{
			Name:        "openai",
			Placeholder: "kvn_aaaaaaaaaaaaaaaaaaaa",
			Secret:      "sk-openai-secret",
			CreatedAt:   time.Unix(1700000000, 0).UTC(),
		},
		{
			Name:        "anthropic",
			Placeholder: "kvn_bbbbbbbbbbbbbbbbbbbb",
			Secret:      "sk-anthropic-secret",
			CreatedAt:   time.Unix(1700000001, 0).UTC(),
		},
	})

	var stdoutBuf bytes.Buffer
	reset := stubCLIEnv(t, cliStubOptions{
		stdout:           &stdoutBuf,
		promptPassphrase: func(string) (string, error) { return "vault-passphrase", nil },
	})
	defer reset()

	if got := runRemove([]string{"openai"}); got != 0 {
		t.Fatalf("runRemove() = %d, want 0", got)
	}
	if got := stdoutBuf.String(); got != "removed openai\n" {
		t.Fatalf("stdout = %q, want %q", got, "removed openai\n")
	}

	decrypted := decryptTestVault(t, "vault-passphrase")
	if len(decrypted.Credentials) != 1 {
		t.Fatalf("len(decrypted.Credentials) = %d, want 1", len(decrypted.Credentials))
	}
	if decrypted.Credentials[0].Name != "anthropic" {
		t.Fatalf("remaining credential = %q, want %q", decrypted.Credentials[0].Name, "anthropic")
	}
}

type cliStubOptions struct {
	stdout                *bytes.Buffer
	stderr                *bytes.Buffer
	promptPassphrase      func(string) (string, error)
	promptPassphraseTwice func(string, string) (string, error)
	promptSecret          func(string) (string, error)
	now                   func() time.Time
}

func stubCLIEnv(t *testing.T, opts cliStubOptions) func() {
	t.Helper()

	originalStdout := stdout
	originalStderr := stderr
	originalPromptPassphrase := promptPassphrase
	originalPromptPassphraseTwice := promptPassphraseTwice
	originalPromptSecret := promptSecretValue
	originalNow := now

	stdout = bytes.NewBuffer(nil)
	if opts.stdout != nil {
		stdout = opts.stdout
	}

	stderr = bytes.NewBuffer(nil)
	if opts.stderr != nil {
		stderr = opts.stderr
	}

	if opts.promptPassphrase != nil {
		promptPassphrase = opts.promptPassphrase
	}
	if opts.promptPassphraseTwice != nil {
		promptPassphraseTwice = opts.promptPassphraseTwice
	}
	if opts.promptSecret != nil {
		promptSecretValue = opts.promptSecret
	}
	if opts.now != nil {
		now = opts.now
	}

	return func() {
		stdout = originalStdout
		stderr = originalStderr
		promptPassphrase = originalPromptPassphrase
		promptPassphraseTwice = originalPromptPassphraseTwice
		promptSecretValue = originalPromptSecret
		now = originalNow
	}
}

func createTestVault(t *testing.T, passphrase string, credentials []vault.Credential) {
	t.Helper()

	encrypted, err := vault.EncryptVault(vault.Vault{
		Version:     vault.CurrentVersion,
		Credentials: credentials,
	}, passphrase)
	if err != nil {
		t.Fatalf("EncryptVault() error = %v", err)
	}
	if err := vault.SaveCiphertext(encrypted); err != nil {
		t.Fatalf("SaveCiphertext() error = %v", err)
	}
}

func decryptTestVault(t *testing.T, passphrase string) vault.Vault {
	t.Helper()

	ciphertext, err := vault.LoadCiphertext()
	if err != nil {
		t.Fatalf("LoadCiphertext() error = %v", err)
	}

	decrypted, err := vault.DecryptVault(ciphertext, passphrase)
	if err != nil {
		t.Fatalf("DecryptVault() error = %v", err)
	}

	return decrypted
}
