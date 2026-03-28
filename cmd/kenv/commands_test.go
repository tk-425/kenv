package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tk-425/kenv/internal/vault"
)

func TestRunInitCreatesEncryptedVault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	var stdoutBuf bytes.Buffer
	reset := stubCLIEnv(t, cliStubOptions{
		stdout:                &stdoutBuf,
		promptPassphraseTwice: func(string, string) (string, error) { return "correct horse battery staple", nil },
	})
	defer reset()

	if got := runInit(nil); got != 0 {
		t.Fatalf("runInit() = %d, want 0", got)
	}
	if got := stdoutBuf.String(); got != "vault initialized\n" {
		t.Fatalf("stdout = %q, want vault initialized", got)
	}
}

func TestRunAddStoresScopedCredentialAndPrintsPlaceholder(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	createTestVault(t, "vault-passphrase", nil)

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	reset := stubCLIEnv(t, cliStubOptions{
		stdout:           &stdoutBuf,
		stderr:           &stderrBuf,
		promptPassphrase: func(string) (string, error) { return "vault-passphrase", nil },
		promptSecret:     func(string) (string, error) { return "sk-live-secret", nil },
		confirmScope:     func(vault.Scope) (bool, error) { return true, nil },
		currentWorkingDir: func() (string, error) {
			return "/tmp/kenv", nil
		},
		detectScope: func(string) (vault.Scope, error) {
			return vault.Scope{ID: "github.com/tk-425/kenv", Label: "kenv", Path: "/tmp/kenv", GitBacked: true}, nil
		},
		now: func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})
	defer reset()

	if got := runAdd([]string{"OPENAI_API_KEY"}); got != 0 {
		t.Fatalf("runAdd() = %d, want 0", got)
	}

	decrypted := decryptTestVault(t, "vault-passphrase")
	if len(decrypted.Credentials) != 1 {
		t.Fatalf("len(credentials) = %d, want 1", len(decrypted.Credentials))
	}
	credential := decrypted.Credentials[0]
	if credential.ScopeID != "github.com/tk-425/kenv" || credential.EnvKey != "OPENAI_API_KEY" {
		t.Fatalf("credential = %#v, want scoped OPENAI_API_KEY record", credential)
	}
	if got, want := stdoutBuf.String(), "OPENAI_API_KEY="+credential.Placeholder+"\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if got, want := stderrBuf.String(), "Secret saved.\nkenv stores the secret securely and will not display it back to you later.\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

func TestRunAddPrintsNormalizedEnvAssignment(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	createTestVault(t, "vault-passphrase", nil)

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	reset := stubCLIEnv(t, cliStubOptions{
		stdout:           &stdoutBuf,
		stderr:           &stderrBuf,
		promptPassphrase: func(string) (string, error) { return "vault-passphrase", nil },
		promptSecret:     func(string) (string, error) { return "sk-live-secret", nil },
		confirmScope:     func(vault.Scope) (bool, error) { return true, nil },
		currentWorkingDir: func() (string, error) {
			return "/tmp/kenv", nil
		},
		detectScope: func(string) (vault.Scope, error) {
			return vault.Scope{ID: "github.com/tk-425/kenv", Label: "kenv", Path: "/tmp/kenv", GitBacked: true}, nil
		},
		now: func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})
	defer reset()

	if got := runAdd([]string{" OPENAI_API_KEY "}); got != 0 {
		t.Fatalf("runAdd() = %d, want 0", got)
	}

	decrypted := decryptTestVault(t, "vault-passphrase")
	if len(decrypted.Credentials) != 1 {
		t.Fatalf("len(credentials) = %d, want 1", len(decrypted.Credentials))
	}
	credential := decrypted.Credentials[0]
	if got, want := stdoutBuf.String(), "OPENAI_API_KEY="+credential.Placeholder+"\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if got, want := stderrBuf.String(), "Secret saved.\nkenv stores the secret securely and will not display it back to you later.\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

func TestRunAddFailsWhenMigrationIsPending(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	createTestVault(t, "vault-passphrase", []vault.Credential{
		testCredential("local:abc", "kenv", "/tmp/kenv", "OPENAI_API_KEY", "kvn_aaaaaaaaaaaaaaaaaaaa", "sk-secret"),
	})

	var stderrBuf bytes.Buffer
	reset := stubCLIEnv(t, cliStubOptions{
		stderr:           &stderrBuf,
		promptPassphrase: func(string) (string, error) { return "vault-passphrase", nil },
		currentWorkingDir: func() (string, error) {
			return "/tmp/kenv", nil
		},
		detectScope: func(string) (vault.Scope, error) {
			return vault.Scope{ID: "github.com/tk-425/kenv", Label: "kenv", Path: "/tmp/kenv", GitBacked: true}, nil
		},
	})
	defer reset()

	if got := runAdd([]string{"OPENAI_API_KEY"}); got != 1 {
		t.Fatalf("runAdd() = %d, want 1", got)
	}
	if !strings.Contains(stderrBuf.String(), "kenv scope migrate") {
		t.Fatalf("stderr = %q, want migration recommendation", stderrBuf.String())
	}
	if strings.Contains(stderrBuf.String(), "Secret saved.") {
		t.Fatalf("stderr = %q, want no add success reminder", stderrBuf.String())
	}
}

func TestRunListShowsCurrentScopeMetadata(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	createTestVault(t, "vault-passphrase", []vault.Credential{
		testCredential("github.com/tk-425/kenv", "kenv", "/tmp/kenv", "OPENAI_API_KEY", "kvn_aaaaaaaaaaaaaaaaaaaa", "sk-openai-secret"),
		testCredential("github.com/tk-425/other", "other", "/tmp/other", "OPENAI_API_KEY", "kvn_bbbbbbbbbbbbbbbbbbbb", "sk-other-secret"),
	})

	var stdoutBuf bytes.Buffer
	reset := stubCLIEnv(t, cliStubOptions{
		stdout:           &stdoutBuf,
		promptPassphrase: func(string) (string, error) { return "vault-passphrase", nil },
		currentWorkingDir: func() (string, error) {
			return "/tmp/kenv", nil
		},
		detectScope: func(string) (vault.Scope, error) {
			return vault.Scope{ID: "github.com/tk-425/kenv", Label: "kenv", Path: "/tmp/kenv", GitBacked: true}, nil
		},
	})
	defer reset()

	if got := runList(nil); got != 0 {
		t.Fatalf("runList() = %d, want 0", got)
	}
	if got := stdoutBuf.String(); !strings.Contains(got, "kenv\tOPENAI_API_KEY\tkvn_aaaaaaaaaaaaaaaaaaaa\n") {
		t.Fatalf("stdout = %q, want current-scope metadata", got)
	}
}

func TestRunShowPrintsPlaceholderOnly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	createTestVault(t, "vault-passphrase", []vault.Credential{
		testCredential("github.com/tk-425/kenv", "kenv", "/tmp/kenv", "OPENAI_API_KEY", "kvn_aaaaaaaaaaaaaaaaaaaa", "sk-secret"),
	})

	var stdoutBuf bytes.Buffer
	reset := stubCLIEnv(t, cliStubOptions{
		stdout:           &stdoutBuf,
		promptPassphrase: func(string) (string, error) { return "vault-passphrase", nil },
		currentWorkingDir: func() (string, error) {
			return "/tmp/kenv", nil
		},
		detectScope: func(string) (vault.Scope, error) {
			return vault.Scope{ID: "github.com/tk-425/kenv", Label: "kenv", Path: "/tmp/kenv", GitBacked: true}, nil
		},
	})
	defer reset()

	if got := runShow([]string{"OPENAI_API_KEY"}); got != 0 {
		t.Fatalf("runShow() = %d, want 0", got)
	}
	if got := stdoutBuf.String(); got != "kvn_aaaaaaaaaaaaaaaaaaaa\n" {
		t.Fatalf("stdout = %q, want placeholder", got)
	}
}

func TestRunRemoveDeletesScopedCredential(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	createTestVault(t, "vault-passphrase", []vault.Credential{
		testCredential("github.com/tk-425/kenv", "kenv", "/tmp/kenv", "OPENAI_API_KEY", "kvn_aaaaaaaaaaaaaaaaaaaa", "sk-openai-secret"),
		testCredential("github.com/tk-425/other", "other", "/tmp/other", "OPENAI_API_KEY", "kvn_bbbbbbbbbbbbbbbbbbbb", "sk-other-secret"),
	})

	var stdoutBuf bytes.Buffer
	reset := stubCLIEnv(t, cliStubOptions{
		stdout:           &stdoutBuf,
		promptPassphrase: func(string) (string, error) { return "vault-passphrase", nil },
		confirmScope:     func(vault.Scope) (bool, error) { return true, nil },
		currentWorkingDir: func() (string, error) {
			return "/tmp/kenv", nil
		},
		detectScope: func(string) (vault.Scope, error) {
			return vault.Scope{ID: "github.com/tk-425/kenv", Label: "kenv", Path: "/tmp/kenv", GitBacked: true}, nil
		},
	})
	defer reset()

	if got := runRemove([]string{"OPENAI_API_KEY"}); got != 0 {
		t.Fatalf("runRemove() = %d, want 0", got)
	}
	if got := stdoutBuf.String(); got != "removed OPENAI_API_KEY\n" {
		t.Fatalf("stdout = %q, want removal output", got)
	}
	decrypted := decryptTestVault(t, "vault-passphrase")
	if len(decrypted.Credentials) != 1 || decrypted.Credentials[0].ScopeID != "github.com/tk-425/other" {
		t.Fatalf("remaining credentials = %#v, want only other scope", decrypted.Credentials)
	}
}

func TestRunScopeMigrateMigratesMatchingLocalScope(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	createTestVault(t, "vault-passphrase", []vault.Credential{
		testCredential("local:abc", "kenv", "/tmp/kenv", "OPENAI_API_KEY", "kvn_aaaaaaaaaaaaaaaaaaaa", "sk-openai-secret"),
	})

	var stdoutBuf bytes.Buffer
	reset := stubCLIEnv(t, cliStubOptions{
		stdout:           &stdoutBuf,
		promptPassphrase: func(string) (string, error) { return "vault-passphrase", nil },
		confirmMigration: func(vault.Scope, []vault.Credential) (bool, error) { return true, nil },
		currentWorkingDir: func() (string, error) {
			return "/tmp/kenv", nil
		},
		detectScope: func(string) (vault.Scope, error) {
			return vault.Scope{ID: "github.com/tk-425/kenv", Label: "kenv", Path: "/tmp/kenv", GitBacked: true}, nil
		},
	})
	defer reset()

	if got := runScopeMigrate(nil); got != 0 {
		t.Fatalf("runScopeMigrate() = %d, want 0", got)
	}
	decrypted := decryptTestVault(t, "vault-passphrase")
	if decrypted.Credentials[0].ScopeID != "github.com/tk-425/kenv" {
		t.Fatalf("ScopeID = %q, want migrated git scope", decrypted.Credentials[0].ScopeID)
	}
}

type cliStubOptions struct {
	stdout                *bytes.Buffer
	stderr                *bytes.Buffer
	promptPassphrase      func(string) (string, error)
	promptPassphraseTwice func(string, string) (string, error)
	promptSecret          func(string) (string, error)
	parentEnviron         func() []string
	runChildProcess       func([]string, []string) (int, error)
	currentWorkingDir     func() (string, error)
	detectScope           func(string) (vault.Scope, error)
	confirmScope          func(vault.Scope) (bool, error)
	confirmMigration      func(vault.Scope, []vault.Credential) (bool, error)
	now                   func() time.Time
}

func stubCLIEnv(t *testing.T, opts cliStubOptions) func() {
	t.Helper()

	originalStdout := stdout
	originalStderr := stderr
	originalPromptPassphrase := promptPassphrase
	originalPromptPassphraseTwice := promptPassphraseTwice
	originalPromptSecret := promptSecretValue
	originalParentEnviron := parentEnviron
	originalRunChildProcess := runChildProcess
	originalCurrentWorkingDir := currentWorkingDir
	originalDetectScope := detectScope
	originalConfirmScope := confirmScopeFunc
	originalConfirmMigration := confirmScopeMigrationFunc
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
	if opts.parentEnviron != nil {
		parentEnviron = opts.parentEnviron
	}
	if opts.runChildProcess != nil {
		runChildProcess = opts.runChildProcess
	}
	if opts.currentWorkingDir != nil {
		currentWorkingDir = opts.currentWorkingDir
	}
	if opts.detectScope != nil {
		detectScope = opts.detectScope
	}
	if opts.confirmScope != nil {
		confirmScopeFunc = opts.confirmScope
	}
	if opts.confirmMigration != nil {
		confirmScopeMigrationFunc = opts.confirmMigration
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
		parentEnviron = originalParentEnviron
		runChildProcess = originalRunChildProcess
		currentWorkingDir = originalCurrentWorkingDir
		detectScope = originalDetectScope
		confirmScopeFunc = originalConfirmScope
		confirmScopeMigrationFunc = originalConfirmMigration
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

func writeTestEnvFile(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func testCredential(scopeID, scopeLabel, scopePath, envKey, placeholder, secret string) vault.Credential {
	return vault.Credential{
		ScopeID:     scopeID,
		ScopeLabel:  scopeLabel,
		ScopePath:   scopePath,
		EnvKey:      envKey,
		Placeholder: placeholder,
		Secret:      secret,
		CreatedAt:   time.Unix(1700000000, 0).UTC(),
	}
}
