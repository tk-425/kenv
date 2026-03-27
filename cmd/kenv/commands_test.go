package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
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

func TestRunCmdHelperProcess(t *testing.T) {
	args := helperProcessArgs()
	if len(args) == 0 || args[0] != "kenv-test-child" {
		return
	}

	if len(args) < 2 {
		os.Exit(97)
	}

	switch args[1] {
	case "print-env":
		for _, key := range args[2:] {
			_, _ = os.Stdout.WriteString(key + "=" + os.Getenv(key) + "\n")
		}
		os.Exit(0)
	case "exit":
		if len(args) != 3 {
			os.Exit(97)
		}

		code, err := strconv.Atoi(args[2])
		if err != nil {
			os.Exit(97)
		}
		os.Exit(code)
	default:
		os.Exit(97)
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

func TestRunCmdPassesThroughOrdinaryEnvWithoutVaultAccess(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	envPath := writeTestEnvFile(t, "PORT=3000\nLOG_LEVEL=debug\n")

	var gotCommand []string
	var gotEnv []string
	promptCalled := false
	reset := stubCLIEnv(t, cliStubOptions{
		parentEnviron: func() []string {
			return []string{
				"PATH=/usr/bin",
				"HOME=/tmp/test-home",
				"IGNORED=value",
				"TMPDIR=/tmp/runtime",
			}
		},
		promptPassphrase: func(string) (string, error) {
			promptCalled = true
			return "", nil
		},
		runChildProcess: func(command []string, env []string) (int, error) {
			gotCommand = append([]string(nil), command...)
			gotEnv = append([]string(nil), env...)
			return 0, nil
		},
	})
	defer reset()

	if got := runCmd([]string{"--env", envPath, "--", "echo", "hi"}); got != 0 {
		t.Fatalf("runCmd() = %d, want 0", got)
	}
	if promptCalled {
		t.Fatal("promptPassphrase() called, want vault unlock skipped when no placeholders exist")
	}
	if !equalStringSlices(gotCommand, []string{"echo", "hi"}) {
		t.Fatalf("command = %#v, want %#v", gotCommand, []string{"echo", "hi"})
	}
	if !equalStringSlices(gotEnv, []string{"PATH=/usr/bin", "HOME=/tmp/test-home", "TMPDIR=/tmp/runtime", "PORT=3000", "LOG_LEVEL=debug"}) {
		t.Fatalf("env = %#v, want baseline env plus parsed values", gotEnv)
	}
}

func TestRunCmdEndToEndPassesThroughOrdinaryEnv(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	envPath := writeTestEnvFile(t, "PORT=3000\nLOG_LEVEL=debug\n")

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	promptCalled := false
	reset := stubCLIEnv(t, cliStubOptions{
		stdout: &stdoutBuf,
		stderr: &stderrBuf,
		parentEnviron: func() []string {
			return []string{
				"PATH=/usr/bin",
				"HOME=/tmp/test-home",
				"TMPDIR=/tmp/runtime",
				"IGNORED=value",
			}
		},
		promptPassphrase: func(string) (string, error) {
			promptCalled = true
			return "", nil
		},
	})
	defer reset()

	args := append([]string{"--env", envPath, "--"}, helperCommand("print-env", "PATH", "HOME", "TMPDIR", "PORT", "LOG_LEVEL", "IGNORED")...)
	if got := runCmd(args); got != 0 {
		t.Fatalf("runCmd() = %d, want 0", got)
	}
	if promptCalled {
		t.Fatal("promptPassphrase() called, want vault unlock skipped when no placeholders exist")
	}
	if got := stdoutBuf.String(); got != "PATH=/usr/bin\nHOME=/tmp/test-home\nTMPDIR=/tmp/runtime\nPORT=3000\nLOG_LEVEL=debug\nIGNORED=\n" {
		t.Fatalf("stdout = %q, want child env output with baseline and parsed values", got)
	}
	if stderrBuf.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderrBuf.String())
	}
}

func TestRunCmdResolvesKnownPlaceholders(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	createTestVault(t, "vault-passphrase", []vault.Credential{
		{
			Name:        "openai",
			Placeholder: "kvn_aaaaaaaaaaaaaaaaaaaa",
			Secret:      "sk-openai-secret",
			CreatedAt:   time.Unix(1700000000, 0).UTC(),
		},
	})

	envPath := writeTestEnvFile(t, "OPENAI_API_KEY=kvn_aaaaaaaaaaaaaaaaaaaa\nPORT=3000\n")

	var gotEnv []string
	reset := stubCLIEnv(t, cliStubOptions{
		parentEnviron: func() []string {
			return []string{
				"PATH=/usr/bin",
				"HOME=/tmp/test-home",
			}
		},
		promptPassphrase: func(string) (string, error) { return "vault-passphrase", nil },
		runChildProcess: func(command []string, env []string) (int, error) {
			gotEnv = append([]string(nil), env...)
			return 0, nil
		},
	})
	defer reset()

	if got := runCmd([]string{"--env", envPath, "--", "echo", "hi"}); got != 0 {
		t.Fatalf("runCmd() = %d, want 0", got)
	}

	if !equalStringSlices(gotEnv, []string{"PATH=/usr/bin", "HOME=/tmp/test-home", "OPENAI_API_KEY=sk-openai-secret", "PORT=3000"}) {
		t.Fatalf("env = %#v, want resolved secret env", gotEnv)
	}
}

func TestRunCmdEndToEndResolvesKnownPlaceholders(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	createTestVault(t, "vault-passphrase", []vault.Credential{
		{
			Name:        "openai",
			Placeholder: "kvn_aaaaaaaaaaaaaaaaaaaa",
			Secret:      "sk-openai-secret",
			CreatedAt:   time.Unix(1700000000, 0).UTC(),
		},
	})

	envPath := writeTestEnvFile(t, "OPENAI_API_KEY=kvn_aaaaaaaaaaaaaaaaaaaa\nPORT=3000\n")

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	reset := stubCLIEnv(t, cliStubOptions{
		stdout: &stdoutBuf,
		stderr: &stderrBuf,
		parentEnviron: func() []string {
			return []string{
				"PATH=/usr/bin",
				"HOME=/tmp/test-home",
			}
		},
		promptPassphrase: func(string) (string, error) { return "vault-passphrase", nil },
	})
	defer reset()

	args := append([]string{"--env", envPath, "--"}, helperCommand("print-env", "PATH", "HOME", "OPENAI_API_KEY", "PORT")...)
	if got := runCmd(args); got != 0 {
		t.Fatalf("runCmd() = %d, want 0", got)
	}
	if got := stdoutBuf.String(); got != "PATH=/usr/bin\nHOME=/tmp/test-home\nOPENAI_API_KEY=sk-openai-secret\nPORT=3000\n" {
		t.Fatalf("stdout = %q, want child env output with resolved secret", got)
	}
	if strings.Contains(stdoutBuf.String(), "kvn_aaaaaaaaaaaaaaaaaaaa") {
		t.Fatalf("stdout unexpectedly contains unresolved placeholder: %q", stdoutBuf.String())
	}
	if stderrBuf.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderrBuf.String())
	}
}

func TestRunCmdFailsOnUnknownPlaceholdersBeforeSpawn(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	createTestVault(t, "vault-passphrase", nil)

	envPath := writeTestEnvFile(t, "OPENAI_API_KEY=kvn_aaaaaaaaaaaaaaaaaaaa\n")

	var stderrBuf bytes.Buffer
	runCalled := false
	reset := stubCLIEnv(t, cliStubOptions{
		stderr:           &stderrBuf,
		promptPassphrase: func(string) (string, error) { return "vault-passphrase", nil },
		runChildProcess: func(command []string, env []string) (int, error) {
			runCalled = true
			return 0, nil
		},
	})
	defer reset()

	if got := runCmd([]string{"--env", envPath, "--", "echo", "hi"}); got != 1 {
		t.Fatalf("runCmd() = %d, want 1", got)
	}
	if runCalled {
		t.Fatal("runChildProcess() called, want unknown placeholders failure before spawn")
	}
	if got := stderrBuf.String(); got != "unknown placeholder(s): kvn_aaaaaaaaaaaaaaaaaaaa\n" {
		t.Fatalf("stderr = %q, want unknown placeholder error", got)
	}
}

func TestRunCmdEmitsWarningsToStderrBeforeSpawn(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	envPath := writeTestEnvFile(t, "OPENAI_API_KEY=sk-live-secret\n")

	var stderrBuf bytes.Buffer
	reset := stubCLIEnv(t, cliStubOptions{
		stderr: &stderrBuf,
		runChildProcess: func(command []string, env []string) (int, error) {
			return 0, nil
		},
	})
	defer reset()

	if got := runCmd([]string{"--env", envPath, "--", "echo", "hi"}); got != 0 {
		t.Fatalf("runCmd() = %d, want 0", got)
	}
	if got := stderrBuf.String(); got != "warning: OPENAI_API_KEY appears to contain a plaintext secret; use a kenv placeholder instead\n" {
		t.Fatalf("stderr = %q, want warning only", got)
	}
	if strings.Contains(stderrBuf.String(), "sk-live-secret") {
		t.Fatalf("stderr unexpectedly contains secret: %q", stderrBuf.String())
	}
}

func TestRunCmdInheritEnvOverlaysParsedAndResolvedValues(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	createTestVault(t, "vault-passphrase", []vault.Credential{
		{
			Name:        "openai",
			Placeholder: "kvn_aaaaaaaaaaaaaaaaaaaa",
			Secret:      "sk-openai-secret",
			CreatedAt:   time.Unix(1700000000, 0).UTC(),
		},
	})

	envPath := writeTestEnvFile(t, "OPENAI_API_KEY=kvn_aaaaaaaaaaaaaaaaaaaa\nLOG_LEVEL=debug\n")

	var gotEnv []string
	reset := stubCLIEnv(t, cliStubOptions{
		parentEnviron:    func() []string { return []string{"PATH=/usr/bin", "OPENAI_API_KEY=parent-secret", "APP_MODE=prod"} },
		promptPassphrase: func(string) (string, error) { return "vault-passphrase", nil },
		runChildProcess: func(command []string, env []string) (int, error) {
			gotEnv = append([]string(nil), env...)
			return 0, nil
		},
	})
	defer reset()

	if got := runCmd([]string{"--inherit-env", "--env", envPath, "--", "echo", "hi"}); got != 0 {
		t.Fatalf("runCmd() = %d, want 0", got)
	}
	if !equalStringSlices(gotEnv, []string{"PATH=/usr/bin", "OPENAI_API_KEY=sk-openai-secret", "APP_MODE=prod", "LOG_LEVEL=debug"}) {
		t.Fatalf("env = %#v, want inherited env with overlays", gotEnv)
	}
}

func TestRunCmdEndToEndInheritEnvOverlaysParsedAndResolvedValues(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	createTestVault(t, "vault-passphrase", []vault.Credential{
		{
			Name:        "openai",
			Placeholder: "kvn_aaaaaaaaaaaaaaaaaaaa",
			Secret:      "sk-openai-secret",
			CreatedAt:   time.Unix(1700000000, 0).UTC(),
		},
	})

	envPath := writeTestEnvFile(t, "OPENAI_API_KEY=kvn_aaaaaaaaaaaaaaaaaaaa\nAPP_MODE=dev\nLOG_LEVEL=debug\n")

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	reset := stubCLIEnv(t, cliStubOptions{
		stdout: &stdoutBuf,
		stderr: &stderrBuf,
		parentEnviron: func() []string {
			return []string{
				"PATH=/usr/bin",
				"OPENAI_API_KEY=parent-secret",
				"APP_MODE=prod",
			}
		},
		promptPassphrase: func(string) (string, error) { return "vault-passphrase", nil },
	})
	defer reset()

	args := append([]string{"--inherit-env", "--env", envPath, "--"}, helperCommand("print-env", "PATH", "OPENAI_API_KEY", "APP_MODE", "LOG_LEVEL")...)
	if got := runCmd(args); got != 0 {
		t.Fatalf("runCmd() = %d, want 0", got)
	}
	if got := stdoutBuf.String(); got != "PATH=/usr/bin\nOPENAI_API_KEY=sk-openai-secret\nAPP_MODE=dev\nLOG_LEVEL=debug\n" {
		t.Fatalf("stdout = %q, want inherited env with parsed and resolved overlays", got)
	}
	if stderrBuf.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderrBuf.String())
	}
}

func TestRunCmdEndToEndReturnsChildExitCode(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	envPath := writeTestEnvFile(t, "LOG_LEVEL=debug\n")

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	reset := stubCLIEnv(t, cliStubOptions{
		stdout: &stdoutBuf,
		stderr: &stderrBuf,
		parentEnviron: func() []string {
			return []string{
				"PATH=/usr/bin",
			}
		},
	})
	defer reset()

	args := append([]string{"--env", envPath, "--"}, helperCommand("exit", "23")...)
	if got := runCmd(args); got != 23 {
		t.Fatalf("runCmd() = %d, want 23", got)
	}
	if stdoutBuf.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdoutBuf.String())
	}
	if stderrBuf.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderrBuf.String())
	}
}

func TestRunCmdFailsWhenPromptRequiresTTYForPlaceholders(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	createTestVault(t, "vault-passphrase", nil)

	envPath := writeTestEnvFile(t, "OPENAI_API_KEY=kvn_aaaaaaaaaaaaaaaaaaaa\n")

	var stderrBuf bytes.Buffer
	runCalled := false
	reset := stubCLIEnv(t, cliStubOptions{
		stderr:           &stderrBuf,
		promptPassphrase: func(string) (string, error) { return "", vault.ErrPromptRequiresTTY },
		runChildProcess: func(command []string, env []string) (int, error) {
			runCalled = true
			return 0, nil
		},
	})
	defer reset()

	if got := runCmd([]string{"--env", envPath, "--", "echo", "hi"}); got != 1 {
		t.Fatalf("runCmd() = %d, want 1", got)
	}
	if runCalled {
		t.Fatal("runChildProcess() called, want prompt failure before spawn")
	}
	if got := stderrBuf.String(); got != vault.ErrPromptRequiresTTY.Error()+"\n" {
		t.Fatalf("stderr = %q, want prompt requires tty error", got)
	}
}

func writeTestEnvFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	return path
}

func helperCommand(args ...string) []string {
	command := []string{os.Args[0], "-test.run=^TestRunCmdHelperProcess$", "--", "kenv-test-child"}
	return append(command, args...)
}

func helperProcessArgs() []string {
	for index, arg := range os.Args {
		if arg == "--" {
			return append([]string(nil), os.Args[index+1:]...)
		}
	}

	return nil
}

func equalStringSlices(got, want []string) bool {
	return len(got) == len(want) && strings.Join(got, "\x00") == strings.Join(want, "\x00")
}
