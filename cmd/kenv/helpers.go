package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/tk-425/kenv/internal/vault"
)

var (
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr

	promptPassphrase      = vault.PromptPassphrase
	promptPassphraseTwice = vault.PromptPassphraseTwice
	promptSecretValue     = vault.PromptSecret

	loadVaultCiphertext       = vault.LoadCiphertext
	saveVaultCiphertext       = vault.SaveCiphertext
	encryptVaultData          = vault.EncryptVault
	decryptVaultData          = vault.DecryptVault
	detectScope               = vault.DetectScope
	parentEnviron             = os.Environ
	runChildProcess           = execChildProcess
	currentWorkingDir         = os.Getwd
	confirmScopeFunc          = confirmScopePrompt
	confirmScopeMigrationFunc = confirmScopeMigrationPrompt

	now = time.Now
)

var (
	errVaultAlreadyExists   = errors.New("vault already exists")
	errScopeMigrationNeeded = errors.New("scope migration required")
)

func wantsHelp(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			return true
		}
	}

	return false
}

func loadUnlockedVault() (vault.Vault, string, error) {
	ciphertext, err := loadVaultCiphertext()
	if err != nil {
		return vault.Vault{}, "", err
	}

	passphrase, err := promptPassphrase("Vault passphrase: ")
	if err != nil {
		return vault.Vault{}, "", err
	}

	decrypted, err := decryptVaultData(ciphertext, passphrase)
	if err != nil {
		return vault.Vault{}, "", err
	}

	return decrypted, passphrase, nil
}

func saveVault(v vault.Vault, passphrase string) error {
	ciphertext, err := encryptVaultData(v, passphrase)
	if err != nil {
		return err
	}

	return saveVaultCiphertext(ciphertext)
}

func detectCurrentScope() (vault.Scope, error) {
	cwd, err := currentWorkingDir()
	if err != nil {
		return vault.Scope{}, fmt.Errorf("resolve current directory: %w", err)
	}

	return detectScope(cwd)
}

func ensureNoPendingScopeMigration(v vault.Vault, scope vault.Scope) error {
	if !scope.GitBacked {
		return nil
	}

	hasPending, err := vault.HasLocalScopeCredentialsForPath(v, scope.Path)
	if err != nil {
		return err
	}
	if hasPending {
		return errScopeMigrationNeeded
	}

	return nil
}

func confirmScope(scope vault.Scope) (bool, error) {
	return confirmScopeFunc(scope)
}

func confirmScopeMigration(scope vault.Scope, credentials []vault.Credential) (bool, error) {
	return confirmScopeMigrationFunc(scope, credentials)
}

func confirmScopePrompt(scope vault.Scope) (bool, error) {
	return promptYesNo(fmt.Sprintf("Detected project:\n  root: %s\n  scope: %s\n  label: %s\n\nUse this project scope? [y/N] ", scope.Path, scope.ID, scope.Label))
}

func confirmScopeMigrationPrompt(scope vault.Scope, credentials []vault.Credential) (bool, error) {
	return promptYesNo(fmt.Sprintf("Detected %d credential(s) to migrate into git scope %s.\nProject root: %s\n\nProceed with `kenv scope migrate`? [y/N] ", len(credentials), scope.ID, scope.Path))
}

func promptYesNo(prompt string) (bool, error) {
	if _, err := fmt.Fprint(stderr, prompt); err != nil {
		return false, fmt.Errorf("write prompt: %w", err)
	}

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("read prompt response: %w", err)
	}

	answer := strings.ToLower(strings.TrimSpace(response))
	return answer == "y" || answer == "yes", nil
}

func ensureVaultDoesNotExist() error {
	_, err := loadVaultCiphertext()
	if errors.Is(err, vault.ErrVaultMissing) {
		return nil
	}
	if err != nil {
		return err
	}

	return errVaultAlreadyExists
}

func printCommandError(err error) {
	fmt.Fprintln(stderr, formatCommandError(err))
}

func formatCommandError(err error) string {
	switch {
	case errors.Is(err, errVaultAlreadyExists):
		return errVaultAlreadyExists.Error()
	case errors.Is(err, vault.ErrVaultMissing):
		return "vault does not exist; run `kenv init` first"
	case errors.Is(err, vault.ErrCredentialNotFound):
		return vault.ErrCredentialNotFound.Error()
	case errors.Is(err, vault.ErrCredentialExists):
		return vault.ErrCredentialExists.Error()
	case errors.Is(err, vault.ErrInvalidCredentialName):
		return vault.ErrInvalidCredentialName.Error()
	case errors.Is(err, vault.ErrUnlockFailed):
		return vault.ErrUnlockFailed.Error()
	case errors.Is(err, vault.ErrPromptRequiresTTY):
		return vault.ErrPromptRequiresTTY.Error()
	case errors.Is(err, vault.ErrPassphraseMismatch):
		return vault.ErrPassphraseMismatch.Error()
	case errors.Is(err, vault.ErrScopeMigrationConflict):
		return err.Error()
	case errors.Is(err, errScopeMigrationNeeded):
		return "this project has pending local-to-git scope migration; run `kenv scope migrate` first"
	default:
		return err.Error()
	}
}

func execChildProcess(command []string, env []string) (int, error) {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start child command: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitCode(exitErr.ProcessState), nil
		}

		return 0, fmt.Errorf("wait for child command: %w", err)
	}

	return exitCode(cmd.ProcessState), nil
}

func exitCode(state *os.ProcessState) int {
	if state == nil {
		return 1
	}

	if code := state.ExitCode(); code >= 0 {
		return code
	}

	return 1
}
