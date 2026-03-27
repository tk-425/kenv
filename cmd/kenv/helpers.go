package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/tk-425/kenv/internal/vault"
)

var (
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr

	promptPassphrase      = vault.PromptPassphrase
	promptPassphraseTwice = vault.PromptPassphraseTwice
	promptSecretValue     = vault.PromptSecret

	loadVaultCiphertext = vault.LoadCiphertext
	saveVaultCiphertext = vault.SaveCiphertext
	encryptVaultData    = vault.EncryptVault
	decryptVaultData    = vault.DecryptVault

	now = time.Now
)

var errVaultAlreadyExists = errors.New("vault already exists")

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
	default:
		return err.Error()
	}
}
