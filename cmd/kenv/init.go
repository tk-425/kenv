package main

import (
	"fmt"

	"github.com/tk-425/kenv/internal/vault"
)

func runInit(args []string) int {
	if wantsHelp(args) {
		printInitUsage()
		return 0
	}
	if len(args) != 0 {
		printInitUsage()
		return 2
	}

	if err := ensureVaultDoesNotExist(); err != nil {
		printCommandError(err)
		return 1
	}

	passphrase, err := promptPassphraseTwice("Vault passphrase: ", "Confirm passphrase: ")
	if err != nil {
		printCommandError(err)
		return 1
	}

	emptyVault := vault.Vault{
		Version:     vault.CurrentVersion,
		Credentials: []vault.Credential{},
	}

	if err := saveVault(emptyVault, passphrase); err != nil {
		printCommandError(err)
		return 1
	}

	ciphertext, err := loadVaultCiphertext()
	if err != nil {
		printCommandError(err)
		return 1
	}
	if _, err := decryptVaultData(ciphertext, passphrase); err != nil {
		printCommandError(err)
		return 1
	}

	fmt.Fprintln(stdout, "vault initialized")
	return 0
}

func printInitUsage() {
	fmt.Fprintln(stderr, `Usage:
  kenv init`)
}
