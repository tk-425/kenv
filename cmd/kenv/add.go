package main

import (
	"fmt"

	"github.com/tk-425/kenv/internal/vault"
)

func runAdd(args []string) int {
	if wantsHelp(args) {
		printAddUsage()
		return 0
	}
	if len(args) != 1 {
		printAddUsage()
		return 2
	}

	v, passphrase, err := loadUnlockedVault()
	if err != nil {
		printCommandError(err)
		return 1
	}

	scope, err := detectCurrentScope()
	if err != nil {
		printCommandError(err)
		return 1
	}
	if err := ensureNoPendingScopeMigration(v, scope); err != nil {
		printCommandError(err)
		return 1
	}
	confirmed, err := confirmScope(scope)
	if err != nil {
		printCommandError(err)
		return 1
	}
	if !confirmed {
		fmt.Fprintln(stdout, "add canceled")
		return 1
	}

	secret, err := promptSecretValue("Secret value: ")
	if err != nil {
		printCommandError(err)
		return 1
	}

	credential, err := vault.AddScopedCredential(&v, scope, args[0], secret, now())
	if err != nil {
		printCommandError(err)
		return 1
	}

	if err := saveVault(v, passphrase); err != nil {
		printCommandError(err)
		return 1
	}

	fmt.Fprintln(stdout, credential.Placeholder)
	return 0
}

func printAddUsage() {
	fmt.Fprintln(stderr, `Usage:
  kenv add <env-key>`)
}
