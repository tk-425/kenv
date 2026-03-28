package main

import (
	"fmt"

	"github.com/tk-425/kenv/internal/vault"
)

func runShow(args []string) int {
	if wantsHelp(args) {
		printShowUsage()
		return 0
	}
	if len(args) != 1 {
		printShowUsage()
		return 2
	}

	v, _, err := loadUnlockedVault()
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

	credential, err := vault.GetCredentialByScopeAndEnvKey(v, scope.ID, args[0])
	if err != nil {
		printCommandError(err)
		return 1
	}

	fmt.Fprintln(stdout, credential.Placeholder)
	return 0
}

func printShowUsage() {
	fmt.Fprintln(stderr, `Usage:
  kenv show <env-key>`)
}
