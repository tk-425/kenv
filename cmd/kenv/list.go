package main

import (
	"fmt"

	"github.com/tk-425/kenv/internal/vault"
)

func runList(args []string) int {
	if wantsHelp(args) {
		printListUsage()
		return 0
	}
	if len(args) != 0 {
		printListUsage()
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

	credentials, err := vault.ListCredentialsInScope(v, scope.ID)
	if err != nil {
		printCommandError(err)
		return 1
	}
	for _, credential := range credentials {
		fmt.Fprintf(stdout, "%s\t%s\t%s\n", credential.ScopeLabel, credential.EnvKey, credential.Placeholder)
	}

	return 0
}

func printListUsage() {
	fmt.Fprintln(stderr, `Usage:
  kenv list`)
}
