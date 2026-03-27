package main

import (
	"fmt"

	"github.com/tk-425/kenv/internal/vault"
)

func runRemove(args []string) int {
	if wantsHelp(args) {
		printRemoveUsage()
		return 0
	}
	if len(args) != 1 {
		printRemoveUsage()
		return 2
	}

	v, passphrase, err := loadUnlockedVault()
	if err != nil {
		printCommandError(err)
		return 1
	}

	if err := vault.RemoveCredential(&v, args[0]); err != nil {
		printCommandError(err)
		return 1
	}

	if err := saveVault(v, passphrase); err != nil {
		printCommandError(err)
		return 1
	}

	fmt.Fprintf(stdout, "removed %s\n", args[0])
	return 0
}

func printRemoveUsage() {
	fmt.Fprintln(stderr, `Usage:
  kenv rm <name>`)
}
