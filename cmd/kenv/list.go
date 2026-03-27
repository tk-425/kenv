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

	for _, credential := range vault.ListCredentials(v) {
		fmt.Fprintf(stdout, "%s\t%s\n", credential.Name, credential.Placeholder)
	}

	return 0
}

func printListUsage() {
	fmt.Fprintln(stderr, `Usage:
  kenv list`)
}
