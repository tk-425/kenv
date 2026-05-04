package main

import "fmt"

func runPassphrase(args []string) int {
	if wantsHelp(args) {
		printPassphraseUsage()
		return 0
	}
	if len(args) != 0 {
		printPassphraseUsage()
		return 2
	}

	v, _, err := loadUnlockedVault()
	if err != nil {
		printCommandError(err)
		return 1
	}

	newPassphrase, err := promptPassphraseTwice("New passphrase: ", "Confirm new passphrase: ")
	if err != nil {
		printCommandError(err)
		return 1
	}

	if err := saveVault(v, newPassphrase); err != nil {
		printCommandError(err)
		return 1
	}

	fmt.Fprintln(stdout, "passphrase updated")
	return 0
}

func printPassphraseUsage() {
	fmt.Fprintln(stderr, `Usage:
  kenv passwd`)
}
