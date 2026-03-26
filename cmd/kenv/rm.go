package main

import (
	"fmt"
	"os"
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

	printNotImplemented("rm")
	return 1
}

func printRemoveUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  kenv rm <name>`)
}
