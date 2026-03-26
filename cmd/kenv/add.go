package main

import (
	"fmt"
	"os"
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

	printNotImplemented("add")
	return 1
}

func printAddUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  kenv add <name>`)
}
