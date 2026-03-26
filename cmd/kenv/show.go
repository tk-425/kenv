package main

import (
	"fmt"
	"os"
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

	printNotImplemented("show")
	return 1
}

func printShowUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  kenv show <name>`)
}
