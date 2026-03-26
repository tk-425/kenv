package main

import (
	"fmt"
	"os"
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

	printNotImplemented("list")
	return 1
}

func printListUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  kenv list`)
}
