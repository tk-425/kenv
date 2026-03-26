package main

import (
	"fmt"
	"os"
)

func runInit(args []string) int {
	if wantsHelp(args) {
		printInitUsage()
		return 0
	}
	if len(args) != 0 {
		printInitUsage()
		return 2
	}

	printNotImplemented("init")
	return 1
}

func printInitUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  kenv init`)
}
