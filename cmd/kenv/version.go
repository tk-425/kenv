package main

import (
	"fmt"
	"os"
)

var version = "dev"

func runVersion(args []string) int {
	if wantsHelp(args) {
		printVersionUsage()
		return 0
	}
	if len(args) != 0 {
		printVersionUsage()
		return 2
	}

	fmt.Fprintln(os.Stdout, version)
	return 0
}

func printVersionUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  kenv version`)
}
