package main

import (
	"fmt"
	"os"
)

func runCmd(args []string) int {
	if wantsHelp(args) {
		printRunUsage()
		return 0
	}
	if !hasRunShape(args) {
		printRunUsage()
		return 2
	}

	printNotImplemented("run")
	return 1
}

func hasRunShape(args []string) bool {
	if len(args) < 4 {
		return false
	}

	index := 0
	if args[index] == "--inherit-env" {
		index++
		if len(args[index:]) < 4 {
			return false
		}
	}

	if args[index] != "--env" {
		return false
	}
	if args[index+1] == "" {
		return false
	}
	if args[index+2] != "--" {
		return false
	}

	return len(args[index+3:]) > 0
}

func printRunUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  kenv run [--inherit-env] --env <file> -- <command...>`)
}
