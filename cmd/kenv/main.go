package main

import (
	"fmt"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		printTopLevelUsage()
		return 2
	}

	switch args[0] {
	case "init":
		return runInit(args[1:])
	case "add":
		return runAdd(args[1:])
	case "list":
		return runList(args[1:])
	case "show":
		return runShow(args[1:])
	case "rm":
		return runRemove(args[1:])
	case "run":
		return runCmd(args[1:])
	case "scope":
		return runScope(args[1:])
	case "backup":
		return runBackup(args[1:])
	case "version":
		return runVersion(args[1:])
	case "help", "-h", "--help":
		printTopLevelUsage()
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n\n", args[0])
		printTopLevelUsage()
		return 2
	}
}

func printTopLevelUsage() {
	fmt.Fprintf(stderr, `kenv stores secrets in a local encrypted vault and resolves placeholders at runtime.

Usage:
  kenv <command> [arguments]

	Commands:
	  init          Initialize the local vault
	  add           Add a secret and return its placeholder
	  list          List scoped secret placeholders
	  show          Show the placeholder for a scoped secret
	  rm            Remove a scoped secret from the vault
	  run           Resolve placeholders from an env file and run a command
	  scope         Manage project scope operations
	  backup        Restore an automatically created vault backup
	  version       Print the kenv version

Help:
  kenv help
  kenv <command> --help
`)
}

func printNotImplemented(command string) {
	fmt.Fprintf(stderr, "kenv %s is not implemented yet\n", command)
}
