package main

import (
	"fmt"

	"github.com/tk-425/kenv/internal/vault"
)

func runScope(args []string) int {
	if wantsHelp(args) || len(args) == 0 {
		printScopeUsage()
		if wantsHelp(args) {
			return 0
		}
		return 2
	}

	switch args[0] {
	case "migrate":
		return runScopeMigrate(args[1:])
	default:
		printScopeUsage()
		return 2
	}
}

func runScopeMigrate(args []string) int {
	if wantsHelp(args) {
		printScopeMigrateUsage()
		return 0
	}
	if len(args) != 0 {
		printScopeMigrateUsage()
		return 2
	}

	v, passphrase, err := loadUnlockedVault()
	if err != nil {
		printCommandError(err)
		return 1
	}

	scope, err := detectCurrentScope()
	if err != nil {
		printCommandError(err)
		return 1
	}
	if !scope.GitBacked {
		printCommandError(fmt.Errorf("`kenv scope migrate` requires a git-backed project scope"))
		return 1
	}

	credentials, err := vault.FindLocalScopeCredentialsByPath(v, scope.Path)
	if err != nil {
		printCommandError(err)
		return 1
	}
	if len(credentials) == 0 {
		fmt.Fprintln(stdout, "nothing to migrate")
		return 0
	}

	confirmed, err := confirmScopeMigration(scope, credentials)
	if err != nil {
		printCommandError(err)
		return 1
	}
	if !confirmed {
		fmt.Fprintln(stdout, "migration canceled")
		return 1
	}

	if err := vault.MigrateLocalScopeToGitScope(&v, scope); err != nil {
		printCommandError(err)
		return 1
	}

	if err := saveVault(v, passphrase); err != nil {
		printCommandError(err)
		return 1
	}

	fmt.Fprintf(stdout, "migrated %d credential(s) into %s\n", len(credentials), scope.ID)
	return 0
}

func printScopeUsage() {
	fmt.Fprintln(stderr, `Usage:
  kenv scope <subcommand>

Subcommands:
  migrate       Migrate local scope credentials into the current git-backed scope`)
}

func printScopeMigrateUsage() {
	fmt.Fprintln(stderr, `Usage:
  kenv scope migrate`)
}
