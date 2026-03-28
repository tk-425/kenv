package main

import (
	"fmt"

	"github.com/tk-425/kenv/internal/vault"
)

func runBackup(args []string) int {
	if len(args) == 0 {
		printBackupUsage()
		return 2
	}

	switch args[0] {
	case "-h", "--help":
		printBackupUsage()
		return 0
	case "restore":
		return runBackupRestore(args[1:])
	default:
		printBackupUsage()
		return 2
	}
}

func runBackupRestore(args []string) int {
	if wantsHelp(args) {
		printBackupRestoreUsage()
		return 0
	}
	if len(args) != 0 {
		printBackupRestoreUsage()
		return 2
	}

	snapshots, err := vault.ListBackupSnapshots()
	if err != nil {
		printCommandError(err)
		return 1
	}
	if len(snapshots) == 0 {
		printCommandError(fmt.Errorf("no backups available"))
		return 1
	}

	selected, err := promptBackupSelection(snapshots)
	if err != nil {
		printCommandError(err)
		return 1
	}
	passphrase, err := promptPassphrase("Vault passphrase: ")
	if err != nil {
		printCommandError(err)
		return 1
	}
	if err := vault.RestoreBackupSnapshot(selected, passphrase); err != nil {
		printCommandError(err)
		return 1
	}

	fmt.Fprintf(stdout, "restored %s\n", selected.Name)
	return 0
}

func printBackupUsage() {
	fmt.Fprintln(stderr, `Usage:
  kenv backup <subcommand>

Subcommands:
  restore       Restore an automatically created vault backup`)
}

func printBackupRestoreUsage() {
	fmt.Fprintln(stderr, `Usage:
  kenv backup restore`)
}
