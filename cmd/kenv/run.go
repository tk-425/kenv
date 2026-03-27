package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/tk-425/kenv/internal/envfile"
	"github.com/tk-425/kenv/internal/vault"
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

	options := parseRunOptions(args)

	parsed, err := envfile.ParseFile(options.envPath)
	if err != nil {
		printCommandError(err)
		return 1
	}

	for _, warning := range parsed.Warnings {
		fmt.Fprintln(stderr, warning.Message)
	}

	resolved := map[string]string{}
	if len(parsed.PlaceholderCandidates) > 0 {
		unlocked, _, err := loadUnlockedVault()
		if err != nil {
			printCommandError(err)
			return 1
		}

		resolved, err = vault.ResolvePlaceholders(unlocked, collectPlaceholderTokens(parsed.PlaceholderCandidates))
		if err != nil {
			printCommandError(err)
			return 1
		}
	}

	env := buildChildEnv(options.inheritEnv, parsed, resolved)
	code, err := runChildProcess(options.command, env)
	if err != nil {
		printCommandError(err)
		return 1
	}

	return code
}

type runOptions struct {
	inheritEnv bool
	envPath    string
	command    []string
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

func parseRunOptions(args []string) runOptions {
	index := 0
	inheritEnv := false
	if args[index] == "--inherit-env" {
		inheritEnv = true
		index++
	}

	return runOptions{
		inheritEnv: inheritEnv,
		envPath:    args[index+1],
		command:    append([]string(nil), args[index+3:]...),
	}
}

func collectPlaceholderTokens(entries []envfile.Entry) []string {
	placeholders := make([]string, 0, len(entries))
	for _, entry := range entries {
		placeholders = append(placeholders, entry.Value)
	}

	return placeholders
}

func buildChildEnv(inheritEnv bool, parsed envfile.File, resolved map[string]string) []string {
	builder := newEnvBuilder()
	if inheritEnv {
		builder.load(parentEnviron())
	} else {
		builder.load(defaultBaselineEnv())
	}

	for _, entry := range parsed.Entries {
		builder.set(entry.Key, entry.Value)
	}
	for _, entry := range parsed.PlaceholderCandidates {
		secret, ok := resolved[entry.Value]
		if !ok {
			continue
		}
		builder.set(entry.Key, secret)
	}

	return builder.list()
}

func defaultBaselineEnv() []string {
	const baselineKeys = "HOME PATH TMPDIR TEMP TMP USER USERPROFILE HOMEDRIVE HOMEPATH"

	allowed := make(map[string]struct{})
	for _, key := range strings.Fields(baselineKeys) {
		allowed[key] = struct{}{}
	}

	baseline := make([]string, 0)
	for _, entry := range parentEnviron() {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if _, keep := allowed[key]; !keep {
			continue
		}
		baseline = append(baseline, entry)
	}

	return baseline
}

type envBuilder struct {
	order  []string
	values map[string]string
}

func newEnvBuilder() *envBuilder {
	return &envBuilder{
		order:  []string{},
		values: make(map[string]string),
	}
}

func (b *envBuilder) load(entries []string) {
	for _, entry := range entries {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		b.set(key, value)
	}
}

func (b *envBuilder) set(key, value string) {
	if _, exists := b.values[key]; !exists {
		b.order = append(b.order, key)
	}
	b.values[key] = value
}

func (b *envBuilder) list() []string {
	env := make([]string, 0, len(b.order))
	for _, key := range b.order {
		env = append(env, key+"="+b.values[key])
	}

	return env
}

func printRunUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  kenv run [--inherit-env] --env <file> -- <command...>`)
}
