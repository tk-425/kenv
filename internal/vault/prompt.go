package vault

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

var (
	ErrPromptRequiresTTY  = errors.New("interactive terminal required for passphrase prompt")
	ErrPassphraseMismatch = errors.New("passphrase confirmation does not match")
)

var (
	promptInput            = os.Stdin
	promptOutput io.Writer = os.Stderr
	isTerminal             = term.IsTerminal
	readPassword           = term.ReadPassword
)

func PromptPassphrase(prompt string) (string, error) {
	return readHiddenInput(prompt)
}

func PromptPassphraseTwice(prompt, confirmPrompt string) (string, error) {
	first, err := readHiddenInput(prompt)
	if err != nil {
		return "", err
	}

	second, err := readHiddenInput(confirmPrompt)
	if err != nil {
		return "", err
	}
	if first != second {
		return "", ErrPassphraseMismatch
	}

	return first, nil
}

func PromptSecret(prompt string) (string, error) {
	return readHiddenInput(prompt)
}

func readHiddenInput(prompt string) (string, error) {
	fd := int(promptInput.Fd())
	if !isTerminal(fd) {
		return "", ErrPromptRequiresTTY
	}

	if _, err := fmt.Fprint(promptOutput, prompt); err != nil {
		return "", fmt.Errorf("write prompt: %w", err)
	}

	valueBytes, err := readPassword(fd)
	if _, newlineErr := fmt.Fprintln(promptOutput); newlineErr != nil && err == nil {
		return "", fmt.Errorf("write prompt newline: %w", newlineErr)
	}
	if err != nil {
		return "", fmt.Errorf("read hidden input: %w", err)
	}

	return string(valueBytes), nil
}
