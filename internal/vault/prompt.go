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
	fd, err := promptInputFD()
	if err != nil {
		return "", err
	}
	if !isTerminal(fd) {
		return "", ErrPromptRequiresTTY
	}

	if _, err := fmt.Fprint(promptOutput, prompt); err != nil {
		return "", fmt.Errorf("write prompt: %w", err)
	}

	valueBytes, err := readPassword(fd)
	_, newlineErr := fmt.Fprintln(promptOutput)
	if err != nil {
		return "", fmt.Errorf("read hidden input: %w", err)
	}
	if newlineErr != nil {
		return "", fmt.Errorf("write prompt newline: %w", newlineErr)
	}

	return string(valueBytes), nil
}

func promptInputFD() (fd int, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			fd = 0
			err = ErrPromptRequiresTTY
		}
	}()

	return int(promptInput.Fd()), nil
}
