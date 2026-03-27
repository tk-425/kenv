package vault

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestPromptPassphraseRequiresTTY(t *testing.T) {
	reset := stubPromptEnv(t, false, nil, nil)
	defer reset()

	_, err := PromptPassphrase("Vault passphrase: ")
	if !errors.Is(err, ErrPromptRequiresTTY) {
		t.Fatalf("PromptPassphrase() error = %v, want ErrPromptRequiresTTY", err)
	}
}

func TestPromptSecretRequiresTTY(t *testing.T) {
	reset := stubPromptEnv(t, false, nil, nil)
	defer reset()

	_, err := PromptSecret("Secret: ")
	if !errors.Is(err, ErrPromptRequiresTTY) {
		t.Fatalf("PromptSecret() error = %v, want ErrPromptRequiresTTY", err)
	}
}

func TestPromptPassphraseTwiceReturnsMismatch(t *testing.T) {
	var output bytes.Buffer
	passwords := [][]byte{[]byte("first"), []byte("second")}

	reset := stubPromptEnv(t, true, &output, func(fd int) ([]byte, error) {
		next := passwords[0]
		passwords = passwords[1:]
		return next, nil
	})
	defer reset()

	_, err := PromptPassphraseTwice("Vault passphrase: ", "Confirm passphrase: ")
	if !errors.Is(err, ErrPassphraseMismatch) {
		t.Fatalf("PromptPassphraseTwice() error = %v, want ErrPassphraseMismatch", err)
	}

	if got, want := output.String(), "Vault passphrase: \nConfirm passphrase: \n"; got != want {
		t.Fatalf("prompt output = %q, want %q", got, want)
	}
}

func TestPromptPassphraseTwiceReturnsPassphraseWhenConfirmed(t *testing.T) {
	var output bytes.Buffer
	passwords := [][]byte{[]byte("matched"), []byte("matched")}

	reset := stubPromptEnv(t, true, &output, func(fd int) ([]byte, error) {
		next := passwords[0]
		passwords = passwords[1:]
		return next, nil
	})
	defer reset()

	got, err := PromptPassphraseTwice("Vault passphrase: ", "Confirm passphrase: ")
	if err != nil {
		t.Fatalf("PromptPassphraseTwice() error = %v", err)
	}
	if got != "matched" {
		t.Fatalf("PromptPassphraseTwice() = %q, want %q", got, "matched")
	}
	if gotOutput, want := output.String(), "Vault passphrase: \nConfirm passphrase: \n"; gotOutput != want {
		t.Fatalf("prompt output = %q, want %q", gotOutput, want)
	}
}

func TestPromptSecretUsesHiddenInputWithoutLeakingValue(t *testing.T) {
	var output bytes.Buffer

	reset := stubPromptEnv(t, true, &output, func(fd int) ([]byte, error) {
		return []byte("sk-test-secret"), nil
	})
	defer reset()

	got, err := PromptSecret("Secret: ")
	if err != nil {
		t.Fatalf("PromptSecret() error = %v", err)
	}
	if got != "sk-test-secret" {
		t.Fatalf("PromptSecret() = %q, want %q", got, "sk-test-secret")
	}
	if gotOutput, want := output.String(), "Secret: \n"; gotOutput != want {
		t.Fatalf("prompt output = %q, want %q", gotOutput, want)
	}
	if bytes.Contains(output.Bytes(), []byte(got)) {
		t.Fatalf("prompt output unexpectedly contains secret value: %q", output.String())
	}
}

func stubPromptEnv(t *testing.T, tty bool, output io.Writer, passwordReader func(fd int) ([]byte, error)) func() {
	t.Helper()

	originalOutput := promptOutput
	originalIsTerminal := isTerminal
	originalReadPassword := readPassword

	promptOutput = io.Discard
	if output != nil {
		promptOutput = output
	}
	isTerminal = func(fd int) bool {
		return tty
	}
	readPassword = func(fd int) ([]byte, error) {
		if passwordReader == nil {
			return nil, errors.New("unexpected readPassword call")
		}
		return passwordReader(fd)
	}

	return func() {
		promptOutput = originalOutput
		isTerminal = originalIsTerminal
		readPassword = originalReadPassword
	}
}
