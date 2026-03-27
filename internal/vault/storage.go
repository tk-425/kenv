package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	vaultDirName  = ".kenv"
	vaultFileName = "vault.age"
)

var (
	ErrUnsafePath          = errors.New("unsafe vault path")
	ErrInsecurePermissions = errors.New("insecure permissions")
	ErrUnexpectedType      = errors.New("unexpected file type")
	ErrVaultMissing        = errors.New("vault does not exist")
)

type PathState int

const (
	PathMissing PathState = iota
	PathValid
	PathUnsafe
)

func VaultDirPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}

	return filepath.Join(home, vaultDirName), nil
}

func VaultFilePath() (string, error) {
	dir, err := VaultDirPath()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, vaultFileName), nil
}

func validateVaultDir(path string) (PathState, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return PathMissing, nil
		}

		return PathUnsafe, fmt.Errorf("stat vault directory: %w", err)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return PathUnsafe, fmt.Errorf("%w: vault directory is a symlink: %s", ErrUnsafePath, path)
	}
	if !info.IsDir() {
		return PathUnsafe, fmt.Errorf("%w: vault directory is not a directory: %s", ErrUnexpectedType, path)
	}
	if hasBroaderPermissions(info.Mode().Perm(), 0o700) {
		return PathUnsafe, fmt.Errorf("%w: vault directory %s must not be broader than 0700", ErrInsecurePermissions, path)
	}

	return PathValid, nil
}

func validateVaultFile(path string) (PathState, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return PathMissing, nil
		}

		return PathUnsafe, fmt.Errorf("stat vault file: %w", err)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return PathUnsafe, fmt.Errorf("%w: vault file is a symlink: %s", ErrUnsafePath, path)
	}
	if !info.Mode().IsRegular() {
		return PathUnsafe, fmt.Errorf("%w: vault file is not a regular file: %s", ErrUnexpectedType, path)
	}
	if hasBroaderPermissions(info.Mode().Perm(), 0o600) {
		return PathUnsafe, fmt.Errorf("%w: vault file %s must not be broader than 0600", ErrInsecurePermissions, path)
	}

	return PathValid, nil
}

func hasBroaderPermissions(actual, allowed os.FileMode) bool {
	return actual&^allowed != 0
}

func LoadCiphertext() ([]byte, error) {
	path, err := VaultFilePath()
	if err != nil {
		return nil, err
	}

	state, err := validateVaultFile(path)
	if err != nil {
		return nil, err
	}
	if state == PathMissing {
		return nil, ErrVaultMissing
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read vault ciphertext: %w", err)
	}

	return data, nil
}

func SaveCiphertext(ciphertext []byte) error {
	dir, err := VaultDirPath()
	if err != nil {
		return err
	}

	if err := ensureVaultDir(dir); err != nil {
		return err
	}

	path := filepath.Join(dir, vaultFileName)
	state, err := validateVaultFile(path)
	if err != nil {
		return err
	}
	if state == PathUnsafe {
		return fmt.Errorf("%w: %s", ErrUnsafePath, path)
	}

	tempFile, err := os.CreateTemp(dir, vaultFileName+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp vault file: %w", err)
	}

	tempPath := tempFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()

	if err := tempFile.Chmod(0o600); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("set temp vault file permissions: %w", err)
	}
	if _, err := tempFile.Write(ciphertext); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("write temp vault file: %w", err)
	}
	if err := tempFile.Sync(); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("sync temp vault file: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close temp vault file: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("rename temp vault file: %w", err)
	}

	cleanup = false

	if err := syncDirectory(dir); err != nil {
		return err
	}

	return nil
}

func ensureVaultDir(path string) error {
	state, err := validateVaultDir(path)
	if err != nil {
		return err
	}
	if state == PathValid {
		return nil
	}
	if state == PathUnsafe {
		return fmt.Errorf("%w: %s", ErrUnsafePath, path)
	}

	if err := os.Mkdir(path, 0o700); err != nil {
		return fmt.Errorf("create vault directory: %w", err)
	}

	state, err = validateVaultDir(path)
	if err != nil {
		return err
	}
	if state != PathValid {
		return fmt.Errorf("%w: vault directory %s was not created securely", ErrUnsafePath, path)
	}

	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open vault directory for sync: %w", err)
	}
	defer dir.Close()

	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync vault directory: %w", err)
	}

	return nil
}
