package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestVaultPathsUseHomeDirectory(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	dir, err := VaultDirPath()
	if err != nil {
		t.Fatalf("VaultDirPath() error = %v", err)
	}

	file, err := VaultFilePath()
	if err != nil {
		t.Fatalf("VaultFilePath() error = %v", err)
	}

	expectedDir := filepath.Join(os.Getenv("HOME"), ".kenv")
	expectedFile := filepath.Join(expectedDir, "vault.age")

	if dir != expectedDir {
		t.Fatalf("VaultDirPath() = %q, want %q", dir, expectedDir)
	}
	if file != expectedFile {
		t.Fatalf("VaultFilePath() = %q, want %q", file, expectedFile)
	}
}

func TestLoadCiphertextReturnsMissingWhenVaultDoesNotExist(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	_, err := LoadCiphertext()
	if !errors.Is(err, ErrVaultMissing) {
		t.Fatalf("LoadCiphertext() error = %v, want ErrVaultMissing", err)
	}
}

func TestSaveCiphertextCreatesSecureVaultArtifacts(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	ciphertext := []byte("ciphertext-data")
	if err := SaveCiphertext(ciphertext); err != nil {
		t.Fatalf("SaveCiphertext() error = %v", err)
	}

	dir, err := VaultDirPath()
	if err != nil {
		t.Fatalf("VaultDirPath() error = %v", err)
	}
	file, err := VaultFilePath()
	if err != nil {
		t.Fatalf("VaultFilePath() error = %v", err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", dir, err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("vault dir mode = %o, want 0700", got)
	}

	fileInfo, err := os.Stat(file)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", file, err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("vault file mode = %o, want 0600", got)
	}

	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", file, err)
	}
	if string(got) != string(ciphertext) {
		t.Fatalf("vault contents = %q, want %q", got, ciphertext)
	}
}

func TestSaveCiphertextOverwritesExistingVaultAtomically(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := SaveCiphertext([]byte("first")); err != nil {
		t.Fatalf("SaveCiphertext(first) error = %v", err)
	}
	if err := SaveCiphertext([]byte("second")); err != nil {
		t.Fatalf("SaveCiphertext(second) error = %v", err)
	}

	got, err := LoadCiphertext()
	if err != nil {
		t.Fatalf("LoadCiphertext() error = %v", err)
	}
	if string(got) != "second" {
		t.Fatalf("LoadCiphertext() = %q, want %q", got, "second")
	}
}

func TestSaveCiphertextRejectsSymlinkedVaultDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	target := filepath.Join(home, "real-dir")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir(%q) error = %v", target, err)
	}

	link := filepath.Join(home, ".kenv")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink(%q, %q) error = %v", target, link, err)
	}

	err := SaveCiphertext([]byte("ciphertext"))
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("SaveCiphertext() error = %v, want ErrUnsafePath", err)
	}
}

func TestSaveCiphertextRejectsInsecureVaultDirectoryPermissions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".kenv")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("Mkdir(%q) error = %v", dir, err)
	}

	err := SaveCiphertext([]byte("ciphertext"))
	if !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("SaveCiphertext() error = %v, want ErrInsecurePermissions", err)
	}
}

func TestLoadCiphertextRejectsSymlinkedVaultFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".kenv")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir(%q) error = %v", dir, err)
	}

	target := filepath.Join(home, "ciphertext.age")
	if err := os.WriteFile(target, []byte("ciphertext"), 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", target, err)
	}

	link := filepath.Join(dir, "vault.age")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink(%q, %q) error = %v", target, link, err)
	}

	_, err := LoadCiphertext()
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("LoadCiphertext() error = %v, want ErrUnsafePath", err)
	}
}

func TestLoadCiphertextRejectsInsecureVaultFilePermissions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".kenv")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir(%q) error = %v", dir, err)
	}

	file := filepath.Join(dir, "vault.age")
	if err := os.WriteFile(file, []byte("ciphertext"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", file, err)
	}

	_, err := LoadCiphertext()
	if !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("LoadCiphertext() error = %v, want ErrInsecurePermissions", err)
	}
}
