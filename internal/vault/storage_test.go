package vault

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
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

func TestSaveCiphertextCreatesPostBackupOnFirstWrite(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	reset := stubBackupNow(t, time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC))
	defer reset()

	if err := SaveCiphertext([]byte("ciphertext")); err != nil {
		t.Fatalf("SaveCiphertext() error = %v", err)
	}

	snapshots, err := ListBackupSnapshots()
	if err != nil {
		t.Fatalf("ListBackupSnapshots() error = %v", err)
	}
	if len(snapshots) != 1 {
		t.Fatalf("len(snapshots) = %d, want 1", len(snapshots))
	}
	if snapshots[0].Kind != backupSnapshotKindPost {
		t.Fatalf("snapshot kind = %q, want %q", snapshots[0].Kind, backupSnapshotKindPost)
	}
	if !snapshots[0].Recommended {
		t.Fatalf("snapshot.Recommended = false, want true")
	}

	markerPath, err := LatestBackupMarkerPath()
	if err != nil {
		t.Fatalf("LatestBackupMarkerPath() error = %v", err)
	}
	marker, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", markerPath, err)
	}
	if got := string(marker); got != snapshots[0].Name+"\n" {
		t.Fatalf("marker = %q, want %q", got, snapshots[0].Name+"\n")
	}
}

func TestSaveCiphertextCreatesPreAndPostBackupsOnOverwrite(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	reset := stubBackupNowSequence(t,
		time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 3, 28, 12, 1, 0, 0, time.UTC),
		time.Date(2026, 3, 28, 12, 2, 0, 0, time.UTC),
	)
	defer reset()

	if err := SaveCiphertext([]byte("first")); err != nil {
		t.Fatalf("SaveCiphertext(first) error = %v", err)
	}
	if err := SaveCiphertext([]byte("second")); err != nil {
		t.Fatalf("SaveCiphertext(second) error = %v", err)
	}

	snapshots, err := ListBackupSnapshots()
	if err != nil {
		t.Fatalf("ListBackupSnapshots() error = %v", err)
	}
	if len(snapshots) != 3 {
		t.Fatalf("len(snapshots) = %d, want 3", len(snapshots))
	}

	kinds := []string{snapshots[0].Kind, snapshots[1].Kind, snapshots[2].Kind}
	slices.Sort(kinds)
	if got, want := kinds, []string{backupSnapshotKindPost, backupSnapshotKindPost, backupSnapshotKindPre}; !slices.Equal(got, want) {
		t.Fatalf("snapshot kinds = %#v, want %#v", got, want)
	}
	if !snapshots[0].Recommended {
		t.Fatalf("newest snapshot should be recommended")
	}
	if snapshots[0].Kind != backupSnapshotKindPost {
		t.Fatalf("recommended snapshot kind = %q, want %q", snapshots[0].Kind, backupSnapshotKindPost)
	}
}

func TestSaveCiphertextPrunesOldBackups(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	times := make([]time.Time, 0, 32)
	base := time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 32; i++ {
		times = append(times, base.Add(time.Duration(i)*time.Minute))
	}
	reset := stubBackupNowSequence(t, times...)
	defer reset()

	for i := 0; i < 12; i++ {
		if err := SaveCiphertext([]byte{byte('a' + i)}); err != nil {
			t.Fatalf("SaveCiphertext(%d) error = %v", i, err)
		}
	}

	snapshots, err := ListBackupSnapshots()
	if err != nil {
		t.Fatalf("ListBackupSnapshots() error = %v", err)
	}
	if len(snapshots) != maxBackupSnapshots {
		t.Fatalf("len(snapshots) = %d, want %d", len(snapshots), maxBackupSnapshots)
	}
	oldestExpected := base.Add(13 * time.Minute)
	newestExpected := base.Add(22 * time.Minute)
	for _, snapshot := range snapshots {
		if snapshot.CreatedAt.Before(oldestExpected) || snapshot.CreatedAt.After(newestExpected) {
			t.Fatalf("snapshot %q has timestamp %v, want retained timestamps in [%v, %v]", snapshot.Name, snapshot.CreatedAt, oldestExpected, newestExpected)
		}
	}
}

func TestSaveCiphertextFailsWhenBackupDirIsInsecure(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if err := os.Mkdir(filepath.Join(home, ".kenv"), 0o700); err != nil {
		t.Fatalf("Mkdir(.kenv) error = %v", err)
	}
	if err := os.Mkdir(filepath.Join(home, ".kenv", "backups"), 0o755); err != nil {
		t.Fatalf("Mkdir(backups) error = %v", err)
	}

	err := SaveCiphertext([]byte("ciphertext"))
	if !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("SaveCiphertext() error = %v, want ErrInsecurePermissions", err)
	}
}

func TestRestoreBackupSnapshotWorksWithoutLiveVault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	reset := stubBackupNowSequence(t,
		time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 3, 28, 12, 1, 0, 0, time.UTC),
		time.Date(2026, 3, 28, 12, 2, 0, 0, time.UTC),
	)
	defer reset()

	firstCiphertext, err := EncryptVault(Vault{Version: CurrentVersion, Credentials: []Credential{}}, "passphrase")
	if err != nil {
		t.Fatalf("EncryptVault(first) error = %v", err)
	}
	secondCiphertext, err := EncryptVault(Vault{
		Version: CurrentVersion,
		Credentials: []Credential{{ScopeID: "scope", ScopeLabel: "scope", ScopePath: "/tmp/project", EnvKey: "OPENAI_API_KEY", Placeholder: "kvn_aaaaaaaaaaaaaaaaaaaa", Secret: "sk-secret"}},
	}, "passphrase")
	if err != nil {
		t.Fatalf("EncryptVault(second) error = %v", err)
	}
	if err := SaveCiphertext(firstCiphertext); err != nil {
		t.Fatalf("SaveCiphertext(first) error = %v", err)
	}
	if err := SaveCiphertext(secondCiphertext); err != nil {
		t.Fatalf("SaveCiphertext(second) error = %v", err)
	}

	snapshots, err := ListBackupSnapshots()
	if err != nil {
		t.Fatalf("ListBackupSnapshots() error = %v", err)
	}
	var target BackupSnapshot
	for _, snapshot := range snapshots {
		if snapshot.Kind == backupSnapshotKindPost && !snapshot.Recommended {
			target = snapshot
			break
		}
	}
	if target.Name == "" {
		t.Fatal("expected older post snapshot")
	}

	livePath, err := VaultFilePath()
	if err != nil {
		t.Fatalf("VaultFilePath() error = %v", err)
	}
	if err := os.Remove(livePath); err != nil {
		t.Fatalf("Remove(%q) error = %v", livePath, err)
	}

	if err := RestoreBackupSnapshot(target, "passphrase"); err != nil {
		t.Fatalf("RestoreBackupSnapshot() error = %v", err)
	}
	got, err := LoadCiphertext()
	if err != nil {
		t.Fatalf("LoadCiphertext() error = %v", err)
	}
	if string(got) != string(firstCiphertext) {
		t.Fatalf("restored ciphertext mismatch")
	}
}

func TestRestoreBackupSnapshotRejectsInvalidSnapshot(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	reset := stubBackupNow(t, time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC))
	defer reset()

	if err := SaveCiphertext([]byte("ciphertext")); err != nil {
		t.Fatalf("SaveCiphertext() error = %v", err)
	}
	snapshots, err := ListBackupSnapshots()
	if err != nil {
		t.Fatalf("ListBackupSnapshots() error = %v", err)
	}
	if err := os.WriteFile(snapshots[0].Path, []byte("corrupted"), 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", snapshots[0].Path, err)
	}

	if err := RestoreBackupSnapshot(snapshots[0], "passphrase"); err == nil {
		t.Fatal("RestoreBackupSnapshot() error = nil, want error")
	}
}

func TestRestoreBackupSnapshotCreatesEmergencySnapshotWhenLiveVaultExists(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	reset := stubBackupNowSequence(t,
		time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 3, 28, 12, 1, 0, 0, time.UTC),
		time.Date(2026, 3, 28, 12, 2, 0, 0, time.UTC),
		time.Date(2026, 3, 28, 12, 3, 0, 0, time.UTC),
	)
	defer reset()

	firstCiphertext, err := EncryptVault(Vault{Version: CurrentVersion, Credentials: []Credential{}}, "passphrase")
	if err != nil {
		t.Fatalf("EncryptVault(first) error = %v", err)
	}
	secondCiphertext, err := EncryptVault(Vault{
		Version: CurrentVersion,
		Credentials: []Credential{{ScopeID: "scope", ScopeLabel: "scope", ScopePath: "/tmp/project", EnvKey: "OPENAI_API_KEY", Placeholder: "kvn_aaaaaaaaaaaaaaaaaaaa", Secret: "sk-secret"}},
	}, "passphrase")
	if err != nil {
		t.Fatalf("EncryptVault(second) error = %v", err)
	}
	if err := SaveCiphertext(firstCiphertext); err != nil {
		t.Fatalf("SaveCiphertext(first) error = %v", err)
	}
	if err := SaveCiphertext(secondCiphertext); err != nil {
		t.Fatalf("SaveCiphertext(second) error = %v", err)
	}

	snapshots, err := ListBackupSnapshots()
	if err != nil {
		t.Fatalf("ListBackupSnapshots() error = %v", err)
	}
	before := len(snapshots)
	target := snapshots[len(snapshots)-1]

	if err := RestoreBackupSnapshot(target, "passphrase"); err != nil {
		t.Fatalf("RestoreBackupSnapshot() error = %v", err)
	}
	afterSnapshots, err := ListBackupSnapshots()
	if err != nil {
		t.Fatalf("ListBackupSnapshots() error = %v", err)
	}
	if len(afterSnapshots) <= before {
		t.Fatalf("len(afterSnapshots) = %d, want > %d", len(afterSnapshots), before)
	}
}

func stubBackupNow(t *testing.T, now time.Time) func() {
	t.Helper()
	original := backupNow
	backupNow = func() time.Time { return now }
	return func() { backupNow = original }
}

func stubBackupNowSequence(t *testing.T, times ...time.Time) func() {
	t.Helper()
	original := backupNow
	index := 0
	backupNow = func() time.Time {
		if index >= len(times) {
			return times[len(times)-1]
		}
		current := times[index]
		index++
		return current
	}
	return func() { backupNow = original }
}
