package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	vaultDirName              = ".kenv"
	vaultFileName             = "vault.age"
	backupDirName             = "backups"
	latestBackupMarkerName    = "LATEST"
	maxBackupSnapshots        = 10
	backupTimestampLayout     = "20060102T150405.000000000Z0700"
	backupSnapshotPrefix      = "vault-"
	backupSnapshotSuffix      = ".age"
	backupSnapshotPendingExt  = ".pending"
	backupSnapshotKindPre     = "pre"
	backupSnapshotKindPost    = "post"
)

var (
	ErrUnsafePath          = errors.New("unsafe vault path")
	ErrInsecurePermissions = errors.New("insecure permissions")
	ErrUnexpectedType      = errors.New("unexpected file type")
	ErrVaultMissing        = errors.New("vault does not exist")
	ErrBackupMissing       = errors.New("backup does not exist")
)

var backupNow = time.Now

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

func BackupDirPath() (string, error) {
	dir, err := VaultDirPath()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, backupDirName), nil
}

func LatestBackupMarkerPath() (string, error) {
	dir, err := BackupDirPath()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, latestBackupMarkerName), nil
}

type BackupSnapshot struct {
	Name          string
	Path          string
	Kind          string
	CreatedAt     time.Time
	Recommended   bool
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

func validateBackupDir(path string) (PathState, error) {
	return validateVaultDir(path)
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

func validateBackupFile(path string) (PathState, error) {
	return validateVaultFile(path)
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
	backupDir, err := BackupDirPath()
	if err != nil {
		return err
	}
	if err := ensureBackupDir(backupDir); err != nil {
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
	if state == PathValid {
		existingCiphertext, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read current vault ciphertext: %w", err)
		}
		if _, err := writeBackupSnapshot(backupDir, backupSnapshotKindPre, existingCiphertext); err != nil {
			return err
		}
	}
	postSnapshot, err := writePendingBackupSnapshot(backupDir, backupSnapshotKindPost, ciphertext)
	if err != nil {
		return err
	}

	if err := writeVaultFileAtomically(dir, path, ciphertext); err != nil {
		return err
	}
	postSnapshot, err = finalizePendingBackupSnapshot(postSnapshot)
	if err != nil {
		return err
	}
	if err := updateLatestBackupMarker(backupDir, postSnapshot.Name); err != nil {
		return err
	}
	if err := pruneBackupSnapshots(backupDir, maxBackupSnapshots); err != nil {
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

func ensureBackupDir(path string) error {
	state, err := validateBackupDir(path)
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
		return fmt.Errorf("create backup directory: %w", err)
	}

	state, err = validateBackupDir(path)
	if err != nil {
		return err
	}
	if state != PathValid {
		return fmt.Errorf("%w: backup directory %s was not created securely", ErrUnsafePath, path)
	}

	return nil
}

func writeVaultFileAtomically(dir, path string, ciphertext []byte) error {
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

func writeBackupSnapshot(dir, kind string, ciphertext []byte) (BackupSnapshot, error) {
	return writeBackupSnapshotWithSuffix(dir, kind, ciphertext, "")
}

func writePendingBackupSnapshot(dir, kind string, ciphertext []byte) (BackupSnapshot, error) {
	return writeBackupSnapshotWithSuffix(dir, kind, ciphertext, backupSnapshotPendingExt)
}

func writeBackupSnapshotWithSuffix(dir, kind string, ciphertext []byte, suffix string) (BackupSnapshot, error) {
	if kind != backupSnapshotKindPre && kind != backupSnapshotKindPost {
		return BackupSnapshot{}, fmt.Errorf("invalid backup snapshot kind %q", kind)
	}
	timestamp := backupNow().UTC()
	name := fmt.Sprintf("%s%s-%s%s%s", backupSnapshotPrefix, timestamp.Format(backupTimestampLayout), kind, backupSnapshotSuffix, suffix)
	path := filepath.Join(dir, name)
	if err := writeBackupFile(path, ciphertext); err != nil {
		return BackupSnapshot{}, err
	}
	if err := syncDirectory(dir); err != nil {
		return BackupSnapshot{}, err
	}

	return BackupSnapshot{
		Name:      name,
		Path:      path,
		Kind:      kind,
		CreatedAt: timestamp,
	}, nil
}

func finalizePendingBackupSnapshot(snapshot BackupSnapshot) (BackupSnapshot, error) {
	if !strings.HasSuffix(snapshot.Name, backupSnapshotPendingExt) {
		return snapshot, nil
	}
	finalName := strings.TrimSuffix(snapshot.Name, backupSnapshotPendingExt)
	finalPath := filepath.Join(filepath.Dir(snapshot.Path), finalName)
	if err := os.Rename(snapshot.Path, finalPath); err != nil {
		return BackupSnapshot{}, fmt.Errorf("finalize backup snapshot: %w", err)
	}
	if err := syncDirectory(filepath.Dir(snapshot.Path)); err != nil {
		return BackupSnapshot{}, err
	}
	snapshot.Name = finalName
	snapshot.Path = finalPath
	return snapshot, nil
}

func writeBackupFile(path string, ciphertext []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create backup snapshot: %w", err)
	}
	if _, err := file.Write(ciphertext); err != nil {
		_ = file.Close()
		return fmt.Errorf("write backup snapshot: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync backup snapshot: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close backup snapshot: %w", err)
	}

	return nil
}

func updateLatestBackupMarker(dir, snapshotName string) error {
	path := filepath.Join(dir, latestBackupMarkerName)
	tempFile, err := os.CreateTemp(dir, latestBackupMarkerName+".tmp-*")
	if err != nil {
		return fmt.Errorf("create latest backup marker temp file: %w", err)
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
		return fmt.Errorf("set latest backup marker permissions: %w", err)
	}
	if _, err := tempFile.WriteString(snapshotName + "\n"); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("write latest backup marker: %w", err)
	}
	if err := tempFile.Sync(); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("sync latest backup marker: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close latest backup marker: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("rename latest backup marker: %w", err)
	}
	cleanup = false

	if err := syncDirectory(dir); err != nil {
		return err
	}

	return nil
}

func ListBackupSnapshots() ([]BackupSnapshot, error) {
	dir, err := BackupDirPath()
	if err != nil {
		return nil, err
	}
	state, err := validateBackupDir(dir)
	if err != nil {
		return nil, err
	}
	if state == PathMissing {
		return []BackupSnapshot{}, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read backup directory: %w", err)
	}
	latestName, err := readLatestBackupMarker(dir)
	if err != nil && !errors.Is(err, ErrBackupMissing) {
		return nil, err
	}

	snapshots := make([]BackupSnapshot, 0, len(entries))
	for _, entry := range entries {
		if entry.Name() == latestBackupMarkerName || strings.HasSuffix(entry.Name(), backupSnapshotPendingExt) {
			continue
		}
		snapshot, ok, err := parseBackupSnapshot(dir, entry.Name())
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		snapshot.Recommended = snapshot.Kind == backupSnapshotKindPost && snapshot.Name == latestName
		snapshots = append(snapshots, snapshot)
	}

	slices.SortFunc(snapshots, func(a, b BackupSnapshot) int {
		if cmp := b.CreatedAt.Compare(a.CreatedAt); cmp != 0 {
			return cmp
		}
		return strings.Compare(b.Name, a.Name)
	})

	return snapshots, nil
}

func RestoreBackupSnapshot(snapshot BackupSnapshot, passphrase string) error {
	ciphertext, err := os.ReadFile(snapshot.Path)
	if err != nil {
		return fmt.Errorf("read backup snapshot: %w", err)
	}
	if _, err := DecryptVault(ciphertext, passphrase); err != nil {
		return err
	}

	dir, err := VaultDirPath()
	if err != nil {
		return err
	}
	if err := ensureVaultDir(dir); err != nil {
		return err
	}
	backupDir, err := BackupDirPath()
	if err != nil {
		return err
	}
	if err := ensureBackupDir(backupDir); err != nil {
		return err
	}
	livePath := filepath.Join(dir, vaultFileName)
	state, err := validateVaultFile(livePath)
	if err != nil {
		return err
	}
	if state == PathValid {
		liveCiphertext, err := os.ReadFile(livePath)
		if err != nil {
			return fmt.Errorf("read current vault ciphertext: %w", err)
		}
		if _, err := writeBackupSnapshot(backupDir, backupSnapshotKindPre, liveCiphertext); err != nil {
			return err
		}
		if err := pruneBackupSnapshots(backupDir, maxBackupSnapshots); err != nil {
			return err
		}
	}
	if err := writeVaultFileAtomically(dir, livePath, ciphertext); err != nil {
		return err
	}

	return nil
}

func readLatestBackupMarker(dir string) (string, error) {
	path := filepath.Join(dir, latestBackupMarkerName)
	state, err := validateBackupFile(path)
	if err != nil {
		if errors.Is(err, ErrInsecurePermissions) || errors.Is(err, ErrUnexpectedType) || errors.Is(err, ErrUnsafePath) {
			return "", err
		}
	}
	if state == PathMissing {
		return "", ErrBackupMissing
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read latest backup marker: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

func parseBackupSnapshot(dir, name string) (BackupSnapshot, bool, error) {
	if strings.HasSuffix(name, backupSnapshotPendingExt) {
		return BackupSnapshot{}, false, nil
	}
	if !strings.HasPrefix(name, backupSnapshotPrefix) || !strings.HasSuffix(name, backupSnapshotSuffix) {
		return BackupSnapshot{}, false, nil
	}
	body := strings.TrimSuffix(strings.TrimPrefix(name, backupSnapshotPrefix), backupSnapshotSuffix)
	parts := strings.Split(body, "-")
	if len(parts) != 2 {
		return BackupSnapshot{}, false, nil
	}
	if parts[1] != backupSnapshotKindPre && parts[1] != backupSnapshotKindPost {
		return BackupSnapshot{}, false, nil
	}
	createdAt, err := time.Parse(backupTimestampLayout, parts[0])
	if err != nil {
		return BackupSnapshot{}, false, fmt.Errorf("parse backup snapshot timestamp %q: %w", name, err)
	}
	path := filepath.Join(dir, name)
	state, err := validateBackupFile(path)
	if err != nil {
		return BackupSnapshot{}, false, err
	}
	if state != PathValid {
		return BackupSnapshot{}, false, fmt.Errorf("%w: backup snapshot %s is not valid", ErrUnsafePath, path)
	}

	return BackupSnapshot{
		Name:      name,
		Path:      path,
		Kind:      parts[1],
		CreatedAt: createdAt,
	}, true, nil
}

func pruneBackupSnapshots(dir string, keep int) error {
	if keep < 1 {
		return fmt.Errorf("backup retention must be at least 1")
	}
	snapshots, err := ListBackupSnapshots()
	if err != nil {
		return err
	}
	if len(snapshots) <= keep {
		return nil
	}
	for _, snapshot := range snapshots[keep:] {
		if err := os.Remove(snapshot.Path); err != nil {
			return fmt.Errorf("remove old backup snapshot: %w", err)
		}
	}
	if err := syncDirectory(dir); err != nil {
		return err
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
