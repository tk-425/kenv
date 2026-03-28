package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"filippo.io/age"
)

var (
	ErrUnlockFailed            = errors.New("vault unlock failed")
	ErrInvalidVaultData        = errors.New("invalid vault data")
	ErrUnsupportedVaultVersion = errors.New("unsupported vault version")
)

var placeholderPattern = regexp.MustCompile(`^kvn_[a-z0-9]{20}$`)

func IsPlaceholder(value string) bool {
	return placeholderPattern.MatchString(value)
}

func EncryptVault(v Vault, passphrase string) ([]byte, error) {
	plaintext, err := marshalVault(v)
	if err != nil {
		return nil, err
	}

	recipient, err := newScryptRecipient(passphrase)
	if err != nil {
		return nil, fmt.Errorf("create scrypt recipient: %w", err)
	}

	ciphertext, err := encryptWithRecipient(plaintext, recipient)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

func DecryptVault(ciphertext []byte, passphrase string) (Vault, error) {
	identity, err := newScryptIdentity(passphrase)
	if err != nil {
		return Vault{}, fmt.Errorf("create scrypt identity: %w", err)
	}

	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return Vault{}, ErrUnlockFailed
		}

		return Vault{}, fmt.Errorf("decrypt vault: %w", err)
	}

	plaintext, err := io.ReadAll(reader)
	if err != nil {
		return Vault{}, fmt.Errorf("read decrypted vault: %w", err)
	}

	v, err := unmarshalVault(plaintext)
	if err != nil {
		return Vault{}, err
	}

	return v, nil
}

func newScryptRecipient(passphrase string) (*age.ScryptRecipient, error) {
	return age.NewScryptRecipient(passphrase)
}

func newScryptIdentity(passphrase string) (*age.ScryptIdentity, error) {
	return age.NewScryptIdentity(passphrase)
}

func encryptWithRecipient(plaintext []byte, recipient age.Recipient) ([]byte, error) {
	var ciphertext bytes.Buffer

	writer, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		return nil, fmt.Errorf("encrypt vault: %w", err)
	}

	if _, err := io.Copy(writer, bytes.NewReader(plaintext)); err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("write plaintext to encryptor: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("finalize encrypted vault: %w", err)
	}

	return ciphertext.Bytes(), nil
}

func marshalVault(v Vault) ([]byte, error) {
	if err := validateVault(&v); err != nil {
		return nil, err
	}

	plaintext, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal vault: %w", err)
	}

	return plaintext, nil
}

func unmarshalVault(plaintext []byte) (Vault, error) {
	var v Vault
	if err := json.Unmarshal(plaintext, &v); err != nil {
		return Vault{}, fmt.Errorf("%w: decode vault JSON: %v", ErrInvalidVaultData, err)
	}

	if err := validateVault(&v); err != nil {
		return Vault{}, err
	}

	return v, nil
}

func validateVault(v *Vault) error {
	if v.Version != CurrentVersion {
		return fmt.Errorf("%w: got version %d", ErrUnsupportedVaultVersion, v.Version)
	}

	if v.Credentials == nil {
		v.Credentials = []Credential{}
	}

	scopedKeys := make(map[string]struct{}, len(v.Credentials))
	placeholders := make(map[string]struct{}, len(v.Credentials))
	for i := range v.Credentials {
		scopeID, err := normalizeCredentialName(v.Credentials[i].ScopeID)
		if err != nil {
			return fmt.Errorf("%w: empty credential scope_id", ErrInvalidVaultData)
		}
		scopeLabel, err := normalizeCredentialName(v.Credentials[i].ScopeLabel)
		if err != nil {
			return fmt.Errorf("%w: empty credential scope_label", ErrInvalidVaultData)
		}
		scopePath, err := normalizeCredentialName(v.Credentials[i].ScopePath)
		if err != nil {
			return fmt.Errorf("%w: empty credential scope_path", ErrInvalidVaultData)
		}
		envKey, err := normalizeCredentialName(v.Credentials[i].EnvKey)
		if err != nil {
			return fmt.Errorf("%w: empty credential env_key", ErrInvalidVaultData)
		}
		if _, err := normalizeCredentialName(v.Credentials[i].Placeholder); err != nil {
			return fmt.Errorf("%w: empty credential placeholder", ErrInvalidVaultData)
		}
		rawPlaceholder := v.Credentials[i].Placeholder
		if !placeholderPattern.MatchString(rawPlaceholder) {
			return fmt.Errorf("%w: invalid placeholder %q", ErrInvalidVaultData, rawPlaceholder)
		}

		scopedKey := scopeID + "\x00" + envKey
		if _, exists := scopedKeys[scopedKey]; exists {
			return fmt.Errorf("%w: duplicate scoped credential (%q, %q)", ErrInvalidVaultData, scopeID, envKey)
		}
		if _, exists := placeholders[rawPlaceholder]; exists {
			return fmt.Errorf("%w: duplicate placeholder %q", ErrInvalidVaultData, rawPlaceholder)
		}

		v.Credentials[i].ScopeID = scopeID
		v.Credentials[i].ScopeLabel = scopeLabel
		v.Credentials[i].ScopePath = scopePath
		v.Credentials[i].EnvKey = envKey

		scopedKeys[scopedKey] = struct{}{}
		placeholders[rawPlaceholder] = struct{}{}
	}

	return nil
}
