package vault

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	placeholderPrefix      = "kvn_"
	placeholderBodyLength  = 20
	maxPlaceholderAttempts = 16
)

var (
	ErrCredentialExists               = errors.New("credential already exists")
	ErrCredentialNotFound             = errors.New("credential not found")
	ErrInvalidCredentialName          = errors.New("invalid credential name")
	ErrPlaceholderGenerationFailed    = errors.New("placeholder generation failed")
	ErrPlaceholderGenerationExhausted = errors.New("placeholder generation exhausted")
	ErrScopeMigrationConflict         = errors.New("scope migration conflict")
)

const placeholderAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

var placeholderRandomReader io.Reader = rand.Reader

func AddScopedCredential(v *Vault, scope Scope, envKey, secret string, now time.Time) (Credential, error) {
	normalizedScope, err := normalizeScope(scope)
	if err != nil {
		return Credential{}, err
	}

	normalizedKey, err := normalizeCredentialName(envKey)
	if err != nil {
		return Credential{}, err
	}

	if _, err := GetCredentialByScopeAndEnvKey(*v, normalizedScope.ID, normalizedKey); err == nil {
		return Credential{}, ErrCredentialExists
	} else if !errors.Is(err, ErrCredentialNotFound) {
		return Credential{}, err
	}

	placeholder, err := generateUniquePlaceholder(v.Credentials)
	if err != nil {
		return Credential{}, err
	}

	credential := Credential{
		ScopeID:     normalizedScope.ID,
		ScopeLabel:  normalizedScope.Label,
		ScopePath:   normalizedScope.Path,
		EnvKey:      normalizedKey,
		Placeholder: placeholder,
		Secret:      secret,
		CreatedAt:   now,
	}

	v.Credentials = append(v.Credentials, credential)
	return credential, nil
}

func ListCredentialsInScope(v Vault, scopeID string) ([]CredentialMetadata, error) {
	normalizedScopeID, err := normalizeCredentialName(scopeID)
	if err != nil {
		return nil, err
	}

	credentials := make([]CredentialMetadata, 0, len(v.Credentials))
	for _, credential := range v.Credentials {
		if credential.ScopeID != normalizedScopeID {
			continue
		}

		credentials = append(credentials, CredentialMetadata{
			ScopeID:     credential.ScopeID,
			ScopeLabel:  credential.ScopeLabel,
			ScopePath:   credential.ScopePath,
			EnvKey:      credential.EnvKey,
			Placeholder: credential.Placeholder,
			CreatedAt:   credential.CreatedAt,
		})
	}

	return credentials, nil
}

func GetCredentialByScopeAndEnvKey(v Vault, scopeID, envKey string) (Credential, error) {
	normalizedScopeID, err := normalizeCredentialName(scopeID)
	if err != nil {
		return Credential{}, err
	}

	normalizedKey, err := normalizeCredentialName(envKey)
	if err != nil {
		return Credential{}, err
	}

	for _, credential := range v.Credentials {
		if credential.ScopeID == normalizedScopeID && credential.EnvKey == normalizedKey {
			return credential, nil
		}
	}

	return Credential{}, ErrCredentialNotFound
}

func RemoveCredentialByScopeAndEnvKey(v *Vault, scopeID, envKey string) error {
	normalizedScopeID, err := normalizeCredentialName(scopeID)
	if err != nil {
		return err
	}

	normalizedKey, err := normalizeCredentialName(envKey)
	if err != nil {
		return err
	}

	for i, credential := range v.Credentials {
		if credential.ScopeID != normalizedScopeID || credential.EnvKey != normalizedKey {
			continue
		}

		v.Credentials = append(v.Credentials[:i], v.Credentials[i+1:]...)
		return nil
	}

	return ErrCredentialNotFound
}

func FindLocalScopeCredentialsByPath(v Vault, scopePath string) ([]Credential, error) {
	normalizedPath, err := normalizeCredentialName(scopePath)
	if err != nil {
		return nil, err
	}

	matches := make([]Credential, 0)
	for _, credential := range v.Credentials {
		if credential.ScopePath != normalizedPath {
			continue
		}
		if !strings.HasPrefix(credential.ScopeID, "local:") {
			continue
		}

		matches = append(matches, credential)
	}

	return matches, nil
}

func HasLocalScopeCredentialsForPath(v Vault, scopePath string) (bool, error) {
	matches, err := FindLocalScopeCredentialsByPath(v, scopePath)
	if err != nil {
		return false, err
	}

	return len(matches) > 0, nil
}

func MigrateLocalScopeToGitScope(v *Vault, scope Scope) error {
	normalizedScope, err := normalizeScope(scope)
	if err != nil {
		return err
	}
	if !normalizedScope.GitBacked {
		return fmt.Errorf("%w: target scope must be git-backed", ErrScopeMigrationConflict)
	}

	localCredentials, err := FindLocalScopeCredentialsByPath(*v, normalizedScope.Path)
	if err != nil {
		return err
	}

	conflicts := make([]string, 0)
	for _, credential := range localCredentials {
		if _, err := GetCredentialByScopeAndEnvKey(*v, normalizedScope.ID, credential.EnvKey); err == nil {
			conflicts = append(conflicts, credential.EnvKey)
			continue
		} else if !errors.Is(err, ErrCredentialNotFound) {
			return err
		}
	}

	if len(conflicts) > 0 {
		return fmt.Errorf("%w: %s", ErrScopeMigrationConflict, strings.Join(conflicts, ", "))
	}

	for i, credential := range v.Credentials {
		if credential.ScopePath != normalizedScope.Path {
			continue
		}
		if !strings.HasPrefix(credential.ScopeID, "local:") {
			continue
		}

		v.Credentials[i].ScopeID = normalizedScope.ID
		v.Credentials[i].ScopeLabel = normalizedScope.Label
		v.Credentials[i].ScopePath = normalizedScope.Path
	}

	return nil
}

func normalizeScope(scope Scope) (Scope, error) {
	id, err := normalizeCredentialName(scope.ID)
	if err != nil {
		return Scope{}, err
	}

	label, err := normalizeCredentialName(scope.Label)
	if err != nil {
		return Scope{}, err
	}

	path, err := normalizeCredentialName(scope.Path)
	if err != nil {
		return Scope{}, err
	}

	return Scope{
		ID:        id,
		Label:     label,
		Path:      path,
		GitBacked: scope.GitBacked,
	}, nil
}

func normalizeCredentialName(name string) (string, error) {
	normalizedName := strings.TrimSpace(name)
	if normalizedName == "" {
		return "", ErrInvalidCredentialName
	}

	return normalizedName, nil
}

func generateUniquePlaceholder(existing []Credential) (string, error) {
	for attempts := 0; attempts < maxPlaceholderAttempts; attempts++ {
		placeholder, err := generatePlaceholder()
		if err != nil {
			return "", err
		}
		if !placeholderExists(existing, placeholder) {
			return placeholder, nil
		}
	}

	return "", ErrPlaceholderGenerationExhausted
}

func generatePlaceholder() (string, error) {
	body, err := randomPlaceholderBody()
	if err != nil {
		return "", err
	}

	placeholder := placeholderPrefix + body
	if !placeholderPattern.MatchString(placeholder) {
		return "", fmt.Errorf("%w: invalid generated placeholder format", ErrPlaceholderGenerationFailed)
	}

	return placeholder, nil
}

func randomPlaceholderBody() (string, error) {
	const maxUnbiasedByte = 252

	body := make([]byte, 0, placeholderBodyLength)
	randomBytes := make([]byte, placeholderBodyLength)
	for len(body) < placeholderBodyLength {
		if _, err := io.ReadFull(placeholderRandomReader, randomBytes); err != nil {
			return "", fmt.Errorf("%w: read random bytes: %v", ErrPlaceholderGenerationFailed, err)
		}

		for _, randomByte := range randomBytes {
			if randomByte >= maxUnbiasedByte {
				continue
			}

			body = append(body, placeholderAlphabet[int(randomByte)%len(placeholderAlphabet)])
			if len(body) == placeholderBodyLength {
				return string(body), nil
			}
		}
	}

	return string(body), nil
}

func placeholderExists(existing []Credential, candidate string) bool {
	for _, credential := range existing {
		if credential.Placeholder == candidate {
			return true
		}
	}

	return false
}
