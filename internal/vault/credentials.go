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
)

const placeholderAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

var placeholderRandomReader io.Reader = rand.Reader

func AddCredential(v *Vault, name, secret string, now time.Time) (Credential, error) {
	normalizedName, err := normalizeCredentialName(name)
	if err != nil {
		return Credential{}, err
	}

	if _, err := GetCredentialByName(*v, normalizedName); err == nil {
		return Credential{}, ErrCredentialExists
	} else if !errors.Is(err, ErrCredentialNotFound) {
		return Credential{}, err
	}

	placeholder, err := generateUniquePlaceholder(v.Credentials)
	if err != nil {
		return Credential{}, err
	}

	credential := Credential{
		Name:        normalizedName,
		Placeholder: placeholder,
		Secret:      secret,
		CreatedAt:   now,
	}

	v.Credentials = append(v.Credentials, credential)
	return credential, nil
}

func ListCredentials(v Vault) []CredentialMetadata {
	credentials := make([]CredentialMetadata, 0, len(v.Credentials))
	for _, credential := range v.Credentials {
		credentials = append(credentials, CredentialMetadata{
			Name:        credential.Name,
			Placeholder: credential.Placeholder,
			CreatedAt:   credential.CreatedAt,
		})
	}

	return credentials
}

func GetCredentialByName(v Vault, name string) (Credential, error) {
	normalizedName, err := normalizeCredentialName(name)
	if err != nil {
		return Credential{}, err
	}

	for _, credential := range v.Credentials {
		if credential.Name == normalizedName {
			return credential, nil
		}
	}

	return Credential{}, ErrCredentialNotFound
}

func RemoveCredential(v *Vault, name string) error {
	normalizedName, err := normalizeCredentialName(name)
	if err != nil {
		return err
	}

	for i, credential := range v.Credentials {
		if credential.Name != normalizedName {
			continue
		}

		v.Credentials = append(v.Credentials[:i], v.Credentials[i+1:]...)
		return nil
	}

	return ErrCredentialNotFound
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
