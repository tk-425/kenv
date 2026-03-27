package vault

import "time"

const CurrentVersion = 1

type Vault struct {
	Version     int          `json:"version"`
	Credentials []Credential `json:"credentials"`
}

type Credential struct {
	Name        string    `json:"name"`
	Placeholder string    `json:"placeholder"`
	Secret      string    `json:"secret"`
	CreatedAt   time.Time `json:"created_at"`
}

type CredentialMetadata struct {
	Name        string    `json:"name"`
	Placeholder string    `json:"placeholder"`
	CreatedAt   time.Time `json:"created_at"`
}
