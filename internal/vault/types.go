package vault

import "time"

const CurrentVersion = 1

type Vault struct {
	Version     int          `json:"version"`
	Credentials []Credential `json:"credentials"`
}

type Credential struct {
	ScopeID     string    `json:"scope_id"`
	ScopeLabel  string    `json:"scope_label"`
	ScopePath   string    `json:"scope_path"`
	EnvKey      string    `json:"env_key"`
	Placeholder string    `json:"placeholder"`
	Secret      string    `json:"secret"`
	CreatedAt   time.Time `json:"created_at"`
}

type CredentialMetadata struct {
	ScopeID     string    `json:"scope_id"`
	ScopeLabel  string    `json:"scope_label"`
	ScopePath   string    `json:"scope_path"`
	EnvKey      string    `json:"env_key"`
	Placeholder string    `json:"placeholder"`
	CreatedAt   time.Time `json:"created_at"`
}

type Scope struct {
	ID        string
	Label     string
	Path      string
	GitBacked bool
}
