# kenv Manual

## Introduction

`kenv` is a local CLI for storing secrets in one encrypted home-directory vault while keeping application-facing config files free of raw secret values.

The intended workflow is:

1. Store a secret in the vault with `kenv add`
2. Put the returned `ENV_KEY=placeholder` line in your `.env` file
3. Start your app through `kenv run`
4. Let `kenv` replace placeholders with real secret values only at process launch time

This keeps `.env` files portable across machines and projects while reducing the chance of committing or copying raw secrets.

## Mental Model

### One vault, many project scopes

`kenv` stores secrets in a single local encrypted vault in your home directory. Secrets are scoped by project, so the same env key can exist in multiple projects with different values.

Each stored credential has:

- `scope_id` — the internal identity of the project scope
- `scope_label` — a human-readable project label
- `scope_path` — the canonical project root path
- `env_key` — the environment variable name, such as `OPENAI_API_KEY`
- `placeholder` — the token you place in your `.env` file

### Project scope behavior

When you run `kenv` inside a Git repository, it tries to detect a Git-backed scope from the repository root and canonicalized `origin` remote.

When no usable Git identity exists, `kenv` falls back to a deterministic local scope for that project directory.

This means:

- `OPENAI_API_KEY` in project A can differ from `OPENAI_API_KEY` in project B
- `kenv show` and `kenv rm` stay inside the current project scope
- `kenv run` still resolves by placeholder token, not by `scope_id` plus `env_key`

### Placeholders, not raw secrets

The placeholder is the value you commit or share in `.env` files. It looks like:

```text
kvn_1234567890abcdefghij
```

Your application never sees that token if you launch it through `kenv run`. `kenv` swaps the placeholder with the real secret before spawning the child process.

## Quick Start

### 1. Initialize the vault

```bash
kenv init
```

You will be prompted for a vault passphrase twice.

### 2. Add a secret

Inside your project:

```bash
kenv add OPENAI_API_KEY
```

`kenv` will:

- unlock the vault
- detect the current project scope
- ask you to confirm the detected scope
- prompt for the secret value
- print an `.env`-ready assignment line to stdout
- print a reminder to stderr that the raw secret will not be displayed later

Example output:

```text
OPENAI_API_KEY=kvn_1234567890abcdefghij
```

### 3. Put the placeholder in `.env`

```dotenv
OPENAI_API_KEY=kvn_1234567890abcdefghij
```

### 4. Run your app through `kenv`

```bash
kenv run --env .env -- node server.js
```

At runtime, `kenv` resolves the placeholder and starts the command with the real secret in the process environment.

## Installation and Setup

### Build from source

Development build:

```bash
make build-dev
```

Release-style build with injected version:

```bash
make build-release VERSION=0.1.0
```

Default local build:

```bash
make build
```

### Local installation

The project rule for this repo is to keep the source version as `dev` and inject the release version at build time. A typical local install flow is:

```bash
make build-release VERSION=0.1.0
cp ./bin/kenv /usr/local/bin/kenv
```

If `/usr/local/bin` is not writable, run the copy step manually with `sudo`.

### Vault location

`kenv` stores encrypted vault data under your home directory in a local vault path managed by the CLI. You do not need to manually edit vault files.

### Passphrase expectations

- `kenv init` asks for the passphrase twice
- commands that unlock the vault ask for the passphrase once
- the passphrase is required to decrypt the vault contents

## Command Reference

### `kenv init`

Initialize the local encrypted vault.

Usage:

```bash
kenv init
```

Behavior:

- fails if the vault already exists
- prompts for a passphrase and confirmation
- creates an empty encrypted vault
- verifies it can decrypt the new vault

Success output:

```text
vault initialized
```

Common errors:

- `vault already exists`
- TTY-related prompt errors
- passphrase mismatch

### `kenv add`

Add a scoped secret and return its placeholder token.

Usage:

```bash
kenv add <env-key>
```

Example:

```bash
kenv add OPENAI_API_KEY
```

Behavior:

- unlocks the vault
- detects the current scope from the working directory
- blocks if a matching local-to-git migration is pending
- asks for scope confirmation
- prompts for the secret value
- stores the secret under the current scope and env key
- prints `ENV_KEY=placeholder` to stdout
- prints the add success reminder to stderr

Notes:

- the same env key may exist in multiple project scopes
- the same env key may not be added twice in the same scope
- `kenv add OPENAI_API_KEY >> .env` appends only the assignment line to `.env`; the reminder still appears in the terminal because it is written to stderr

Common errors:

- `credential already exists`
- `this project has pending local-to-git scope migration; run \`kenv scope migrate\` first`
- scope detection errors

### `kenv list`

List placeholders for the current project scope.

Usage:

```bash
kenv list
```

Output format:

```text
<scope_label>\t<env_key>\t<placeholder>
```

Example:

```text
kenv	OPENAI_API_KEY	kvn_1234567890abcdefghij
kenv	ANTHROPIC_API_KEY	kvn_abcdefghij1234567890
```

Behavior:

- unlocks the vault
- detects the current scope
- blocks if migration is required for the current path
- lists only credentials in the current scope

### `kenv show`

Show the placeholder for a scoped secret in the current project.

Usage:

```bash
kenv show <env-key>
```

Example:

```bash
kenv show OPENAI_API_KEY
```

Output:

```text
kvn_1234567890abcdefghij
```

Behavior:

- unlocks the vault
- detects the current scope
- blocks if migration is required
- returns only the current scope’s record

If another project has the same env key, `kenv show` does not cross scope boundaries to return it.

### `kenv rm`

Remove a scoped secret from the current project scope.

Usage:

```bash
kenv rm <env-key>
```

Example:

```bash
kenv rm OPENAI_API_KEY
```

Behavior:

- unlocks the vault
- detects the current scope
- blocks if migration is required
- asks for scope confirmation
- removes the secret only from the current scope
- saves the vault

Success output:

```text
removed OPENAI_API_KEY
```

If you decline the scope confirmation prompt, the command exits with:

```text
remove canceled
```

### `kenv run`

Resolve placeholders from an env file and start a command.

Usage:

```bash
kenv run [--inherit-env] --env <file> -- <command...>
```

Examples:

```bash
kenv run --env .env -- node server.js
kenv run --env .env.local -- python app.py
kenv run --inherit-env --env .env -- npm run dev
```

Behavior:

- reads the env file
- identifies placeholder candidates
- unlocks the vault only if placeholders are present
- resolves placeholders by placeholder token
- builds a child environment
- spawns the requested command

By default, `kenv run` starts from a minimal baseline environment. `--inherit-env` loads the current shell environment first, then overlays values from the env file and resolved secrets.

Important:

- `kenv run` does not resolve by env key or by project scope
- it resolves only by placeholder token
- unknown placeholders fail closed before the child process is started

### `kenv scope migrate`

Upgrade local-scope credentials to the current Git-backed scope when a project becomes Git-backed later.

Usage:

```bash
kenv scope migrate
```

Behavior:

- unlocks the vault
- detects the current scope
- requires the current scope to be Git-backed
- finds local-scope credentials whose `scope_path` exactly matches the current canonical project root
- saves the migrated vault
- prints `nothing to migrate` if none are found
- prompts for migration confirmation
- fails on conflicting env keys already present in the Git-backed scope
- rewrites matching local-scope records into the Git-backed scope

Success output:

```text
migrated 2 credential(s) into github.com/tk-425/kenv
```

No-op output:

```text
nothing to migrate
```

If the project is not Git-backed:

```text
`kenv scope migrate` requires a git-backed project scope
```

### `kenv backup restore`

Restore the live vault from an automatically created encrypted backup snapshot.

Usage:

```bash
kenv backup restore
```

Behavior:

- reads automatic encrypted snapshots from `~/.kenv/backups`
- shows available snapshots in reverse chronological order
- marks the latest complete post-save snapshot as recommended
- still allows selecting older pre-save snapshots for rollback
- prompts for the vault passphrase before restoring
- validates the selected snapshot before replacing the live vault
- works even if `~/.kenv/vault.age` is missing
- snapshots the current live vault before restore when one exists

Notes:

- backups are created automatically around mutating vault writes
- retention is fixed at 10 snapshots in the current version
- backup failures are treated as save failures so recoverability is not silently weakened

### `kenv version`

Print the CLI version string.

Usage:

```bash
kenv version
```

Typical output:

```text
dev
```

Release builds should inject a concrete version string.

## Project Scope Behavior

### Git-backed scope

If `kenv` finds a `.git` marker while walking upward from the current working directory:

- that directory is treated as the project root
- `kenv` tries to read and canonicalize `remote.origin.url`
- if successful, the canonical remote becomes the scope identity
- the repo basename becomes the scope label
- the canonical root path becomes the scope path

### Local fallback scope

If no usable Git identity exists:

- the canonical project root path is used as scope metadata
- a deterministic local scope ID is derived from the canonical path
- the directory basename is used as the scope label

This lets non-Git projects work without extra configuration.

### Nested directories

Running `kenv` from a nested subdirectory inside a repository still uses the repository root scope.

### Migration behavior

If a project originally used a local scope and later becomes Git-backed, `kenv` does not migrate automatically. The explicit migration path is:

```bash
kenv scope migrate
```

## Typical Workflows

### New project in a Git repository

```bash
kenv init
kenv add OPENAI_API_KEY >> .env
kenv run --env .env -- npm run dev
```

### Existing non-Git local project

```bash
cd ~/scratch/my-script
kenv add API_TOKEN > .env
kenv run --env .env -- python script.py
```

### Project that later becomes a Git repo

Before Git identity:

```bash
kenv add OPENAI_API_KEY
```

After Git initialization and remote setup:

```bash
kenv scope migrate
```

### Rotating a secret

There is no dedicated rotate command today. A practical flow is:

1. note or re-fetch the env key
2. remove it from the current scope
3. add it again with the new secret
4. keep using the new placeholder in `.env`

Example:

```bash
kenv rm OPENAI_API_KEY
kenv add OPENAI_API_KEY
```

### Removing a secret

```bash
kenv rm OPENAI_API_KEY
```

Remember to remove or update any placeholder still present in your `.env` files.

## Language and Framework Examples

### Node.js

`.env`

```dotenv
OPENAI_API_KEY=kvn_1234567890abcdefghij
PORT=3000
```

Run:

```bash
kenv run --env .env -- node server.js
```

Minimal usage:

```js
console.log(process.env.OPENAI_API_KEY);
```

### Express

`.env`

```dotenv
OPENAI_API_KEY=kvn_1234567890abcdefghij
SESSION_SECRET=kvn_abcdefghij1234567890
```

Run:

```bash
kenv run --env .env -- node server.js
```

### Next.js

Use placeholders in `.env.local` for server-side secrets:

```dotenv
OPENAI_API_KEY=kvn_1234567890abcdefghij
```

Run local development:

```bash
kenv run --env .env.local -- npm run dev
```

Notes:

- server-side code sees the resolved secret at runtime
- do not treat `kenv` as a client-side secret delivery mechanism
- avoid placing sensitive secrets in `NEXT_PUBLIC_*` variables

### Python

`.env`

```dotenv
OPENAI_API_KEY=kvn_1234567890abcdefghij
```

Run a script:

```bash
kenv run --env .env -- python app.py
```

Minimal usage:

```python
import os

print(os.environ["OPENAI_API_KEY"])
```

### FastAPI

```bash
kenv run --env .env -- uvicorn app:app --reload
```

### Django

```bash
kenv run --env .env -- python manage.py runserver
```

### Ruby

`.env`

```dotenv
OPENAI_API_KEY=kvn_1234567890abcdefghij
```

Run:

```bash
kenv run --env .env -- ruby app.rb
```

### Rails

```bash
kenv run --env .env -- bin/rails server
```

### Go

`.env`

```dotenv
DATABASE_URL=kvn_1234567890abcdefghij
```

Run:

```bash
kenv run --env .env -- go run ./cmd/api
```

Your Go process reads the final value from `os.Getenv`.

### Shell scripts

`.env`

```dotenv
API_TOKEN=kvn_1234567890abcdefghij
```

Run:

```bash
kenv run --env .env -- bash deploy.sh
```

### Docker and local container workflows

For local workflows, use `kenv run` to launch Docker commands with resolved environment values:

```bash
kenv run --env .env -- docker compose up
```

This is useful when the Docker command or wrapper script reads environment variables at launch time.

What `kenv` does not do:

- it does not rewrite image layers
- it does not inject secrets into a Docker build context automatically
- it does not replace a dedicated production secret manager

## `.env` File Patterns

### Recommended pattern

Commit placeholders, not raw secrets:

```dotenv
OPENAI_API_KEY=kvn_1234567890abcdefghij
ANTHROPIC_API_KEY=kvn_abcdefghij1234567890
LOG_LEVEL=debug
```

### Recommended repo hygiene

- placeholders in `.env.example` or team-shared `.env` files are fine
- raw secrets should never be committed
- if your team shares placeholder-bearing files, each developer still needs matching secrets in their own local vault

### Important distinction

- placeholder token: safe to place in config files relative to raw secrets
- raw secret: should stay only in the encrypted vault and child process environment

## Migration Guide

### Local scope to Git-backed scope

If you used `kenv` before a project had a usable Git identity, and later the project becomes Git-backed, run:

```bash
kenv scope migrate
```

Migration rules:

- migration is explicit only
- matching is by exact canonical `scope_path`
- conflicting env keys are not auto-merged
- unrelated local scopes are not touched

### What migration-required errors mean

If `kenv add`, `kenv list`, `kenv show`, or `kenv rm` tells you to run `kenv scope migrate`, it means:

- the current project is now Git-backed
- matching local-scope credentials still exist for this exact project path
- `kenv` wants you to upgrade them explicitly before continuing

## Troubleshooting

### `vault does not exist; run \`kenv init\` first`

Initialize the vault:

```bash
kenv init
```

### `vault unlock failed`

The passphrase was incorrect, or the vault could not be unlocked with the provided passphrase.

### `credential already exists`

That env key already exists in the current scope. Use a different env key, remove the old one, or inspect it with:

```bash
kenv list
kenv show <env-key>
```

### `credential not found`

The requested env key does not exist in the current project scope.

### `this project has pending local-to-git scope migration; run \`kenv scope migrate\` first`

Run:

```bash
kenv scope migrate
```

### `invalid placeholder`

The stored or parsed placeholder does not match the expected token format. Placeholders are strict and are not silently normalized.

### Unknown placeholder during `kenv run`

The env file contains a placeholder token that is not present in the unlocked vault.

### Scope confusion between projects

Check that you are running inside the intended project root or nested directory. Git-backed projects use repository scope; non-Git projects use local fallback scope.

## Security Notes

- `kenv` is a local CLI, not a cloud secret manager
- it helps keep raw secrets out of `.env` files and day-to-day command lines
- the encrypted vault is local to the user environment
- wrong-scope behavior in `show` and `rm` is treated as an important boundary
- placeholders remain globally unique to avoid ambiguous runtime resolution
- placeholder validation is intentionally strict; padded placeholder strings are rejected rather than silently trimmed into validity

What `kenv` does not protect against:

- a compromised local machine
- a stolen vault passphrase
- unsafe application logging that prints secrets after process launch
- production secret distribution on its own

## FAQ

### Can I use the same env key in multiple projects?

Yes. That is the main purpose of project scoping.

### Why does `kenv` ask for scope confirmation?

To make mutating commands explicit about which project scope they are about to affect.

### Why does `kenv run` resolve by placeholder instead of env key?

Because placeholders are globally unique and avoid ambiguity across project scopes at runtime.

### What happens if I move a project directory?

Scope detection uses canonical path metadata and, when available, Git-backed identity. Moving a non-Git project can change how local fallback scope is derived.

### What if my Git repo has no usable remote?

`kenv` falls back to a deterministic local scope.

### Can I share the vault across machines?

Not automatically. `kenv` is built around a local encrypted vault model.

### Can I commit placeholder values?

That is the intended workflow. The placeholder is not the raw secret.

### Should I put secrets in `NEXT_PUBLIC_*` or other client-exposed variables?

No. `kenv` helps with server-side or local process environment injection, not safe client-side secret distribution.

## Command Cheat Sheet

Initialize vault:

```bash
kenv init
```

Add a secret:

```bash
kenv add OPENAI_API_KEY >> .env
```

List current project secrets:

```bash
kenv list
```

Show a placeholder:

```bash
kenv show OPENAI_API_KEY
```

Remove a secret:

```bash
kenv rm OPENAI_API_KEY
```

Run an app with resolved secrets:

```bash
kenv run --env .env -- node server.js
```

Run with inherited shell environment:

```bash
kenv run --inherit-env --env .env -- npm run dev
```

Migrate local scope to Git-backed scope:

```bash
kenv scope migrate
```

Print version:

```bash
kenv version
```

## Appendix

### Placeholder format

The current placeholder format is:

```text
kvn_[a-z0-9]{20}
```

### Related docs

- [`.docs/SCOPED-VAULT-DESIGN.md`](/Users/terrykang/Documents/Programming/+Projects/+CLI/kenv/.docs/SCOPED-VAULT-DESIGN.md)
- [`.docs/SCOPED-VAULT-PLAN.md`](/Users/terrykang/Documents/Programming/+Projects/+CLI/kenv/.docs/SCOPED-VAULT-PLAN.md)
- [`.docs/PLAN-v2.md`](/Users/terrykang/Documents/Programming/+Projects/+CLI/kenv/.docs/PLAN-v2.md)
