# kenv

`kenv` is a local CLI for storing secrets in one encrypted home-directory vault while keeping project `.env` files free of raw secret values.

Instead of committing real secrets into `.env`, you store the secret once in the vault, put a `kvn_...` placeholder into `.env`, and launch your app through `kenv run` so the placeholder is resolved only at process start.

## Why

- Keep raw secrets out of `.env` files
- Reuse one local encrypted vault across projects
- Support project-scoped secrets, so the same env key can differ by repo
- Make `.env` files portable while still resolving real secrets locally

## How It Works

1. Run `kenv add OPENAI_API_KEY`
2. `kenv` stores the real secret in the encrypted vault
3. `kenv` prints `OPENAI_API_KEY=kvn_...`
4. Put that assignment into `.env`
5. Run your app with `kenv run --env .env -- <command>`
6. `kenv` replaces the placeholder with the real secret only for that child process

Direct app launches will still see the raw placeholder. Only `kenv run` resolves it.

## Quick Start

### 1. Initialize the vault

```bash
kenv init
```

### 2. Add a secret

```bash
kenv add OPENAI_API_KEY
```

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

## Command Overview

- `kenv init` — initialize the local encrypted vault
- `kenv add <env-key>` — store a scoped secret and print an `.env`-ready placeholder assignment
- `kenv list` — list placeholders in the current project scope
- `kenv show <env-key>` — show the placeholder for the current project scope
- `kenv rm <env-key>` — remove a scoped secret
- `kenv run --env <file> -- <command...>` — resolve placeholders and run a child command
- `kenv scope migrate` — migrate local-scope credentials into the current git-backed scope
- `kenv backup restore` — restore from an automatically created encrypted vault backup
- `kenv version` — print the current version

## Backup and Restore

`kenv` automatically keeps encrypted vault snapshots under `~/.kenv/backups/`.

- successful saves create `pre` and `post` snapshots
- retention is fixed at 10 snapshots
- `kenv backup restore` lets you recover from vault corruption or accidental changes

Current restore flow:

1. list available backups
2. prompt for vault passphrase
3. prompt for backup selection
4. restore the selected snapshot

## Build

Development build:

```bash
make build-dev
```

Release-style build with injected version:

```bash
make build-release VERSION=0.1.1
```

The source version stays `dev`; release versions are injected at build time.

## Install

```bash
cp ./bin/kenv /usr/local/bin/kenv
```

Typical local release install flow:

```bash
make build-release VERSION=0.1.1
cp ./bin/kenv /usr/local/bin/kenv
```

## Documentation

For the full manual, see [`docs/MANUAL.md`](./docs/MANUAL.md).
