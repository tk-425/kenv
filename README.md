# kenv

`kenv` is a local CLI for storing secrets in one encrypted home-directory vault while keeping project `.env` files free of raw secret values.

Instead of committing real secrets into `.env`, you store the secret once in the vault, put a `kvn_...` placeholder into `.env`, and launch your app through `kenv run` so the placeholder is resolved only at process start.

## Why

- Keep raw secrets out of `.env` files
- Reuse one local encrypted vault across projects
- Support project-scoped secrets, so the same env key can differ by repo
- Make `.env` files portable while still resolving real secrets locally

## Quick Start

### 1. Initialize the vault

```bash
kenv init
```

### 2. Add a secret

```bash
kenv add <env-key>
```

### 3. Put the placeholder in `.env`

```dotenv
<env-key>=kvn_1234567890abcdefghij
```

### 4. Run your app through `kenv`

```bash
kenv run -- <command>
```

For the full command reference, workflows, and troubleshooting, see the [manual](./docs/MANUAL.md).

## Build

```bash
make build-dev              # development build
make build-release VERSION=x.y.z  # release build with injected version
```

## Install

```bash
cp ./bin/kenv /usr/local/bin/kenv
```
