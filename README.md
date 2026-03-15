# 🔐 DesktopSecrets

![CI/CD Status](https://img.shields.io/github/actions/workflow/status/it-atelier-gn/desktop-secrets/pipeline.yaml)
![Go](https://img.shields.io/github/go-mod/go-version/it-atelier-gn/desktop-secrets)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/it-atelier-gn/desktop-secrets)

DesktopSecrets is a lightweight, secure utility that centralizes secret management for developers and power users on the desktop. It integrates with KeePass and local user-provided secrets to make retrieving credentials simple, scriptable, and safe, while minimizing repeated password prompts through configurable caching. Designed for workflows that require environment templating and command-line automation, DesktopSecrets helps you keep sensitive data out of source files and streamline local development and deployment tasks.

## ✨ Features

- 🔑 **KeePass Integration** – Seamlessly fetch secrets from KeePass vaults.
- 💾 **Smart Caching** – Unlocked vaults stay accessible for a configurable duration.
- ⚙️ **Easy Configuration** – GUI settings menu in the taskbar icon.

---

## 🔌 Secret Providers

Secret providers define how DesktopSecrets retrieves secrets from different sources

### 🔑 KeePass Provider

Prompts the user for the master password of a KeePass vault and returns the requested entry.

#### Format

```properties
SECRET_NAME=keepass(VAULT|SECRET_TITLE)
```

* VAULT = Path to a KeePass database file
* SECRET_TITLE = Title of the entry inside the vault

### 👤 User Provider

Prompts the user to manually enter a secret value.

#### Format

```properties
SECRET_NAME=user(TITLE)
```
## 🚀 Commands

### 📄*tplenv*

A command-line tool that resolves secrets inside on or more `.env.tpl` files.

####  Usage Example 

```properties
DATABASE_URL=postgresql://localhost:5432/mydb
API_SECRET=keepass($USERPROFILE\Credentials.kdbx|dev-api-secret)
LOG_LEVEL=debug
```

Running `tplenv` prints the merged, fully resolved environment so it can be sourced into a shell.
Use `tplenv --apply-one-liner` to learn how to apply it directly.
Use `tplenv run` to execute a command with all resolved variables injected into the environment.

### 🛠️ *getsec*

A command‑line tool for resolving secrets passed directly as arguments.

####  Usage Example

```shell
getsec "API_SECRET=keepass($USERPROFILE\Credentials.kdbx|dev-api-secret)"
```

## 🧑‍🎓 Advanced topics

### ⚙️ Configuration

Access settings via the **taskbar icon menu**.

**Default Configuration Locations**
* macOS: `~/Library/Application Support/desktop-secrets`
* Linux: `$XDG_CONFIG_HOME/desktop-secrets` or `~/.config/desktop-secrets`
* Windows: `%APPDATA%\desktop-secrets`

#### Aliases

Define aliases for cleaner configuration in the file `aliases.yaml`:

Example:

```yaml
cloud: 
    file: C:\Project\ABC\Vaults\cloud-secrets.kdbx
    master: keepass(C:\Project\ABC\Vaults\personal.kdbx|Cloud Secrets)
local: C:\Users\User\Vaults\local-secrets.kdbx
```

Use an alias with the & prefix: ```&cloud``` or  ```&local```

#### Overrides

Environment overrides:
- `DESKTOP_SECRETS_CONFIG_FILE` - override the config file
- `DESKTOP_SECRETS_ALIASES_FILE` - override the aliases file
- `DESKTOP_SECRETS_KEYFILES_FILE` - to override the keyfiles file

### Chaining

The KeePass provider supports opening a KeePass database using a secret retrieved from another KeePass database.

**Example:**
```properties
SECRET_NAME=keepass(VAULT_A[keepass(VAULT_B|SECRET_TITLE_B)]|SECRET_TITLE_A)
```

This prompts the user for the master password of VAULT_B, uses the value of SECRET_TITLE_B from VAULT_B as the master password to unlock VAULT_A, and then retrieves SECRET_TITLE_A from VAULT_A.


## 🛠️ Build

### Prerequisites

- Ensure Go is installed and set up.

### Build from Source

**Standard build:**

Windows

```pwsh
go build -o tplenv.exe ./cmd/tplenv
go build -o getsec.exe ./cmd/getsec
```

Linux 

```shell
go build -o tplenv ./cmd/tplenv
go build -o getsec ./cmd/getsec
```
