# 🔐 DesktopSecrets

![CI/CD Status](https://img.shields.io/github/actions/workflow/status/it-atelier-gn/desktop-secrets/ci.yml)
![Go](https://img.shields.io/github/go-mod/go-version/it-atelier-gn/desktop-secrets)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/it-atelier-gn/desktop-secrets)

DesktopSecrets is a lightweight, secure utility that centralizes secret management for developers and power users on the desktop. It integrates with KeePass and local user-provided secrets to make retrieving credentials simple, scriptable, and safe, while minimizing repeated password prompts through configurable caching. Designed for workflows that require environment templating and command-line automation, DesktopSecrets helps you keep sensitive data out of source files and streamline local development and deployment tasks.

---

## ✨ Features

- 🔑 **KeePass Integration** – Retrieve secrets from KeePass vaults using flexible path and wildcard matching.  
- 🧩 **Secret References** – A unified syntax for referencing secrets from any provider.  
- 🔁 **Recursive Aliases** – Define reusable secret references.  
- 💾 **Smart Caching** – Unlocked vaults stay accessible for a configurable duration.  
- ⚙️ **Easy Configuration** – GUI settings menu in the taskbar icon and simple YAML files.

---

## 🔌 Secret References

A *Secret Reference* is an expression that resolves to a secret value.  
Examples:

```
keepass(C:\Vaults\cloud.kdbx|/AWS/Prod/api-key)
user(Enter API key)
```

Aliases expand recursively into other secret references.

---

## 🔑 KeePass Provider

The KeePass provider retrieves secrets from `.kdbx` vaults.  
It supports:

- absolute paths  
- wildcard paths (`*` = one level, `**` = any depth)  
- escaped slashes (`\/`)  
- attribute selection  
- chaining

### Basic Format

```properties
SECRET_NAME=keepass(VAULT|ENTRY)
```

- **VAULT** – Path to a KeePass database file (or alias)  
- **ENTRY** – Title or path pattern

### Entry Lookup Rules

#### 1. Bare titles  
If the entry does **not** start with `/`, it is treated as:

```
**/<title>
```

Example:

```
keepass(vault.kdbx|api-key)
```

Searches for any entry named `api-key` anywhere in the tree.

#### 2. Absolute paths

```
keepass(vault.kdbx|/AWS/Prod/api-key)
```

Matches exactly that path.

#### 3. Wildcards

- `*` matches **one** group level  
- `**` matches **zero or more** group levels  

Examples:

```
keepass(vault.kdbx|/AWS/*/api-key)
keepass(vault.kdbx|/AWS/**/api-key)
```

#### 4. Escaped slashes

```
keepass(vault.kdbx|/AWS/Prod/My\/Key)
```

Matches an entry titled `My/Key`.

#### 5. Attribute selection

```
keepass(vault.kdbx|/AWS/Prod/api-key|UserName)
keepass(vault.kdbx|/AWS/Prod/api-key|URL)
keepass(vault.kdbx|/AWS/Prod/api-key|Notes)
keepass(vault.kdbx|/AWS/Prod/api-key|customField)
```

Attribute names are case-sensitive. If omitted, the default attribute is the `Password`.

---

## 👤 User Provider

Prompts the user to manually enter a secret value.

```
SECRET_NAME=user(Title shown in prompt)
```

---

## 🔁 Aliases

Aliases are defined in `aliases.yaml`.

Example:

```yaml
cloud: 
  file: C:\Vaults\cloud.kdbx 
  master: keepass(&personal|Cloud Master Password)
personal: C:\Vaults\personal.kdbx
```

Usage:

```
MAPS_API_KEY=keepass(&cloud|/Google/Prod/api-key) 
CLAUDE_API_KEY=keepass(&personal|Claude Code API key)
```

---

## 🔗 Chaining

KeePass vaults can be unlocked using secrets retrieved from other providers.

Example:

```properties
SECRET=keepass(VAULT_A[keepass(VAULT_B|MasterPassword)]|/Prod/api-key)
```

This:

1. Resolves the inner secret reference  
2. Uses it as the master password for `VAULT_A`  
3. Retrieves the final entry

Chaining works with all lookup modes, including wildcards and aliases.

---

## 🚀 Commands

### 📄 *tplenv*

Resolves secrets inside one or more `.env.tpl` files.

Example:

```properties
DATABASE_URL=postgresql://localhost:5432/mydb
API_SECRET=keepass($USERPROFILE\Credentials.kdbx|api-key)
LOG_LEVEL=debug
```

`tplenv` prints the fully resolved environment.  
Use `tplenv run` to execute a command with resolved variables injected.

---

### 🛠️ *getsec*

Resolves a single secret reference passed directly as an argument.

Example:

```sh
getsec "API_SECRET=keepass($USERPROFILE\Credentials.kdbx|api-key)"
```

---

## ⚙️ Configuration

Settings are accessible via the taskbar icon.

### Default Configuration Locations

- macOS: `~/Library/Application Support/desktop-secrets`
- Linux: `$XDG_CONFIG_HOME/desktop-secrets` or `~/.config/desktop-secrets`
- Windows: `%APPDATA%\desktop-secrets`

### Environment Overrides

- `DESKTOP_SECRETS_CONFIG_FILE`  
- `DESKTOP_SECRETS_ALIASES_FILE`  
- `DESKTOP_SECRETS_KEYFILES_FILE`

---

## 🛠️ Build

### Prerequisites

- Go installed and configured

### Build from Source

Windows:

```pwsh
go build -o tplenv.exe ./cmd/tplenv
go build -o getsec.exe ./cmd/getsec
```

Linux:

```sh
go build -o tplenv ./cmd/tplenv
go build -o getsec ./cmd/getsec
```

### Usage as library
```
go get github.com/it-atelier-gn/desktop-secrets
```

```go
import (
  "os"
  desktopsecrets "github.com/it-atelier-gn/desktop-secrets"
)

func main() {
  // Required: allows this binary to be re-launched as the secrets daemon.
  if desktopsecrets.Init() {
    os.Exit(0)
  }

  secret, err := desktopsecrets.ResolveSecret("user(DB Password)")
  if err != nil {
    panic(err)
  }
  println(secret)
}
```
