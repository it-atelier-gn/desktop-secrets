# DesktopSecrets

![CI/CD Status](https://img.shields.io/github/actions/workflow/status/it-atelier-gn/desktop-secrets/ci.yml)
![Go](https://img.shields.io/github/go-mod/go-version/it-atelier-gn/desktop-secrets)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/it-atelier-gn/desktop-secrets)

DesktopSecrets is a utility that allows you to remove secrets from your filesystem by transforming them to *Secret References*. It integrates with KeePass, AWS Secrets Manager, AWS Parameter Store, Azure Key Vault, GCP Secret Manager, HashiCorp Vault, 1Password, Windows Credential Manager, macOS Keychain, and local user-provided prompts to make retrieving credentials simple, scriptable, and safe, while minimizing repeated password prompts through configurable caching. 

---

## Secret References

A *Secret Reference* is an expression that resolves to a secret value

Examples:

```
keepass(C:\Vaults\cloud.kdbx|/AWS/Prod/api-key)
awssm(MyApp/DB|password)
awsps(/myapp/prod/api-key)
azkv(mykv/dbpass)
gcpsm(my-project/api-key)
vault(secret/data/myapp|password)
op(Personal/GitHub|token)
wincred(MyApp/DBPassword)
keychain(git.example.com|alice)
user(Enter API key)
```

---

## Commands

DesktopSecrets provides the following commands.

### *tplenv*

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

### *getsec*

Resolves a single secret reference passed directly as an argument.

Example:

```sh
getsec "API_SECRET=keepass($USERPROFILE\Credentials.kdbx|api-key)"
```

---

## User Provider

Prompts the user to manually enter a secret value.

```
SECRET_NAME=user(Title shown in prompt)
```

---

## Windows Credential Manager Provider *(Windows only)*

Retrieves secrets from the Windows Credential Manager — the built-in credential store accessible via **Control Panel › Credential Manager**.

Create entries with `cmdkey` or the GUI:

```powershell
cmdkey /generic:"MyApp/DBPassword" /user:"myuser" /pass:"mysecret"
```

### Format

```properties
SECRET_NAME=wincred(TARGET)              # password field (default)
SECRET_NAME=wincred(TARGET|password)     # password field (explicit)
SECRET_NAME=wincred(TARGET|username)     # username field
```

- **TARGET** — The credential target name used when storing the credential
- **Field** — `password` (default) or `username`

### Example

```properties
DB_PASSWORD=wincred(MyApp/DBPassword)
DB_USER=wincred(MyApp/DBPassword|username)
```

---

## AWS Provider

Retrieves secrets from **AWS Secrets Manager** (`awssm`) and **AWS Parameter Store** (`awsps`).

Uses the standard AWS credential chain — no extra configuration needed:
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` env vars
- `~/.aws/credentials` + `~/.aws/config` (respects `AWS_PROFILE`, `AWS_DEFAULT_REGION`)
- IAM instance roles, ECS task roles, Web Identity tokens

Resolved values are cached in-memory for the configured TTL (same as KeePass).

### AWS Secrets Manager

```properties
# Raw string secret
API_KEY=awssm(MyApp/ApiKey)

# JSON field extraction
DB_USER=awssm(MyApp/DB|username)
DB_PASS=awssm(MyApp/DB|password)
```

### AWS Parameter Store

SecureString parameters are always decrypted automatically.

```properties
# Parameter value
API_KEY=awsps(/myapp/prod/api-key)

# JSON field extraction
DB_HOST=awsps(/myapp/prod/db|host)
```


---

## Azure Key Vault Provider

Retrieves secrets from **Azure Key Vault** (`azkv`).

Uses `DefaultAzureCredential` — tries in order: env vars, workload identity, managed identity, Azure CLI (`az login`), Azure PowerShell, Azure Developer CLI. No extra config needed if any of those are set up.

### Format

```properties
SECRET_NAME=azkv(VAULT/NAME)                    # raw secret value
SECRET_NAME=azkv(VAULT/NAME|field)              # JSON field extraction
SECRET_NAME=azkv(https://VAULT.vault.azure.net/NAME)  # full URL form
```

- **VAULT** — Key Vault name (e.g. `mykv`) or full URL
- **NAME** — secret name
- **field** — optional JSON field if the secret value is JSON

### Example

```properties
DB_PASSWORD=azkv(mykv/db-password)
DB_USER=azkv(mykv/db-credentials|username)
```

---

## GCP Secret Manager Provider

Retrieves secrets from **Google Cloud Secret Manager** (`gcpsm`).

Uses Application Default Credentials — `GOOGLE_APPLICATION_CREDENTIALS` env var, `gcloud auth application-default login`, attached service account on GCE/GKE/Cloud Run, etc.

### Format

```properties
SECRET_NAME=gcpsm(PROJECT/NAME)                 # latest version
SECRET_NAME=gcpsm(PROJECT/NAME/VERSION)         # specific version
SECRET_NAME=gcpsm(PROJECT/NAME|field)           # JSON field extraction
SECRET_NAME=gcpsm(projects/P/secrets/N/versions/V)  # fully-qualified form
```

- **PROJECT** — GCP project ID
- **NAME** — secret name
- **VERSION** — numeric version or `latest` (default)
- **field** — optional JSON field if the secret payload is JSON

### Example

```properties
API_KEY=gcpsm(my-project/api-key)
DB_PASS=gcpsm(my-project/db-credentials|password)
```

---

## macOS Keychain Provider *(macOS only)*

Retrieves generic passwords from the **macOS login keychain** via the `security` CLI.

Create entries with the `security` command or Keychain Access.app:

```sh
security add-generic-password -s git.example.com -a alice -w 'the-token'
```

### Format

```properties
SECRET_NAME=keychain(SERVICE)            # any account matching service
SECRET_NAME=keychain(SERVICE|ACCOUNT)    # specific account
```

### Example

```properties
GIT_TOKEN=keychain(git.example.com|alice)
AWS_KEY=keychain(aws-prod)
```

---

## HashiCorp Vault Provider

Retrieves secrets from **HashiCorp Vault** (`vault`).

Uses the standard Vault client config — no extra setup needed:
- `VAULT_ADDR` — Vault server URL
- `VAULT_TOKEN` — auth token (or file token, AppRole, etc. via standard Vault env vars)
- `VAULT_NAMESPACE` — namespace for Vault Enterprise

### Format

```properties
SECRET_NAME=vault(PATH)                 # returns raw JSON or single-key value
SECRET_NAME=vault(PATH|field)           # extracts a named field
```

- **PATH** — full Vault path. For KV v2, include `data/` (e.g. `secret/data/myapp`)
- **field** — optional. If omitted and the secret has a single key, its value is returned; otherwise the full JSON object is returned.

### Example

```properties
# KV v2 mount at 'secret/'
DB_PASSWORD=vault(secret/data/myapp|password)
API_TOKEN=vault(secret/data/myapp|api_token)

# KV v1 mount
LEGACY_KEY=vault(kv/legacy/key)
```

---

## 1Password Provider

Retrieves secrets from **1Password** via the `op` CLI (`op`).

Requires the [1Password CLI](https://developer.1password.com/docs/cli/) installed and signed in (`op signin`).

### Format

```properties
SECRET_NAME=op(VAULT/ITEM)              # default `password` field
SECRET_NAME=op(VAULT/ITEM|field)        # named field (1Password-native, not JSON)
```

Under the hood this invokes `op read op://VAULT/ITEM/field`.

### Example

```properties
GITHUB_TOKEN=op(Personal/GitHub|token)
DB_PASS=op(Work/Production-DB|password)
```

---

## KeePass Provider

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


### Aliases

Aliases for KeePass databases for more flexibility. Aliases are defined in `aliases.yaml` and referenced with `&`.

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

### Chaining

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

## Configuration

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

## Build

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

# License
MIT © 2026 Georg Nelles
