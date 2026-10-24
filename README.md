# DesktopSecrets

![CI/CD Status](https://img.shields.io/github/actions/workflow/status/it-atelier-gn/desktop-secrets/ci.yml)
![Go](https://img.shields.io/github/go-mod/go-version/it-atelier-gn/desktop-secrets)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

DesktopSecrets is a utility that allows you to remove secrets from your filesystem by transforming them to *Secret References*. It integrates with various *Secret Providers* to make retrieving credentials simple, scriptable, and safe, while minimizing repeated password prompts through configurable caching. 

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

| Flag | Description |
|------|-------------|
| `--shell` | Shell syntax for the output: `auto`, `sh`, `pwsh` or `cmd` |
| `--format` | Output format: `env`, `json` or `raw` |
| `--only` | Comma-separated list of variables to include |
| `--exclude` | Comma-separated list of variables to exclude |
| `--apply-one-liner` | Print a command that loads the environment into the current shell, e.g. `tplenv --shell=pwsh env \| Invoke-Expression` |
| `--version` | Print version and revision |

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

## Retrieval Approvals

Choose in the tray menu under **Settings** how the daemon decides whether to hand out a secret:

| Mode | What happens on a retrieval |
|------|-----------------------------|
| Off (default) | No prompt. Any program running as you that can reach the daemon receives secrets once the vault is unlocked. |
| Standard | An Allow / Deny dialog for every retrieval that is not covered by a live grant. |
| Advanced *(Windows only)* | After Allow, Windows Hello or a hardware security key confirms the retrieval. |

When you pick **Advanced**, Windows Hello is checked once. If Windows Hello is not set up, you are asked to register a security key instead. To register a different key, delete `webauthn.cred` in the configuration directory; you are asked for a new one on the next retrieval.

### Minimum settings for all users

An administrator can set minimum settings that apply to every user of the computer. Users can choose stricter settings but not weaker ones; options below the minimum are shown as managed by your organization.

| Setting | Effect |
|---------|--------|
| Approval required | Every retrieval needs at least the Standard dialog. |
| Windows Hello or security key required *(Windows only)* | Every retrieval needs the Advanced mode. On other platforms this setting is ignored and noted in `daemon.log`. |
| Maximum unlock TTL | Vaults stay unlocked for at most this many minutes. |

To change them, open **Settings** and choose **Change minimum settings…**. Windows asks for administrator rights through UAC, Linux through `pkexec`.

The settings are stored where only administrators can write:

| Platform | Location |
|----------|----------|
| Windows | Registry key `HKLM\SOFTWARE\Policies\desktop-secrets`, can be distributed through group policy |
| Linux, macOS | `/etc/desktop-secrets/policy.yaml`, owned by root |

Registry values:

| Value | Type | Content |
|-------|------|---------|
| `RetrievalApproval` | DWORD | `1` to require approval |
| `MinApprovalFactor` | String | `os_local` to require Windows Hello or a security key, empty otherwise |
| `MaxUnlockTTL` | DWORD | Minutes, `0` for no limit |

`policy.yaml`:

```yaml
retrieval_approval: true
min_approval_factor: os_local
max_unlock_ttl: 60
```

The minimum settings take effect when the daemon starts and when they are changed in the settings window.

### Audit log

Every approval decision is written as one JSON line to `audit.log` in the configuration directory. On Windows, the same record also goes to the Windows **Application** event log under the source `desktop-secrets`, where users cannot delete it and event forwarding or a SIEM can collect it. Changes to the minimum settings are recorded there as well.

| Event ID | Level | Meaning |
|----------|-------|---------|
| 100 | Information | Retrieval allowed after the approval dialog |
| 101 | Information | Retrieval allowed by an existing grant |
| 200 | Warning | Retrieval denied |
| 201 | Warning | Retrieval denied and the cached secret forgotten |
| 202 | Warning | Vault unlock failed |
| 203 | Warning | Windows Hello or security key not confirmed |
| 300 | Information | Minimum settings changed |

The event source is registered the first time the minimum settings are changed. Before that, Event Viewer shows the events with a note that the description cannot be found; the record itself is still included.

## Background Daemon

The first `getsec` or `tplenv` call starts a daemon in the background. It keeps unlocked vaults for the configured TTL and keeps running after the terminal, IDE or tool that started it is closed. Its log is `daemon.log` in the configuration directory; at startup it records how the daemon was started and which attempts failed.

| Platform | How the daemon is started | Where to find it |
|----------|---------------------------|------------------|
| Windows | Directly, or through the Windows Task Scheduler when the calling program does not let its processes outlive it | Hidden task `desktop-secrets daemon <your SID>` in the root folder of the Task Scheduler library |
| Linux with a systemd user session | As its own systemd user service | `systemctl --user status desktop-secrets-daemon` |
| Linux without a systemd user session, macOS | In its own session, detached from the terminal | `daemon.log` |

On Windows, a daemon started through the Task Scheduler takes its environment from your Windows user profile, and the `DESKTOP_SECRETS_*` variables of the calling shell are passed on to it. Deleting the task is safe, it is recreated when needed. On Linux, the daemon receives the environment of the shell that started it.

To stop the daemon on Linux, run `systemctl --user stop desktop-secrets-daemon` or choose **Exit** in the tray menu.

If the daemon can only be started inside the caller's lifetime, it stops together with the calling program, and vaults have to be unlocked again on the next call. On Windows, `getsec` prints a warning and `daemon.log` contains a `warning:` line in that case. On Linux this happens when the caller runs inside a systemd unit that is stopped and no systemd user session is reachable, and always inside sandboxes with their own process namespace.

### Protection of cached secrets

Secrets the daemon keeps for the TTL are stored encrypted in its memory. For KeePass this covers the fields the database marks as protected, such as passwords; other fields such as user names and URLs are kept as plain text.

| Platform | Cached secrets | Access by other processes of your user |
|----------|----------------|----------------------------------------|
| Windows | Encrypted with a key held by Windows for this one process. A memory dump, for example "Create dump file" in Task Manager, contains no readable secret. | Reading or changing the daemon's memory is refused, so Task Manager and similar tools cannot create a dump of it. Ending the daemon from Task Manager or with `taskkill` works. |
| Linux | Encrypted with a key that is kept out of swap and core dumps. | Reading the daemon's memory through `/proc/<pid>/mem`, debuggers and core dumps is refused. |
| macOS | Encrypted with a key that is kept out of swap. | Core dumps are disabled. |

An administrator, root, or a process running with debug privileges can still read the daemon's memory. While a secret is being handed out, its plain value is briefly present in the daemon.

If the daemon cannot apply this protection, `daemon.log` contains a `warning:` line.

## Default Configuration Locations

- macOS: `~/Library/Application Support/desktop-secrets`
- Linux: `$XDG_CONFIG_HOME/desktop-secrets` or `~/.config/desktop-secrets`
- Windows: `%APPDATA%\desktop-secrets`

## Environment Overrides

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

### Tests

```sh
go test ./...
```

Windows Hello and security-key approvals need a real authenticator and are not covered by the tests. Check them by hand after changes to that code.

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
