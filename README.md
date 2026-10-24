# DesktopSecrets

![CI/CD Status](https://img.shields.io/github/actions/workflow/status/it-atelier-gn/desktop-secrets/ci.yml)
![Go](https://img.shields.io/github/go-mod/go-version/it-atelier-gn/desktop-secrets)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

DesktopSecrets keeps secrets out of your files. You write *secret references* such as `keepass(C:\Vaults\cloud.kdbx|api-key)` instead of the secret itself, and `tplenv` or `getsec` resolve them when they are needed. Unlocked vaults stay open for a time you choose, so you are not asked for the master password on every call.

Download `getsec` and `tplenv` for Windows or Linux from the [releases page](https://github.com/it-atelier-gn/desktop-secrets/releases).

## Commands

| Command | What it does |
|---------|--------------|
| `tplenv` | Reads every `.env.tpl*` file in the current directory and prints the resolved environment |
| `tplenv run CMD ARGS…` | Runs a command with the resolved variables set |
| `getsec 'NAME=REFERENCE'` | Resolves the references passed as arguments and prints `NAME=value` |

```properties
# .env.tpl
DATABASE_URL=postgresql://localhost:5432/mydb
API_SECRET=keepass($USERPROFILE\Credentials.kdbx|api-key)
```

`$VAR` and `${VAR}` are replaced with variables from your environment before secrets are resolved. Resolved secret values are passed on unchanged, even when they contain `$`.

| `tplenv` flag | Description |
|---------------|-------------|
| `--shell` | Output syntax: `auto`, `sh`, `pwsh` or `cmd` |
| `--format` | Output format: `env`, `json` or `raw` |
| `--only` | Comma-separated variables to include |
| `--exclude` | Comma-separated variables to exclude |
| `--apply-one-liner` | Print a command that loads the environment into the current shell, e.g. `tplenv --shell=pwsh env \| Invoke-Expression` |
| `--version` | Print version and revision |

Values are quoted for the selected shell, so the output is safe for `eval` or `Invoke-Expression`. `cmd.exe` cannot hold values that span several lines; such variables are left out of the `cmd` output with a message on stderr. Use `tplenv run` for them.

## Providers

| Reference | Source | Sign-in |
|-----------|--------|---------|
| `keepass(VAULT\|ENTRY[\|ATTRIBUTE])` | KeePass `.kdbx` file, see [KeePass](#keepass) | Master password, keyfile or another reference |
| `user(PROMPT)` | Value typed into a dialog | – |
| `wincred(TARGET[\|username])` | Windows Credential Manager *(Windows)* | Your Windows logon |
| `keychain(SERVICE[\|ACCOUNT])` | macOS login keychain *(macOS)* | Your macOS logon |
| `awssm(SECRET[\|FIELD])` | AWS Secrets Manager | AWS credential chain: environment, `~/.aws`, `AWS_PROFILE`, instance and task roles |
| `awsps(PARAMETER[\|FIELD])` | AWS Parameter Store, SecureStrings decrypted | as above |
| `azkv(VAULT/NAME[\|FIELD])` | Azure Key Vault; `VAULT` may also be the full vault URL | Environment, managed identity, `az login`, Azure PowerShell or `azd` |
| `gcpsm(PROJECT/NAME[/VERSION][\|FIELD])` | Google Cloud Secret Manager; latest version by default | Application Default Credentials, e.g. `gcloud auth application-default login` |
| `vault(PATH[\|FIELD])` | HashiCorp Vault; KV v2 paths include `data/` | `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE` |
| `op(VAULT/ITEM[\|FIELD])` | 1Password; `password` field by default | [1Password CLI](https://developer.1password.com/docs/cli/) signed in |

`FIELD` picks a key from a secret stored as JSON. For `vault`, a secret with a single key returns its value and otherwise the whole JSON. For `op`, `FIELD` is a 1Password field name.

```properties
DB_PASS=awssm(MyApp/DB|password)
API_KEY=awsps(/myapp/prod/api-key)
DB_PASSWORD=azkv(mykv/db-password)
TOKEN=gcpsm(my-project/api-key/3)
APP_TOKEN=vault(secret/data/myapp|api_token)
GITHUB_TOKEN=op(Personal/GitHub|token)
DB_USER=wincred(MyApp/DBPassword|username)
GIT_TOKEN=keychain(git.example.com|alice)
OTP=user(Enter one-time code)
```

Values from `user` and the cloud providers are kept for the same time as unlocked vaults.

## KeePass

| Entry | Matches |
|-------|---------|
| `api-key` | An entry titled `api-key` in any group |
| `/AWS/Prod/api-key` | Exactly this path |
| `/AWS/*/api-key` | One group level in place of `*` |
| `/AWS/**/api-key` | Any number of group levels in place of `**` |
| `/AWS/Prod/My\/Key` | An entry titled `My/Key` |

The third part selects the attribute: `UserName`, `URL`, `Notes` or a custom field, case-sensitive. Without it, `Password` is returned.

**Aliases** name a database in `aliases.yaml` and are referenced with `&`. An alias can carry a `master` reference that unlocks it without a prompt:

```yaml
personal: C:\Vaults\personal.kdbx
cloud:
  file: C:\Vaults\cloud.kdbx
  master: keepass(&personal|Cloud Master Password)
```

```properties
MAPS_API_KEY=keepass(&cloud|/Google/Prod/api-key)
```

**Chaining** unlocks a database with a secret from any provider, written in brackets after the vault:

```properties
SECRET=keepass(C:\Vaults\a.kdbx[wincred(VaultA)]|/Prod/api-key)
```

Aliases and keyfiles can also be edited in the tray menu under **Aliases…** and **Keyfiles…**. **Cached secrets…** lists what is unlocked and lets you forget it.

## Retrieval approvals

Choose in the tray menu under **Settings** whether the daemon asks before handing out a secret:

| Mode | On every retrieval without a live grant |
|------|-----------------------------------------|
| Off (default) | No prompt |
| Standard | Allow / Deny dialog |
| Advanced *(Windows)* | Allow / Deny, then Windows Hello or a security key |

If Windows Hello is not set up, Advanced asks you to register a security key. To register a different key, delete `webauthn.cred` in the configuration directory.

### Minimum settings for all users

An administrator can set minimum settings for every user of the computer through **Settings › Change minimum settings…**; Windows asks for administrator rights through UAC, Linux through `pkexec`. Users can choose stricter settings, not weaker ones.

| Setting | Registry value (DWORD/String) | `policy.yaml` key | Effect |
|---------|-------------------------------|-------------------|--------|
| Approval required | `RetrievalApproval` = `1` | `retrieval_approval: true` | At least Standard |
| Windows Hello or security key required | `MinApprovalFactor` = `os_local` | `min_approval_factor: os_local` | Advanced; ignored outside Windows and noted in `daemon.log` |
| Maximum unlock TTL | `MaxUnlockTTL` = minutes | `max_unlock_ttl: 60` | Upper limit for how long vaults and cached secrets stay unlocked; `0` for none |

| Platform | Location |
|----------|----------|
| Windows | `HKLM\SOFTWARE\Policies\desktop-secrets`, can be distributed through group policy |
| Linux, macOS | `/etc/desktop-secrets/policy.yaml`, owned by root |

The daemon reads them at startup and when they are changed in the settings window.

### Audit log

Every approval decision is written to `audit.log` in the configuration directory. On Windows it also goes to the **Application** event log under the source `desktop-secrets`, where event forwarding or a SIEM can collect it.

| Event ID | Level | Meaning |
|----------|-------|---------|
| 100 | Information | Allowed in the dialog |
| 101 | Information | Allowed by an existing grant |
| 200 | Warning | Denied |
| 201 | Warning | Denied and the cached secret forgotten |
| 202 | Warning | Vault unlock failed |
| 203 | Warning | Windows Hello or security key not confirmed |
| 300 | Information | Minimum settings changed |

Until the minimum settings are changed for the first time, Event Viewer shows these events with a note that the description cannot be found; the record is still included.

## Background daemon

The first `getsec` or `tplenv` call starts a daemon with a tray icon. It keeps unlocked vaults for the chosen time and keeps running after the terminal or IDE that started it is closed. Choose **Exit** in the tray menu to stop it.

| Platform | Started | Where to find it |
|----------|---------|------------------|
| Windows | Directly, or through the Task Scheduler when the calling program would end it, without a console window | Hidden task `desktop-secrets daemon <your SID>`; deleting it is safe |
| Linux with systemd user session | As a user service | `systemctl --user status desktop-secrets-daemon` |
| Linux without it, macOS | Detached from the terminal | `daemon.log` |

A daemon started through the Task Scheduler takes its environment from your Windows profile plus the `DESKTOP_SECRETS_*` variables of the calling shell. If the daemon can only run as long as the calling program, `getsec` warns and `daemon.log` contains a `warning:` line; vaults then have to be unlocked again on the next call.

Cached secrets are kept encrypted in the daemon's memory. On Windows and Linux, other processes of your user cannot read that memory or create a dump of it; administrators and root still can. For KeePass this covers the fields the database marks as protected, such as passwords.

## Configuration

| Platform | Directory |
|----------|-----------|
| Windows | `%APPDATA%\desktop-secrets` |
| Linux | `$XDG_CONFIG_HOME/desktop-secrets` or `~/.config/desktop-secrets` |
| macOS | `~/Library/Application Support/desktop-secrets` |

| Variable | Overrides the path of |
|----------|-----------------------|
| `DESKTOP_SECRETS_CONFIG_FILE` | `config.yaml` |
| `DESKTOP_SECRETS_ALIASES_FILE` | `aliases.yaml` |
| `DESKTOP_SECRETS_KEYFILES_FILE` | `keyfiles.yaml` |

## License

MIT © 2026 Georg Nelles
