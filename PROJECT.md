# DesktopSecrets

Lightweight desktop secret management utility with KeePass, Windows Credential Manager, and AWS integration. Centralizes credential retrieval for scripting and env templating.

**Module:** `github.com/it-atelier-gn/desktop-secrets`
**Go Version:** 1.26
**Repo:** `it-atelier-gn/desktop-secrets`

## Architecture

Client-daemon model. Client starts daemon if not running, communicates via HTTP on a random localhost port. Daemon runs as a persistent background process with a system tray icon (Fyne + systray). IPC discovery uses platform-specific shared memory (named pipes on Windows, mmap on Unix) to share `{Port, Token, PID}`.

## CLI Entry Points

- `cmd/tplenv/main.go` — Main tool. Finds `.env.tpl` files, resolves secrets via daemon, supports multiple output formats and running commands with resolved env.
- `cmd/getsec/main.go` — Resolves a single secret reference to stdout.
- `resolve.go` — Public library API: `Init()` and `ResolveSecret(ref string)`.

## Key Packages

| Package | Purpose |
|---|---|
| `internal/server/` | Daemon: HTTP server, system tray, secret resolution, app state |
| `internal/client/` | CLI client: daemon lifecycle, health checks, IPC, rendering |
| `internal/keepass/` | KeePass vault access, caching, path/wildcard matching, aliases |
| `internal/wincred/` | Windows Credential Manager access (Windows only; stub on other platforms) |
| `internal/aws/` | AWS Secrets Manager + Parameter Store (planned — see below) |
| `internal/user/` | Interactive user prompt manager with caching |
| `internal/shm/` | Platform-specific shared memory for IPC |
| `internal/config/` | Viper-based configuration init |
| `internal/prompt/` | GUI password dialogs |

## Secret Reference Syntax

| Expression | Provider | Description |
|---|---|---|
| `keepass(vault.kdbx\|/path/entry)` | KeePass | Entry from a .kdbx vault |
| `keepass(vault.kdbx\|entry\|UserName)` | KeePass | Specific attribute |
| `keepass(&alias\|entry)` | KeePass | Via alias from aliases.yaml |
| `keepass(vault[user(master)]\|entry)` | KeePass | Chained unlock |
| `wincred(target)` | Windows Credential Manager | Password field |
| `wincred(target\|username)` | Windows Credential Manager | Username field |
| `awssm(secret-id)` | AWS Secrets Manager | Full secret value *(planned)* |
| `awssm(secret-id\|json-key)` | AWS Secrets Manager | JSON field extraction *(planned)* |
| `awsps(parameter-name)` | AWS Parameter Store | Parameter value, always decrypted *(planned)* |
| `awsps(parameter-name\|json-key)` | AWS Parameter Store | JSON field extraction *(planned)* |
| `user(prompt title)` | Interactive prompt | GUI password dialog |

## Public Library API

```go
import desktopsecrets "github.com/it-atelier-gn/desktop-secrets"

func main() {
    if desktopsecrets.Init() { return }  // required — handles daemon re-launch
    secret, err := desktopsecrets.ResolveSecret("wincred(MyApp/DBPassword)")
}
```

`Init()` must be called at the top of `main()`. It detects if the process was re-launched as the daemon (`--daemon` flag) and handles it. Without it, `ResolveSecret` returns an error.

## Build

```powershell
go build -o tplenv.exe ./cmd/tplenv
go build -o getsec.exe ./cmd/getsec
```

## Config Locations (Windows)

`%APPDATA%\desktop-secrets\` — contains `config.yaml`, `aliases.yaml`, `keyfiles.yaml`.

## CI

`.github/workflows/ci.yml` — triggers on push to `main` or `v*` tags. Builds Windows+Linux amd64 binaries. On release tags, publishes to GitHub Releases with SHA256 checksums.

## GitHub Page

`docs/index.html` — landing page served via GitHub Pages. Contains: hero, features, providers overview, syntax reference, install scripts, download links.
Install scripts: `docs/install.ps1` (Windows), `docs/install.sh` (Linux).

---

## Planned: AWS Provider (`awssm` + `awsps`)

### Syntax

```properties
# AWS Secrets Manager — raw string secret
DB_PASSWORD=awssm(MyApp/DBPassword)

# AWS Secrets Manager — JSON field extraction
DB_USER=awssm(MyApp/DB|username)
DB_PASS=awssm(MyApp/DB|password)

# AWS Parameter Store — SecureString auto-decrypted
API_KEY=awsps(/myapp/prod/api-key)

# AWS Parameter Store — JSON field extraction
DB_HOST=awsps(/myapp/prod/db|host)
```

### Auth

Standard AWS credential chain — no custom config needed:
1. `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` env vars
2. `~/.aws/credentials` + `~/.aws/config` (default profile or `AWS_PROFILE`)
3. IAM instance roles / ECS task roles / Web Identity tokens

Region resolved from `AWS_DEFAULT_REGION` → `AWS_REGION` → `~/.aws/config`.

### Caching

Resolved values cached in-memory for the daemon's configured TTL (same setting as KeePass). Avoids repeated API calls and reduces cost.

### JSON Extraction

When a `|field` is provided, the raw secret/parameter value is parsed as JSON and the named key is extracted. If the value is not valid JSON, an error is returned.

### Implementation Plan

1. **`internal/aws/manager.go`** — `AWSManager` struct with:
   - `ResolveSecret(ctx, secretID, field)` — Secrets Manager
   - `ResolveParameter(ctx, name, field)` — Parameter Store
   - In-memory TTL cache (per resolved key, using sync.Map + expiry goroutine matching keepass pattern)
   - AWS SDK v2: `github.com/aws/aws-sdk-go-v2`
   - Lazy client init (load config on first call, not at daemon start)

2. **`internal/server/state.go`** — Add `AWSResolver` interface + `AWS` field to `AppState`

3. **`internal/server/env.go`** — Add `awssm(` and `awsps(` prefix detection and dispatch in `parseAndResolve` and `ResolveEnvLines`

4. **`internal/server/env_test.go`** — Add `fakeAWSResolver`, tests for both providers including JSON extraction and error cases

5. **`README.md`** + **`docs/index.html`** — Add AWS provider section and update providers grid

### Open Questions

- Should the cache be per `(service, secret-id)` or per fully resolved expression `awssm(MyApp/DB|username)`? → Per `(service, secret-id)` so the full JSON blob is cached once and multiple fields can be extracted from it cheaply.
- Error behaviour when AWS credentials are not configured: return a clear error (`AWS credentials not configured`) rather than hanging.
