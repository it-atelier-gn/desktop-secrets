# 🔐 DesktopSecrets

> 🚀 A powerful system for the seamless retrieval of secrets on your development machine. DesktopSecrets conveniently provides access to secrets for your locally running software.

DesktopSecrets will automatically start when one of the clients is used for the first time. A tray icon allows you to easily control the system.

#### ✨ Features

- 🔑 **KeePass Integration** – Seamlessly fetch secrets from KeePass vaults.
- 💾 **Smart Caching** – Unlocked vaults stay accessible for a configurable duration.
- ⚙️ **Easy Configuration** – GUI settings menu in the taskbar icon.

---

## ⚙️ Configuration

Access settings via the **taskbar icon menu**.

**Configuration Location:**
- The `DESKTOP_SECRETS_CONFIG_FILE` environment variable, or if not present,
- The executable directory file name `config.yaml`.


## 🚀 Clients

### 🛠️ *getsec*

A command-line client for DesktopSecrets that allows to retrieve secrets defined as command-line arguments.

#### Basic Usage

```shell
getsec "API_SECRET=keepass($USERPROFILE\Credentials.kdbx|dev-api-secret)" "CLOUD_KEY=keepass(&cloud|Live Token)"
```

### 📄*tplenv*

A command-line client for DesktopSecrets that allows to retrieve secrets defined in a `.env` template file.

####  Basic Usage

Create a `.env.tpl` file with secret links:

```properties
DATABASE_URL=postgresql://localhost:5432/mydb
API_SECRET=keepass($USERPROFILE\Credentials.kdbx|dev-api-secret)
LOG_LEVEL=debug
```

Run `tplenv` to output the content of the `.env.tpl` file with the retrieved secrets.

---

## 🔌 Secret Providers

Secret providers are components that allow DesktopSecrets to retrieve secrets from various sources.

#### 🔑 KeePass Provider

Ask the user to provide the master password of the given vault and retrieve the given secret.

##### Link Format

```properties
SECRET_NAME=keepass(VAULT|SECRET_TITLE)
```

##### Aliases

Define system-wide aliases for cleaner configuration:

Example:

```yaml
cloud: C:\Project\ABC\Vaults\cloud-secrets.kdbx
local: C:\Users\User\Vaults\local-secrets.kdbx
```

**Alias Configuration Locations:**
- The `DESKTOP_SECRETS_ALIASES_FILE` environment variable, or if not present,
- The executable directory file name `aliases.yaml`.

#### 👤 User Provider

##### Link Format

Ask the user to provide a password with the given title.

```properties
SECRET_NAME=user(title)
```

## 🛠️ Build

##### Prerequisites

- Ensure Go is installed and set up.

##### Build from Source

**Standard build:**

```bash
go build -o tplenv.exe ./cmd/tplenv
go build -o getsec.exe ./cmd/getsec
```
