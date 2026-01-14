package version

// Set these via build flags: -ldflags "-X desktopsecrets/internal/version.Version=... -X desktopsecrets/internal/version.desktopsecrets.Revision=..."
var (
	Version  = "dev"
	Revision = "unknown"
)
