package version

// Set these via build flags: -ldflags "-X desktopsecrets/internal/version.Version=... -X desktopsecrets/internal/version.desktopsecrets.Revision=..."
var (
	Version  = "dev"
	Revision = "0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d0e0f0a0b"
)
