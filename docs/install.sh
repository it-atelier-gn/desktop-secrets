#!/usr/bin/env bash
set -euo pipefail

REPO="it-atelier-gn/desktop-secrets"

# Detect OS and arch
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)        ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

if [ "$OS" != "linux" ]; then
  echo "Unsupported OS: $OS" >&2
  exit 1
fi

INSTALL_DIR="${HOME}/.local/bin"
mkdir -p "$INSTALL_DIR"

echo "Fetching latest release..."
VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | grep '"tag_name"' \
  | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
echo "Installing DesktopSecrets $VERSION"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# Download SHA256SUMS
curl -fsSL "https://github.com/$REPO/releases/download/$VERSION/SHA256SUMS" \
  -o "$TMPDIR/SHA256SUMS"

for BIN in tplenv getsec; do
    FILENAME="${BIN}-${VERSION}-${OS}-${ARCH}"
    URL="https://github.com/$REPO/releases/download/$VERSION/$FILENAME"

    echo "Downloading $BIN..."
    curl -fsSL "$URL" -o "$TMPDIR/$FILENAME"

    # Verify checksum
    (cd "$TMPDIR" && grep "$FILENAME" SHA256SUMS | sha256sum -c --quiet)

    install -m 755 "$TMPDIR/$FILENAME" "$INSTALL_DIR/$BIN"
    echo "  -> $INSTALL_DIR/$BIN"
done

echo ""
echo "DesktopSecrets $VERSION installed successfully."

if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo ""
    echo "~/.local/bin is not in your PATH. Add this to your shell profile:"
    echo "  export PATH=\"\$PATH:$INSTALL_DIR\""
fi

echo ""
echo "Run 'tplenv --help' or 'getsec --help' to get started."
