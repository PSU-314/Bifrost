#!/usr/bin/env bash
#
# install.sh — Build and install Bifrost (user-local, no sudo required)
#
# What this does:
#   1. Configures and builds the project with CMake (Release, out-of-source in build/)
#   2. Installs the resulting binary to ~/.local/bin
#   3. Installs the .desktop file to ~/.local/share/applications
#   4. Refreshes the desktop database and registers the bifrost-totp:// scheme
#
# Usage:
#   ./install.sh            # build + install
#   ./install.sh --clean    # wipe build/ first, then build + install
#   ./install.sh --uninstall # remove installed files

set -euo pipefail

# ---- Configuration (edit these to match your repo) -------------------------
PROJECT_NAME="bifrost"
BINARY_NAME="bifrost"          # CMake target / output binary name
DESKTOP_FILE_NAME="bifrost-authentication.desktop"
MIME_SCHEME="x-scheme-handler/bifrost-totp"
BUILD_DIR="build"
BUILD_TYPE="Release"
# ------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_PREFIX="$HOME/.local"
INSTALL_BIN_DIR="$INSTALL_PREFIX/bin"
INSTALL_DESKTOP_DIR="$INSTALL_PREFIX/share/applications"
CONFIG_DIR="$HOME/.config/$PROJECT_NAME"

OS="$(uname -s)"

log()  { echo -e "\033[1;34m[install]\033[0m $*"; }
err()  { echo -e "\033[1;31m[error]\033[0m $*" >&2; }

# ---- System Dependency Check -------------------------------------------
command -v cmake >/dev/null 2>&1 || { err "cmake not found."; exit 1; }
command -v pkg-config >/dev/null 2>&1 || { err "pkg-config not found."; exit 1; }

# ---- Uninstall path ----------------------------------------------------
if [[ "${1:-}" == "--uninstall" ]]; then
    log "Removing installed binary, desktop file, configs, and protocol registration..."
    rm -f "$INSTALL_BIN_DIR/$BINARY_NAME"
    rm -f "$INSTALL_DESKTOP_DIR/$DESKTOP_FILE_NAME"
    rm -rf "$CONFIG_DIR"
    if [[ "$OS" == "Linux" ]]; then
        update-desktop-database "$INSTALL_DESKTOP_DIR" 2>/dev/null || true
    fi
    log "Uninstalled successfully."
    exit 0
fi

# ---- Optional clean ------------------------------------------------------
if [[ "${1:-}" == "--clean" ]]; then
    log "Cleaning previous build directory..."
    rm -rf "$SCRIPT_DIR/$BUILD_DIR"
fi

# ── Parallel job count (cross-platform) ──────────────────────────────────────
if [[ "$OS" == "Darwin" ]]; then
    JOBS="$(sysctl -n hw.logicalcpu)"
else
    JOBS="$(nproc)"
fi

# ---- Build -------------------------------------------------------------
log "Configuring CMake build ($BUILD_TYPE)..."
cmake -S "$SCRIPT_DIR" -B "$SCRIPT_DIR/$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX"

log "Building $PROJECT_NAME..."
cmake --build "$SCRIPT_DIR/$BUILD_DIR" --parallel "$JOBS"

BUILT_BINARY="$SCRIPT_DIR/$BUILD_DIR/src/$BINARY_NAME"
if [[ ! -f "$BUILT_BINARY" ]]; then
    err "Expected built binary at $BUILT_BINARY but it wasn't found."
    err "Check that BINARY_NAME matches your CMake target's output name."
    exit 1
fi

log "Installing $PROJECT_NAME (Binaries & Desktop file)"
cmake --install "$SCRIPT_DIR/$BUILD_DIR"

# ---- Install certificates ---------------------------------------------
log "Installing certificates to $CONFIG_DIR/certs ..."
install -d -m 700 "$CONFIG_DIR/certs"

for cert in "$SCRIPT_DIR/certs/"*.crt "$SCRIPT_DIR/certs/"*.pem; do
    if [[ -f "$cert" ]]; then
        install -m 444 "$cert" "$CONFIG_DIR/certs/"
    fi
done

for key in "$SCRIPT_DIR/certs/"*.key; do
    if [[ -f "$key" ]]; then
        install -m 400 "$key" "$CONFIG_DIR/certs/"
    fi
done

# ── Register MIME / URL scheme ────────────────────────────────────────────────
if [[ "$OS" == "Linux" ]]; then
    log "Refreshing desktop database..."
    update-desktop-database "$INSTALL_DESKTOP_DIR" 2>/dev/null || true

    log "Registering $MIME_SCHEME -> $DESKTOP_FILE_NAME ..."
    xdg-mime default "$DESKTOP_FILE_NAME" "$MIME_SCHEME"
elif [[ "$OS" == "Darwin" ]]; then
    # macOS URL scheme registration requires an app bundle with Info.plist
    # CFBundleURLTypes. A plain binary cannot register URL schemes on macOS
    # without going through LaunchServices. No automated registration is
    # possible here; instruct the user.
    log "macOS: URL scheme registration requires an app bundle."
    log "Add 'bifrost-totp' to CFBundleURLTypes in your Info.plist and run:"
    log "  /System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f <YourApp.app>"
fi

log "Done."
echo
echo "  Binary  : $INSTALL_BIN_DIR/$BINARY_NAME"
echo "  Desktop : $INSTALL_DESKTOP_DIR/$DESKTOP_FILE_NAME  (Linux)"
echo "  Protocol: $MIME_SCHEME  (Linux)"
echo
echo "Test (Linux): xdg-open 'bifrost-totp://test'"
echo "Uninstall   : ./install.sh --uninstall"
