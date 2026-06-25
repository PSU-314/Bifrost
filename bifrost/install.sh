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

echo "SCRIPT_DIR: $SCRIPT_DIR"

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
    update-desktop-database "$INSTALL_DESKTOP_DIR" 2>/dev/null || true
    log "Uninstalled successfully."
    exit 0
fi

# ---- Optional clean ------------------------------------------------------
if [[ "${1:-}" == "--clean" ]]; then
    log "Cleaning previous build directory..."
    rm -rf "$SCRIPT_DIR/$BUILD_DIR"
fi

# ---- Build -------------------------------------------------------------
log "Configuring CMake build ($BUILD_TYPE)..."
cmake -S "$SCRIPT_DIR" -B "$SCRIPT_DIR/$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX"

log "Building $PROJECT_NAME..."
cmake --build "$SCRIPT_DIR/$BUILD_DIR" --parallel "$(nproc)"

BUILT_BINARY="$SCRIPT_DIR/$BUILD_DIR/src/$BINARY_NAME"
if [[ ! -f "$BUILT_BINARY" ]]; then
    err "Expected built binary at $BUILT_BINARY but it wasn't found."
    err "Check that BINARY_NAME matches your CMake target's output name."
    exit 1
fi

log "Installing $PROJECT_NAME (Binaries & Desktop file)"
cmake --install "$SCRIPT_DIR/$BUILD_DIR"

# ---- Install binary ---------------------------------------------------
log "Installing binary to $INSTALL_BIN_DIR ..."
mkdir -p "$INSTALL_BIN_DIR"
install -m 755 "$BUILT_BINARY" "$INSTALL_BIN_DIR/$BINARY_NAME"

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

# # ---- Install desktop file (with path rewritten to the installed binary) ---
# log "Installing desktop file to $INSTALL_DESKTOP_DIR ..."
# mkdir -p "$INSTALL_DESKTOP_DIR"
#
# # Rewrite the Exec= line so it points at the installed binary location,
# # regardless of what path was hardcoded in the source .desktop file.
# sed -e "s|^Exec=.*|Exec=$INSTALL_BIN_DIR/$BINARY_NAME %u|" \
#     "$SCRIPT_DIR/$DESKTOP_FILE_NAME" > "$INSTALL_DESKTOP_DIR/$DESKTOP_FILE_NAME"
#
# chmod 644 "$INSTALL_DESKTOP_DIR/$DESKTOP_FILE_NAME"
#
# # ---- Validate desktop file (best-effort) -------------------------------
# if command -v desktop-file-validate >/dev/null 2>&1; then
#     log "Validating desktop file..."
#     desktop-file-validate "$INSTALL_DESKTOP_DIR/$DESKTOP_FILE_NAME" || true
# fi

# ---- Refresh desktop database and register protocol -----------------------
log "Refreshing desktop database..."
update-desktop-database "$INSTALL_PREFIX/share/applications" 2>/dev/null || true

log "Registering $MIME_SCHEME -> $DESKTOP_FILE_NAME as default handler..."
xdg-mime default "$DESKTOP_FILE_NAME" "$MIME_SCHEME"

log "Done."
echo
echo "  Binary:       $INSTALL_BIN_DIR/$BINARY_NAME"
echo "  Desktop file: $INSTALL_DESKTOP_DIR/$DESKTOP_FILE_NAME"
echo "  Protocol:     $MIME_SCHEME"
echo
echo "Test with:  xdg-open 'bifrost-totp://test'"
echo "Uninstall:  ./install.sh --uninstall"
