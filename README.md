# Bifrost Authentication

> A hardware-rooted, mutual-TLS TOTP authenticator — a C++20 terminal client paired with a Python Flask server that together establish a cryptographically-bound time-based one-time password (TOTP) secret without ever transmitting it in plaintext.

---

## Table of Contents

- [Description](#description)
- [Features](#features)
- [Architecture Overview](#architecture-overview)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [PKI Generation](#pki-generation)
  - [Login Server (Python)](#login-server-python)
  - [Bifrost Client (C++)](#bifrost-client-c)
- [Usage](#usage)
  - [Starting the Server](#starting-the-server)
  - [Registering a New Account](#registering-a-new-account)
  - [Generating TOTP Codes](#generating-totp-codes)
- [Configuration](#configuration)
- [Security Design](#security-design)
- [Contributing](#contributing)
- [Testing](#testing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## Description

**Bifrost** is a two-factor authentication system built from first principles. Rather than relying on a shared secret scanned via QR code, Bifrost derives a unique TOTP key for each account through a combination of **mutual TLS (mTLS)** and **HKDF key derivation** — binding the secret cryptographically to both the TLS session and a password-derived key material. The result is a secret that neither side ever transmits directly, and that is tied to the client's PKI identity.

The system consists of two components:

- **`bifrost/`** — A C++20 terminal client that performs mTLS registration, derives TOTP keys, and displays live rotating codes with a progress bar in the terminal.
- **`login-server/`** — A Python Flask web application that handles user signup, key exchange, and two-factor login verification.

---

## Features

**Client (`bifrost`)**

- **Mutual TLS registration** — connects to the login server using a client certificate issued by a private CA, enforcing bidirectional identity verification
- **TLS Exporter-based key binding** — uses `SSL_export_keying_material` (RFC 5705 / RFC 8446 §7.5) to bind the TOTP secret to the TLS session, not just the password
- **HKDF-SHA256 key derivation** — derives the final TOTP secret via HKDF (`RFC 5869`) combining the TLS exporter material and an Argon2id-derived password key
- **AES-256-GCM encrypted KeyStore** — all TOTP secrets are stored on-disk in an AES-256-GCM encrypted file, with the encryption key derived from a master password via PBKDF2-SHA256 (310,000 iterations per OWASP 2023)
- **SecureBytes allocator** — secrets in memory are zeroed via `OPENSSL_cleanse` on deallocation, preventing heap remnants
- **Live TOTP display** — renders all registered accounts with their current OTP, remaining validity, and a terminal progress bar, refreshing twice per second
- **`bifrost-totp://` custom URL scheme** — clicking a link on the signup page automatically launches the terminal and initiates registration
- **Cross-platform terminal launcher** — detects and launches `gnome-terminal`, `konsole`, `kitty`, `alacritty`, `xterm`, and others on Linux; uses AppleScript on macOS; `cmd.exe` on Windows
- **Hardened binary** — built with stack protector, full RELRO, BIND_NOW, PIE, and optional ASAN/UBSAN support

**Server (`login-server`)**

- **4-step web registration flow** — Signup → Key Exchange → Login → 2FA
- **mTLS server** — a dedicated background thread accepts Bifrost client connections on port 8443, validates client certificates, and performs the HKDF derivation server-side
- **Argon2id password key derivation** — generates `PW_KEY` from the user's password before it is used as HKDF salt
- **Single-use, time-limited exchange endpoints** — registration tokens expire in 5 minutes and are destroyed on first successful use
- **TOTP verification with clock-skew tolerance** — accepts codes from the current, previous, and next 30-second windows; uses constant-time comparison to prevent timing attacks
- **SQLite-backed user store** — via Flask-SQLAlchemy

---

## Architecture Overview

```
User browser                login-server (Flask, port 5000)
     │                              │
     │──── POST /signup ───────────▶│  creates ExchangeToken (PIN, PW_KEY, TTL=5min)
     │◀─── bifrost-totp:// URI ─────│
     │
     │  (click URI)
     ▼
bifrost client                login-server (mTLS, port 8443)
     │                              │
     │──── mTLS handshake ─────────▶│  verifies client cert against root CA
     │──── GET /signup/<PIN> ───────▶│
     │◀─── PW_KEY + ACC_INFO ────────│
     │
     │  both sides run:
     │  HKDF-SHA256(ikm = TLS_exporter_material,
     │              salt = PW_KEY,
     │              info = "bifrost-totp-key")
     │
     │  → identical 48-byte TOTP secret, never transmitted
     ▼
[KeyStore] secret encrypted with AES-256-GCM, key from PBKDF2(master password)
```

---

## Installation

### Prerequisites

**Client**
- CMake ≥ 3.28
- C++20-capable compiler (GCC ≥ 11 or Clang ≥ 13)
- OpenSSL ≥ 3.0 (development headers)
- `pkg-config`

**Server**
- Python ≥ 3.12
- OpenSSL library (shared, accessible via `ctypes.util.find_library("ssl")`)

**Both**
- Bash (for `generate_pki.sh` and `install.sh`)

---

### PKI Generation

Both components require a shared private CA. The included script generates a complete three-tier PKI (root CA → server chain → client chain):

```bash
# From the repository root
chmod +x generate_pki.sh
./generate_pki.sh
```

This will:

1. Create a self-signed **Root CA** (Ed25519)
2. Issue an **intermediate CA** signed by the root
3. Issue a **server certificate** (EC P-256) signed by the intermediate, placed in `login-server/pki/`
4. Issue a **client certificate** (EC P-256) for Bifrost, placed in `bifrost/certs/`

> **Note:** The generated PKI uses a private root CA intended for local development and testing. Do not use self-signed certificates in production without a proper trust model.

---

### Login Server (Python)

```bash
cd login-server

# Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

**Dependencies installed:**
- `Flask` 3.1.3, `Werkzeug` 3.1.7 — web framework
- `Flask-SQLAlchemy` 3.1.1, `SQLAlchemy` 2.0.51 — ORM / SQLite
- `argon2-cffi` 25.1.0 — Argon2id password key derivation

> **Python 3.12 note:** The server uses a `ctypes` workaround to call `SSL_export_keying_material` directly, as `ssl.SSLSocket.export_keying_material()` was only added in Python 3.13. If you upgrade to Python 3.13+, the `ctypes` workaround in `app.py` can be replaced with the native API.

---

### Bifrost Client (C++)

#### Option A — Automated install script (Linux, recommended)

```bash
cd bifrost
chmod +x install.sh

# Build and install to ~/.local/bin
./install.sh

# Optional: wipe the build directory first
./install.sh --clean

# Uninstall
./install.sh --uninstall
```

The script builds a Release binary, installs it to `~/.local/bin/bifrost`, registers the `bifrost-totp://` URL scheme via `.desktop` file (Linux), and copies certificates to `~/.config/bifrost/certs/`.

#### Option B — Manual CMake build

```bash
cd bifrost
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

The compiled binary will be at `build/src/bifrost`.

**CMake options:**

| Option | Default | Description |
|---|---|---|
| `BIFROST_BUILD_TESTS` | `OFF` | Build the test suite |
| `ENABLE_SANITIZERS` | `OFF` | Enable ASAN + UBSAN (Debug builds only) |

---

## Usage

### Starting the Server

```bash
cd login-server
source .venv/bin/activate

# Optional: set a stable secret key for session cookies
export FLASK_SECRET_KEY="your-secret-here"

# Optional: override the mTLS port (default: 8443)
export MTLS_PORT=8443

python app.py
```

The server starts two listeners:
- **HTTP** on port 5000 (Flask dev server) — the browser-facing registration UI
- **mTLS** on port 8443 — the Bifrost client registration endpoint

Open your browser to `http://localhost:5000` to begin.

---

### Registering a New Account

1. **Navigate** to `http://localhost:5000` and click **Sign Up**.

2. **Enter** a username and password. The server will:
   - Create a user record
   - Derive a `PW_KEY` using Argon2id
   - Generate a time-limited single-use exchange token (5-minute TTL)
   - Display a `bifrost-totp://` deep-link URI

3. **Click the URI** (or run it with `xdg-open` on Linux). Bifrost will:
   - Open a terminal window automatically
   - Prompt for your KeyStore master password
   - Connect to the mTLS server on port 8443
   - Complete the HKDF key derivation
   - Save the encrypted TOTP secret to `~/.config/bifrost/totp-secrets.keys`

4. **Return to the browser** and proceed through Login → 2FA using the code displayed in the terminal.

#### Manual registration (without URL scheme)

```bash
bifrost "bifrost-totp://host=localhost/signup/<PIN>&port=8443"
```

---

### Generating TOTP Codes

Once registration is complete, launch Bifrost at any time to view your live codes:

```bash
bifrost
```

The terminal will display each registered account with:
- The 6-digit TOTP code
- Remaining validity in seconds
- A visual progress bar
- Server certificate CN and fingerprint

Codes refresh every 500 ms. Press `Ctrl+C` to exit.

---

## Configuration

### Client

Bifrost looks for its configuration files under the XDG config directory:

| Platform | Config directory |
|---|---|
| Linux / BSD | `$XDG_CONFIG_HOME/bifrost/` (falls back to `~/.config/bifrost/`) |
| macOS | `~/Library/Application Support/bifrost/` |
| Windows | `%APPDATA%\bifrost\` |

Expected files:

```
<config_dir>/
├── certs/
│   ├── root-ca.crt          # Root CA certificate (trust anchor)
│   ├── bifrost-chain.pem    # Client certificate chain (leaf + intermediate)
│   └── bifrost.key          # Client private key
└── totp-secrets.keys        # AES-256-GCM encrypted KeyStore (created on first registration)
```

To use a non-default keystore file, pass it at runtime (see `Paths::setKeyfile`).

### Server

| Environment variable | Default | Description |
|---|---|---|
| `FLASK_SECRET_KEY` | `os.urandom(32)` | Session cookie signing key; set a stable value in production |
| `MTLS_PORT` | `8443` | Port for the mTLS Bifrost registration listener |

PKI paths (relative to `login-server/`):

```
pki/
├── root-ca/root-ca.crt       # Root CA (used to verify client certificates)
└── server/
    ├── server-chain.pem      # Server certificate chain
    └── server.key            # Server private key
```

If any PKI file is missing, the mTLS server will not start and a warning will be logged. The HTTP server continues running normally.

---

## Security Design

**Key derivation pipeline:**

```
user password
     │
     ▼ Argon2id (time=2, mem=64MB)
  PW_KEY (16 bytes)
     │
     │   TLS Exporter Material (48 bytes)
     │   RFC 5705 / RFC 8446 §7.5
     │   label: "bifrost-ms"
     ▼
HKDF-SHA256(ikm=exporter_material, salt=PW_KEY, info="bifrost-totp-key")
     │
     ▼
  TOTP secret (48 bytes) — stored encrypted on client, hashed on server
```

**KeyStore encryption:**

```
master password
     │
     ▼ PBKDF2-SHA256 (310,000 iterations, 16-byte salt)
  encryption key (32 bytes)
     │
     ▼ AES-256-GCM (96-bit random nonce, 128-bit auth tag)
  encrypted KeyStore blob
```

**Known limitations / planned improvements:**

- TOTP currently uses HMAC-SHA1 (RFC 6238 default). A migration to HMAC-SHA256 is noted in the source (`// TODO: SECURITY — SHA-1 is cryptographically weak`) and requires both sides to switch simultaneously.
- The Diffie-Hellman implementation in `login-server/utils/dh.py` uses a 50-bit prime and is explicitly marked for **demonstration/educational purposes only**. The production key exchange is performed through the TLS exporter mechanism described above.
- `ssl.VERIFY_X509_STRICT` is currently commented out on the server (`# ctx.verify_flags = ssl.VERIFY_X509_STRICT`) due to OpenSSL 3.x compatibility considerations.

---

## Contributing

Contributions are welcome. Please follow these guidelines:

1. **Fork** the repository and create a feature branch from `main`.

2. **Code style:**
   - C++: follow the existing style (C++20, no extensions, `-Wall -Wextra -Wpedantic`). Run with ASAN/UBSAN enabled (`-DENABLE_SANITIZERS=ON`) before submitting.
   - Python: PEP 8. Use type hints where the existing code does.

3. **Security-sensitive changes** (crypto primitives, TLS configuration, KeyStore format) require explicit justification and references to relevant RFCs or CVEs in the PR description.

4. **Do not break the mTLS handshake** — both sides must agree on the HKDF label (`"bifrost-ms"`), info (`"bifrost-totp-key"`, exactly 16 bytes, no null terminator), and output length.

5. Open an issue before starting large refactors or feature additions.

---

## Testing

### Client (C++)

The test suite is gated behind a CMake option:

```bash
cmake -S bifrost -B build \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBIFROST_BUILD_TESTS=ON \
    -DENABLE_SANITIZERS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

### Server (Python)

Run the server in debug mode with the Flask development server. For integration testing of the mTLS handshake, `generate_pki.sh` produces a ready-to-use PKI. The repository also includes a `test-handshake-fixed.sh` script (not shown in tree but referenced in development) that validates the mTLS PKI chain using `openssl s_server` / `openssl s_client`.

**Quick smoke test (manual):**

```bash
# 1. Start the server
cd login-server && python app.py

# 2. In a second terminal, test the mTLS endpoint directly
openssl s_client \
  -connect localhost:8443 \
  -cert bifrost/certs/bifrost-chain.pem \
  -key bifrost/certs/bifrost.key \
  -CAfile login-server/pki/root-ca/root-ca.crt \
  -verify_return_error
```

---

## License

This project does not currently specify a license. All rights reserved by the author unless otherwise noted. If you intend to use or adapt this code, please contact the repository owner.

---

## Acknowledgements

- [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) — TOTP: Time-Based One-Time Password Algorithm
- [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226) — HOTP: An HMAC-Based One-Time Password Algorithm
- [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- [RFC 5705](https://datatracker.ietf.org/doc/html/rfc5705) / [RFC 8446 §7.5](https://datatracker.ietf.org/doc/html/rfc8446#section-7.5) — TLS Keying Material Exporters
- [OpenSSL 3.x](https://www.openssl.org/) — TLS, AES-GCM, HKDF, PBKDF2, and X.509 implementations
- [argon2-cffi](https://argon2-cffi.readthedocs.io/) — Argon2id key derivation
- [Flask](https://flask.palletsprojects.com/) — Python web framework
- [System Design Handbook — How Google Authenticator Works](https://www.systemdesignhandbook.com/guides/how-google-authenticator-works-system-design/)
