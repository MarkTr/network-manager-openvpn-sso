# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NetworkManager VPN plugin that adds OAuth 2.0/OIDC Single Sign-On support for OpenVPN connections. Consists of two components:
1. **Rust D-Bus service** (`src/`) — the core daemon that implements the NetworkManager VPN plugin protocol
2. **KDE Plasma UI plugin** (`plasma-nm-plugin/`) — optional C++17/Qt6 frontend for KDE NetworkManager configuration

## Commands

### Rust service
```sh
cargo build --release          # build the daemon binary
cargo test                     # run all tests
cargo fmt --all -- --check     # check formatting
cargo clippy --all-features -- -D warnings  # lint (warnings are errors)
cargo audit                    # security audit of dependencies
```

### KDE Plasma plugin (optional)
```sh
cmake -B build plasma-nm-plugin/
cmake --build build
```

### Install everything (requires root)
```sh
sudo ./install.sh   # builds + installs service, D-Bus policy, and KDE plugin if deps present
sudo ./uninstall.sh
```

System build dependencies: `libdbus-1-dev`, `libssl-dev`, `pkg-config`, `libgtk-4-dev`, `libadwaita-1-dev` (the last two build the `nm-openvpn-sso-auth-dialog` GNOME password-prompt binary — see below). KDE plugin additionally requires Qt6, KDE Frameworks 6 (CoreAddons, I18n, KIOWidgets, NetworkManagerQt), and extra-cmake-modules.

## Architecture

The Rust service is single-binary (`nm-openvpn-sso-service`) with a Tokio async runtime. The high-level data flow when a VPN connection is initiated:

```
NetworkManager
    └─ D-Bus (dbus.rs) ← implements NMVpnPlugin interface
         └─ openvpn.rs  ← spawns OpenVPN process, drives management interface
              ├─ config.rs  ← parses connection settings from NM D-Bus format
              ├─ oauth.rs   ← browser-based OAuth 2.0/OIDC flow via loopback callback server
              └─ secrets.rs ← caches tokens in libsecret keyring (file fallback at /var/lib/nm-openvpn-sso/)
```

### Key design points

- **D-Bus service name:** `org.freedesktop.NetworkManager.openvpn-sso` at `/org/freedesktop/NetworkManager/VPN/Plugin`
- **Event bus:** `openvpn.rs` emits `VpnEvent` variants over an `mpsc` channel; `dbus.rs` processes them in its event loop
- **SSO trigger:** When the OpenVPN management interface sends an `>AUTH` message containing a URL, `oauth.rs` opens it in a browser, starts a local HTTP server (axum) to capture the callback, then passes the resulting auth token back through the management socket
- **Token caching:** `secrets.rs` stores `StoredTokens` (access + refresh token, expiry) in the system keyring under collection `nm-openvpn-sso`; on reconnect the cached token bypasses the browser flow if still valid (with a 60 s expiry buffer)
- **Hybrid password-then-SSO:** connections with `vpn.data["requires-password"] = "true"` (`ConnectionConfig.requires_password`) need a real login before the SSO challenge. `dbus.rs`'s `need_secrets` returns `"vpn"` when no password is available yet, which makes GNOME Shell exec the `nm-openvpn-sso-auth-dialog` binary (`src/bin/auth_dialog.rs`, a GTK4/libadwaita dialog) per NetworkManager's standard VPN auth-dialog protocol — declared via `[GNOME] auth-dialog=` in `data/nm-openvpn-sso-service.name`. The collected username/password flow back through `vpn.secrets`, and `openvpn.rs` sends them for real (no placeholder) at the first `>PASSWORD:...Need...` prompt. Everything downstream (SSO challenge detection, browser flow, token caching) is unchanged; pure-SSO connections (`requires-password` unset) never touch this path.
- **Logging:** `tracing` with journald sink (`RUST_LOG` to override, defaults to INFO)

### KDE Plasma plugin

The C++ plugin (`plasma-nm-plugin/`) is a shared library loaded by `plasma-nm`. It provides three widgets:
- `OpenVpnSsoSettingWidget` — edits VPN connection settings (config file path, server overrides)
- `OpenVpnSsoAuthWidget` — shows SSO status during an active authentication
- `OpenVpnSsoUiPlugin` — factory + import/export of `.ovpn` profiles

The plugin communicates with the Rust service only through NetworkManager's standard D-Bus VPN plugin interface; there is no direct IPC between the two.

## CI

GitHub Actions runs on push/PR to `main`: `check` → `fmt` → `clippy` → `build` → `test` → `cargo-audit`. The release pipeline (tag `v*`) produces `.deb`, `.rpm`, `.pkg.tar.zst`, and a generic tarball.
