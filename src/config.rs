// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Pegasus Heavy Industries LLC

//! Connection configuration parsing and management

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use zbus::zvariant::OwnedValue;

/// VPN connection settings extracted from NetworkManager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionConfig {
    /// Unique connection identifier (used for keyring storage)
    pub uuid: String,
    /// Human-readable connection name
    pub id: String,
    /// Path to the .ovpn configuration file (None for NM-imported connections)
    pub config_path: Option<PathBuf>,
    /// Optional server override
    pub remote: Option<String>,
    /// Optional port override
    pub port: Option<u16>,
    /// Optional protocol override (udp/tcp)
    pub protocol: Option<String>,
    /// Username for initial auth (placeholder for SSO)
    pub username: Option<String>,
    /// Password for initial auth (placeholder for SSO)
    pub password: Option<String>,
    /// Additional OpenVPN arguments
    pub extra_args: Vec<String>,
    /// CA certificate path (from vpn.data "ca")
    pub ca: Option<String>,
    /// Client certificate path (from vpn.data "cert")
    pub cert: Option<String>,
    /// Client key path (from vpn.data "key")
    pub key: Option<String>,
    /// TLS auth key path (from vpn.data "ta")
    pub ta: Option<String>,
    /// TLS auth key direction (from vpn.data "ta-dir")
    pub ta_dir: Option<String>,
    /// Cipher algorithm (from vpn.data "cipher")
    pub cipher: Option<String>,
    /// Auth/digest algorithm (from vpn.data "auth")
    pub auth: Option<String>,
    /// Tunnel device type (from vpn.data "dev")
    pub dev: Option<String>,
    /// Remote cert TLS check (from vpn.data "remote-cert-tls")
    pub remote_cert_tls: Option<String>,
    /// Connection type: tls, password, etc. (from vpn.data "connection-type")
    pub connection_type: Option<String>,
    /// Whether this server requires a real username/password login before
    /// the SSO/OAuth challenge (from vpn.data "requires-password", default false)
    pub requires_password: bool,
}

impl ConnectionConfig {
    /// Parse connection settings from NetworkManager D-Bus format
    /// The format is a{sa{sv}} - dict of setting-name -> dict of key -> variant
    pub fn from_nm_settings(
        settings: &HashMap<String, HashMap<String, OwnedValue>>,
    ) -> Result<Self> {
        // Extract connection section
        let connection = settings
            .get("connection")
            .ok_or_else(|| anyhow!("Missing 'connection' settings section"))?;

        let uuid = get_string(connection, "uuid")?;
        let id = get_string(connection, "id").unwrap_or_else(|_| "OpenVPN SSO".to_string());

        // Extract VPN section
        let vpn = settings
            .get("vpn")
            .ok_or_else(|| anyhow!("Missing 'vpn' settings section"))?;

        // Get VPN data (nested dict)
        let vpn_data = get_string_dict(vpn, "data").unwrap_or_default();

        let config_path = vpn_data.get("config").map(PathBuf::from);

        // Parse individual NM settings (used when config_path is None)
        let ca = vpn_data.get("ca").cloned();
        let cert = vpn_data.get("cert").cloned();
        let key = vpn_data.get("key").cloned();
        let ta = vpn_data.get("ta").cloned();
        let ta_dir = vpn_data.get("ta-dir").cloned();
        let cipher = vpn_data.get("cipher").cloned();
        let auth = vpn_data.get("auth").cloned();
        let dev = vpn_data.get("dev").cloned();
        let remote_cert_tls = vpn_data.get("remote-cert-tls").cloned();
        let connection_type = vpn_data.get("connection-type").cloned();
        let requires_password = vpn_data
            .get("requires-password")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);

        // Validate: need either a config file or at least a CA cert
        if config_path.is_none() && ca.is_none() {
            return Err(anyhow!(
                "Missing OpenVPN config: need either vpn.data.config path or vpn.data.ca certificate"
            ));
        }

        let remote = vpn_data.get("remote").cloned();
        let port = vpn_data.get("port").and_then(|p| p.parse().ok());
        let protocol = vpn_data.get("proto").cloned();

        // Get secrets section for password (and a live-entered username, which
        // takes priority over a static vpn.data username when present — the
        // auth-dialog for requires_password connections writes both back as secrets)
        let vpn_secrets = get_string_dict(vpn, "secrets").unwrap_or_default();
        let password = vpn_secrets.get("password").cloned();
        // NetworkManager has a dedicated top-level "user-name" property on the "vpn"
        // setting (a sibling of "data"/"secrets", NM_SETTING_VPN_USER_NAME) — for
        // connection-type=password connections it routes the auth-dialog's collected
        // username there instead of leaving it in vpn.secrets, so it must take
        // priority over both fallbacks or the username is silently lost.
        let username = get_string(vpn, "user-name")
            .ok()
            .or_else(|| vpn_secrets.get("user-name").cloned())
            .or_else(|| vpn_secrets.get("username").cloned())
            .or_else(|| vpn_data.get("username").cloned());

        Ok(Self {
            uuid,
            id,
            config_path,
            remote,
            port,
            protocol,
            username,
            password,
            extra_args: Vec::new(),
            ca,
            cert,
            key,
            ta,
            ta_dir,
            cipher,
            auth,
            dev,
            remote_cert_tls,
            connection_type,
            requires_password,
        })
    }

    /// Whether NetworkManager still needs to fetch a real password (and username)
    /// from the user/secret-agent before Connect can proceed. Always false when
    /// `requires_password` is false — a strict superset of the pure-SSO behavior.
    pub fn needs_password_secrets(&self) -> bool {
        self.requires_password && self.password.as_deref().map(str::is_empty).unwrap_or(true)
    }

    /// Build OpenVPN command line arguments
    pub fn build_openvpn_args(&self, management_socket: &str) -> Vec<String> {
        let mut args = Vec::new();

        if let Some(ref config_path) = self.config_path {
            // .ovpn file mode: use --config
            args.extend([
                "--config".to_string(),
                config_path.to_string_lossy().to_string(),
            ]);
        } else {
            // NM-imported mode: build from individual settings
            args.extend([
                "--client".to_string(),
                "--nobind".to_string(),
                "--dev".to_string(),
                self.dev.clone().unwrap_or_else(|| "tun".to_string()),
                "--persist-key".to_string(),
                // Deliberately NOT --persist-tun: it keeps the tun/tap device alive
                // across the openvpn process's own internal restarts (SIGUSR1,
                // --ping-restart) by design, but this plugin has no per-connection
                // tracking of the assigned device name to clean it up afterward — so
                // with this flag, the interface silently outlives the process on any
                // exit path (explicit disconnect from the NM GUI, a lost connection,
                // a crash), leaving a dangling tunX device behind. NetworkManager
                // expects to fully own the interface's lifecycle for the connections
                // it manages, so let openvpn tear its device down on exit as normal.
                "--resolv-retry".to_string(),
                "infinite".to_string(),
                // Every connection this plugin drives expects a live username/password
                // prompt over the management interface (--management-query-passwords,
                // below) — whether that's the SSO placeholder or a real hybrid-auth
                // password. Without this, and with no --cert/--key/--pkcs12 configured,
                // OpenVPN refuses to start at all: "No client-side authentication
                // method is specified." Raw .ovpn files (--config mode) typically
                // already declare this themselves; NM-imported individual-field
                // connections don't unless we add it here.
                "--auth-user-pass".to_string(),
            ]);

            if let Some(ref ca) = self.ca {
                args.extend(["--ca".to_string(), ca.clone()]);
            }
            if let Some(ref cert) = self.cert {
                args.extend(["--cert".to_string(), cert.clone()]);
            }
            if let Some(ref key) = self.key {
                args.extend(["--key".to_string(), key.clone()]);
            }
            if let Some(ref ta) = self.ta {
                args.push("--tls-auth".to_string());
                args.push(ta.clone());
                if let Some(ref dir) = self.ta_dir {
                    args.push(dir.clone());
                }
            }
            if let Some(ref cipher) = self.cipher {
                args.extend(["--cipher".to_string(), cipher.clone()]);
            }
            if let Some(ref auth) = self.auth {
                args.extend(["--auth".to_string(), auth.clone()]);
            }
            if let Some(ref remote_cert_tls) = self.remote_cert_tls {
                args.extend(["--remote-cert-tls".to_string(), remote_cert_tls.clone()]);
            }
        }

        // Common: management interface
        args.extend([
            "--management".to_string(),
            management_socket.to_string(),
            "unix".to_string(),
            "--management-query-passwords".to_string(),
            "--management-hold".to_string(),
            "--script-security".to_string(),
            "2".to_string(),
            // Required for server-side SSO plugins (e.g. openvpn-auth-oauth2): --push-peer-info
            // alone does NOT advertise SSO capability — IV_SSO must be set explicitly, and only
            // then does --push-peer-info transmit it. Without it, the server has no way to know
            // this client can do a browser-based flow and falls back to its legacy/non-SSO auth
            // path (e.g. a CRV1 challenge) instead of returning an auth URL challenge. Most .ovpn
            // files don't set this themselves; OpenVPN3-based clients set it automatically.
            "--setenv".to_string(),
            "IV_SSO".to_string(),
            "webauth".to_string(),
            "--push-peer-info".to_string(),
        ]);

        // Common: apply overrides
        if let Some(ref remote) = self.remote {
            // NM stores remotes as comma-separated "host:port:proto" or "host:port" entries.
            // Each entry becomes a separate --remote host port [proto] argument.
            for entry in remote.split(',') {
                let parts: Vec<&str> = entry.trim().split(':').collect();
                match parts.as_slice() {
                    [host, port, proto] => args.extend([
                        "--remote".to_string(),
                        host.to_string(),
                        port.to_string(),
                        proto.to_string(),
                    ]),
                    [host, port] => {
                        args.extend(["--remote".to_string(), host.to_string(), port.to_string()])
                    }
                    [host] => args.extend(["--remote".to_string(), host.to_string()]),
                    _ => {}
                }
            }
        }

        if let Some(port) = self.port {
            args.extend(["--port".to_string(), port.to_string()]);
        }

        if let Some(ref proto) = self.protocol {
            args.extend(["--proto".to_string(), proto.clone()]);
        }

        args.extend(self.extra_args.clone());

        args
    }
}

fn get_string(dict: &HashMap<String, OwnedValue>, key: &str) -> Result<String> {
    dict.get(key)
        .ok_or_else(|| anyhow!("Missing key: {}", key))
        .and_then(|v| {
            // Try to extract string from the variant value
            // zvariant stores strings as Str or String types
            let s = v.to_string();
            // Remove quotes if present (zvariant's Display adds them)
            let trimmed = s.trim_matches('"');
            if !trimmed.is_empty() {
                Ok(trimmed.to_string())
            } else {
                Err(anyhow!("Key {} is not a string or is empty", key))
            }
        })
}

fn get_string_dict(
    dict: &HashMap<String, OwnedValue>,
    key: &str,
) -> Option<HashMap<String, String>> {
    use tracing::info;
    use zbus::zvariant::Value;

    dict.get(key).and_then(|v| {
        let mut result = HashMap::new();
        // The "secrets" dict holds real credentials — never log its contents,
        // only that parsing happened, to avoid leaking cleartext passwords.
        let is_secret = key == "secrets";

        // Log the raw value for debugging
        info!(
            "Parsing vpn.data key '{}', raw value type: {:?}",
            key,
            v.value_signature()
        );

        // Try to access as Dict<String, String> using Value
        let value: Value = v.clone().into();
        if is_secret {
            info!("Converted to Value variant: <redacted>");
        } else {
            info!("Converted to Value variant: {:?}", value);
        }

        // Try as Dict
        if let Value::Dict(dict_val) = &value {
            for (k, v_inner) in dict_val.iter() {
                // k and v_inner are &Value
                if let (Value::Str(key_str), Value::Str(val_str)) = (k, v_inner) {
                    result.insert(key_str.to_string(), val_str.to_string());
                }
            }
        }

        // Fallback: try parsing from string representation
        if result.is_empty() {
            let s = v.to_string();
            if is_secret {
                info!("Trying string parse from: <redacted>");
            } else {
                info!("Trying string parse from: {}", s);
            }

            // Format from NetworkManager is often "key = value, key2 = value2"
            // when converted to string
            for pair in s.split(", ") {
                if let Some((k, val)) = pair.split_once(" = ") {
                    let k = k.trim().trim_matches('"');
                    let val = val.trim().trim_matches('"');
                    if !k.is_empty() && !val.is_empty() {
                        result.insert(k.to_string(), val.to_string());
                    }
                }
            }
        }

        if is_secret {
            info!(
                "Parsed vpn.{} result: <redacted, {} keys>",
                key,
                result.len()
            );
        } else {
            info!("Parsed vpn.{} result: {:?}", key, result);
        }

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zbus::zvariant::Value;

    fn str_value(s: &str) -> OwnedValue {
        OwnedValue::try_from(Value::from(s.to_string())).unwrap()
    }

    fn dict_value(map: HashMap<String, String>) -> OwnedValue {
        OwnedValue::from(map)
    }

    fn settings_with(
        vpn_data: &[(&str, &str)],
        vpn_secrets: &[(&str, &str)],
    ) -> HashMap<String, HashMap<String, OwnedValue>> {
        let mut connection = HashMap::new();
        connection.insert("uuid".to_string(), str_value("test-uuid"));
        connection.insert("id".to_string(), str_value("Test VPN"));

        let mut data: HashMap<String, String> = vpn_data
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        // Every fixture needs either a config path or a CA cert to pass validation.
        data.entry("ca".to_string())
            .or_insert_with(|| "/etc/test-ca.pem".to_string());

        let secrets: HashMap<String, String> = vpn_secrets
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        let mut vpn = HashMap::new();
        vpn.insert("data".to_string(), dict_value(data));
        if !secrets.is_empty() {
            vpn.insert("secrets".to_string(), dict_value(secrets));
        }

        let mut settings = HashMap::new();
        settings.insert("connection".to_string(), connection);
        settings.insert("vpn".to_string(), vpn);
        settings
    }

    #[test]
    fn requires_password_defaults_to_false_when_absent() {
        let settings = settings_with(&[], &[]);
        let config = ConnectionConfig::from_nm_settings(&settings).unwrap();
        assert!(!config.requires_password);
    }

    #[test]
    fn requires_password_parses_truthy_and_falsy_values() {
        for (raw, expected) in [
            ("true", true),
            ("TRUE", true),
            ("1", true),
            ("false", false),
            ("0", false),
            ("garbage", false),
        ] {
            let settings = settings_with(&[("requires-password", raw)], &[]);
            let config = ConnectionConfig::from_nm_settings(&settings).unwrap();
            assert_eq!(config.requires_password, expected, "input {:?}", raw);
        }
    }

    #[test]
    fn username_falls_back_to_vpn_data_when_no_secret_present() {
        let settings = settings_with(&[("username", "static-user")], &[]);
        let config = ConnectionConfig::from_nm_settings(&settings).unwrap();
        assert_eq!(config.username, Some("static-user".to_string()));
    }

    #[test]
    fn username_secret_overrides_vpn_data_username() {
        let settings = settings_with(
            &[("username", "static-user")],
            &[("username", "live-user"), ("password", "s3cret")],
        );
        let config = ConnectionConfig::from_nm_settings(&settings).unwrap();
        assert_eq!(config.username, Some("live-user".to_string()));
        assert_eq!(config.password, Some("s3cret".to_string()));
    }

    #[test]
    fn top_level_vpn_user_name_takes_priority_over_secrets_and_data() {
        let mut settings = settings_with(
            &[("username", "static-user")],
            &[("username", "secrets-user"), ("password", "s3cret")],
        );
        settings
            .get_mut("vpn")
            .unwrap()
            .insert("user-name".to_string(), str_value("mark"));
        let config = ConnectionConfig::from_nm_settings(&settings).unwrap();
        assert_eq!(config.username, Some("mark".to_string()));
        assert_eq!(config.password, Some("s3cret".to_string()));
    }

    #[test]
    fn falls_back_when_top_level_vpn_user_name_absent() {
        let settings = settings_with(&[("username", "static-user")], &[]);
        let config = ConnectionConfig::from_nm_settings(&settings).unwrap();
        assert_eq!(config.username, Some("static-user".to_string()));
    }

    #[test]
    fn falls_back_to_hyphenated_user_name_secret_before_username_secret() {
        let settings = settings_with(
            &[("username", "static-user")],
            &[("user-name", "hyphen-user"), ("username", "no-hyphen-user")],
        );
        let config = ConnectionConfig::from_nm_settings(&settings).unwrap();
        assert_eq!(config.username, Some("hyphen-user".to_string()));
    }

    #[test]
    fn username_is_none_when_neither_source_has_it() {
        let settings = settings_with(&[], &[]);
        let config = ConnectionConfig::from_nm_settings(&settings).unwrap();
        assert_eq!(config.username, None);
    }

    #[test]
    fn needs_password_secrets_is_false_superset_when_not_required() {
        let settings = settings_with(&[], &[]);
        let mut config = ConnectionConfig::from_nm_settings(&settings).unwrap();
        assert!(!config.needs_password_secrets());

        config.password = Some("anything".to_string());
        assert!(!config.needs_password_secrets());
    }

    #[test]
    fn needs_password_secrets_truth_table() {
        let settings = settings_with(&[("requires-password", "true")], &[]);
        let mut config = ConnectionConfig::from_nm_settings(&settings).unwrap();
        assert!(config.password.is_none());
        assert!(config.needs_password_secrets());

        config.password = Some(String::new());
        assert!(config.needs_password_secrets());

        config.password = Some("real-password".to_string());
        assert!(!config.needs_password_secrets());
    }

    fn base_config() -> ConnectionConfig {
        ConnectionConfig {
            uuid: "test-uuid".to_string(),
            id: "Test VPN".to_string(),
            config_path: Some(PathBuf::from("/etc/openvpn/test.ovpn")),
            remote: None,
            port: None,
            protocol: None,
            username: None,
            password: None,
            extra_args: Vec::new(),
            ca: None,
            cert: None,
            key: None,
            ta: None,
            ta_dir: None,
            cipher: None,
            auth: None,
            dev: None,
            remote_cert_tls: None,
            connection_type: None,
            requires_password: false,
        }
    }

    #[test]
    fn build_openvpn_args_nm_imported_mode_includes_auth_user_pass() {
        let mut config = base_config();
        config.config_path = None;
        config.ca = Some("/etc/openvpn/ca.pem".to_string());
        let args = config.build_openvpn_args("/tmp/sock");
        assert!(
            args.iter().any(|a| a == "--auth-user-pass"),
            "NM-imported connections need --auth-user-pass or OpenVPN refuses to start \
             with no --cert/--key/--pkcs12 configured either"
        );
    }

    #[test]
    fn build_openvpn_args_nm_imported_mode_omits_persist_tun() {
        let mut config = base_config();
        config.config_path = None;
        config.ca = Some("/etc/openvpn/ca.pem".to_string());
        let args = config.build_openvpn_args("/tmp/sock");
        assert!(
            !args.iter().any(|a| a == "--persist-tun"),
            "--persist-tun keeps the tun device alive after the openvpn process exits, \
             but this plugin has no way to clean it up afterward, leaving a dangling \
             interface on disconnect or a lost connection"
        );
    }

    #[test]
    fn build_openvpn_args_includes_push_peer_info() {
        let args = base_config().build_openvpn_args("/tmp/sock");
        assert!(args.iter().any(|a| a == "--push-peer-info"));
    }

    #[test]
    fn build_openvpn_args_advertises_iv_sso_webauth() {
        let args = base_config().build_openvpn_args("/tmp/sock");
        let idx = args
            .iter()
            .position(|a| a == "--setenv")
            .expect("--setenv IV_SSO webauth must be present");
        assert_eq!(&args[idx + 1..idx + 3], &["IV_SSO", "webauth"]);
    }

    #[test]
    fn build_openvpn_args_splits_multi_remote_host_port_proto() {
        let mut config = base_config();
        config.remote = Some("vpn.example.com:1194:udp, vpn2.example.com:443:tcp".to_string());
        let args = config.build_openvpn_args("/tmp/sock");

        let remote_positions: Vec<usize> = args
            .iter()
            .enumerate()
            .filter(|(_, a)| *a == "--remote")
            .map(|(i, _)| i)
            .collect();
        assert_eq!(remote_positions.len(), 2);
        assert_eq!(
            &args[remote_positions[0] + 1..remote_positions[0] + 4],
            &["vpn.example.com", "1194", "udp"]
        );
        assert_eq!(
            &args[remote_positions[1] + 1..remote_positions[1] + 4],
            &["vpn2.example.com", "443", "tcp"]
        );
    }

    #[test]
    fn build_openvpn_args_handles_host_port_only() {
        let mut config = base_config();
        config.remote = Some("vpn.example.com:1194".to_string());
        let args = config.build_openvpn_args("/tmp/sock");

        let idx = args.iter().position(|a| a == "--remote").unwrap();
        assert_eq!(&args[idx + 1..idx + 3], &["vpn.example.com", "1194"]);
    }

    #[test]
    fn build_openvpn_args_handles_host_only() {
        let mut config = base_config();
        config.remote = Some("vpn.example.com".to_string());
        let args = config.build_openvpn_args("/tmp/sock");

        let idx = args.iter().position(|a| a == "--remote").unwrap();
        assert_eq!(&args[idx + 1], "vpn.example.com");
    }
}
