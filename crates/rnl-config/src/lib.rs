//! Configuration schema. Unknown settings are rejected, never ignored.

use std::path::Path;

use serde::{Deserialize, Serialize};

use rnl_core::Error;

pub const DEFAULT_MTU: u16 = 1380;
pub const DEFAULT_KEEPALIVE_SECS: u64 = 25;
pub const DEFAULT_REKEY_SECS: u64 = 600;
pub const DEFAULT_REKEY_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub server: ServerSection,
    #[serde(default)]
    pub security: SecuritySection,
    #[serde(default)]
    pub transports: TransportsSection,
    #[serde(default)]
    pub session: SessionSection,
    pub clients: Vec<ClientEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    pub listen: String,
    pub port: u16,
    #[serde(default = "default_interface")]
    pub interface: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// UDP worker shards (SO_REUSEPORT). Defaults to available cores.
    pub workers: Option<usize>,
}

fn default_interface() -> String {
    "rnl0".into()
}
fn default_mtu() -> u16 {
    DEFAULT_MTU
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0".into(),
            port: 443,
            interface: default_interface(),
            mtu: DEFAULT_MTU,
            workers: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SecuritySection {
    pub protocol_version: u32,
    pub cipher: String,
    pub handshake: String,
    pub replay_window: u32,
    /// Optional hex PSK (64 hex chars). Omit for the all-zero PSK.
    pub psk: Option<String>,
}

impl Default for SecuritySection {
    fn default() -> Self {
        Self {
            protocol_version: 1,
            cipher: "chacha20-poly1305".into(),
            handshake: "noise-ik".into(),
            replay_window: 4096,
            psk: None,
        }
    }
}

impl SecuritySection {
    /// Only the frozen v1 suite is accepted.
    pub fn validate(&self) -> Result<(), Error> {
        if self.protocol_version != 1
            || self.cipher != "chacha20-poly1305"
            || self.handshake != "noise-ik"
            || self.replay_window != 4096
        {
            return Err(Error::Config(
                "only the fixed v1 suite is supported: version 1, chacha20-poly1305, noise-ik, replay_window 4096".into(),
            ));
        }
        Ok(())
    }

    pub fn psk_bytes(&self) -> Result<[u8; 32], Error> {
        match &self.psk {
            None => Ok(rnl_crypto::ZERO_PSK),
            Some(s) => {
                let v = hex::decode(s.trim().strip_prefix("0x").unwrap_or(s.trim()))
                    .map_err(|_| Error::Config("psk must be 64 hex chars".into()))?;
                v.try_into()
                    .map_err(|_| Error::Config("psk must be exactly 32 bytes".into()))
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TransportsSection {
    pub udp: bool,
    pub tcp: bool,
    pub sctp: bool,
    pub preferred: String,
    pub fallback: bool,
    /// TCP listen port; TCP is enabled when tcp=true and this is set.
    pub tcp_port: Option<u16>,
    /// Endpoint advertised to clients for the TCP fallback carrier.
    /// Defaults to the UDP listen host + tcp_port.
    pub tcp_advertise: Option<String>,
}

impl Default for TransportsSection {
    fn default() -> Self {
        Self {
            udp: true,
            tcp: false,
            sctp: false,
            preferred: "udp".into(),
            fallback: true,
            tcp_port: None,
            tcp_advertise: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SessionSection {
    pub keepalive_seconds: u64,
    pub rekey_seconds: u64,
    pub rekey_bytes: u64,
}

impl Default for SessionSection {
    fn default() -> Self {
        Self {
            keepalive_seconds: DEFAULT_KEEPALIVE_SECS,
            rekey_seconds: DEFAULT_REKEY_SECS,
            rekey_bytes: DEFAULT_REKEY_BYTES,
        }
    }
}

/// An authorized client: static X25519 public key (hex) plus metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientEntry {
    pub id: String,
    pub public_key: String,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub client: ClientSection,
    #[serde(default)]
    pub security: SecuritySection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSection {
    /// Server endpoint as "host:port".
    pub server: String,
    /// Client static private key, hex (64 chars).
    pub private_key: String,
    #[serde(default = "default_interface")]
    pub interface: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// TCP fallback endpoint; overrides the server-advertised one when set.
    #[serde(default)]
    pub fallback_server: Option<String>,
}

impl ClientConfig {
    pub fn private_key_bytes(&self) -> Result<[u8; 32], Error> {
        let v = hex::decode(self.client.private_key.trim())
            .map_err(|_| Error::Config("private_key must be 64 hex chars".into()))?;
        v.try_into()
            .map_err(|_| Error::Config("private_key must be exactly 32 bytes".into()))
    }
}

impl ServerConfig {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let cfg: ServerConfig =
            toml::from_str(s).map_err(|e| Error::Config(format!("invalid server config: {e}")))?;
        cfg.security.validate()?;
        for c in &cfg.clients {
            let k = hex::decode(c.public_key.trim())
                .map_err(|_| Error::Config(format!("client {}: public_key must be hex", c.id)))?;
            if k.len() != 32 {
                return Err(Error::Config(format!(
                    "client {}: public_key must be 32 bytes",
                    c.id
                )));
            }
        }
        Ok(cfg)
    }

    pub fn load(path: &Path) -> Result<Self, Error> {
        let s = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
        Self::parse(&s)
    }
}

impl ClientConfig {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let cfg: ClientConfig =
            toml::from_str(s).map_err(|e| Error::Config(format!("invalid client config: {e}")))?;
        cfg.security.validate()?;
        Ok(cfg)
    }

    pub fn load(path: &Path) -> Result<Self, Error> {
        let s = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
        Self::parse(&s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example_server_config() {
        let s = r#"
[server]
listen = "0.0.0.0"
port = 443
interface = "rnl0"
mtu = 1380

[security]
protocol_version = 1
cipher = "chacha20-poly1305"
handshake = "noise-ik"
replay_window = 4096

[transports]
udp = true

[session]
keepalive_seconds = 25

[[clients]]
id = "laptop"
public_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
enabled = true
"#;
        let cfg = ServerConfig::parse(s).unwrap();
        assert_eq!(cfg.server.port, 443);
        assert_eq!(cfg.clients.len(), 1);
    }

    #[test]
    fn rejects_unknown_fields() {
        let s = r#"
[server]
listen = "0.0.0.0"
port = 443
wat = 1
[[clients]]
id = "x"
public_key = "aa"
"#;
        assert!(ServerConfig::parse(s).is_err());
    }

    #[test]
    fn rejects_unsupported_suite() {
        let s = r#"
[server]
listen = "0.0.0.0"
port = 443
[security]
cipher = "aes-gcm"
[[clients]]
id = "x"
public_key = "aa"
"#;
        assert!(ServerConfig::parse(s).is_err());
    }
}
