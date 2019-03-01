use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub trustdns: Option<HashMap<String, DNS>>,
    pub ca: Option<HashMap<String, CA>>,
    pub service: Option<HashMap<String, Service>>,
    pub cert: Option<Vec<Cert>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CA {
    pub directory: Option<String>,
    pub account_email: String,
    pub account_key: String,
    pub key_types: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DNS {
    pub server: String,
    pub auth_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Service {
    pub reload_cmd: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Cert {
    pub zone: String,
    pub ca: Option<Vec<String>>, // ["letsencrypt", "ed25519-ca"]
    pub key_types: Option<Vec<String>>,
    pub pem_key: Option<bool>,
    pub dns: Option<String>,
    pub reload: Option<Vec<String>>,
    pub san: Vec<Domain>, // must be at the end, otherwise "ValueAfterTable" toml error
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Domain {
    pub name: String,
    pub tcp: Option<Vec<u16>>,
    pub udp: Option<Vec<u16>>,
}
impl Config {
    pub fn from_file(path: &str) -> Result<Config, Box<std::error::Error>> {
        let file = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&file)?;

        Ok(config)
    }
}
impl Domain {
    pub fn tcp(&self) -> &[u16] {
        match &self.tcp {
            Some(ports) => &ports,
            None => &[],
        }
    }
    pub fn udp(&self) -> &[u16] {
        match &self.udp {
            Some(ports) => &ports,
            None => &[],
        }
    }
}
impl CA {
    pub fn directory(&self) -> &str {
        match &self.directory {
            Some(v) => &v,
            None => "https://acme-v02.api.letsencrypt.org/directory",
        }
    }
}
