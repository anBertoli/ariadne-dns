use crate::shared::dns;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::{fs, net};

/// Configuration values obtained parsing the configuration file.
#[derive(Debug, Serialize, Deserialize)]
pub struct Conf {
    pub log_level: log::Level,
    pub udp_server: UdpServerConf,
    pub tcp_server: TcpServerConf,
    pub zone: ZoneConf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UdpServerConf {
    pub address: String,
    pub port: u16,
    pub write_timeout: u64,
    pub threads: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TcpServerConf {
    pub address: String,
    pub port: u16,
    pub read_timeout: u64,
    pub write_timeout: u64,
    pub threads: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ZoneConf {
    pub starting_ttl: u32,
    pub zone: String,
    pub file: String,
    pub sub_zones: Vec<SubZoneConf>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubZoneConf {
    pub starting_ttl: u32,
    pub min_ttl: u32,
    pub zone: String,
    pub file: String,
}

impl Conf {
    /// Read and parse the configuration values from a file. The file must
    /// be JSON-encoded and follow the organization of the [Conf] struct.
    pub fn from_file(path: &str) -> Result<Self, String> {
        let file_bytes = match fs::read_to_string(path) {
            Err(err) => return Err(err.to_string()),
            Ok(v) => v,
        };
        let conf = match serde_json::from_str::<Self>(&file_bytes) {
            Err(err) => return Err(err.to_string()),
            Ok(conf) => conf,
        };
        match conf.validate() {
            Ok(_) => Ok(conf),
            Err(err) => Err(err),
        }
    }

    /// Validate a configuration struct against some common errors.
    fn validate(&self) -> Result<(), String> {
        // Udp server confs.
        if let Err(err) = net::IpAddr::from_str(self.udp_server.address.as_ref()) {
            return Err(format!("invalid udp address: {}", err));
        }
        if self.udp_server.write_timeout == 0 {
            return Err("invalid udp write timeout: 0 seconds".to_string());
        }
        if self.udp_server.threads == 0 {
            return Err("invalid udp threads: 0".to_string());
        }

        // Tcp server confs.
        if let Err(err) = net::IpAddr::from_str(self.tcp_server.address.as_ref()) {
            return Err(format!("invalid tcp address: {}", err));
        }
        if self.tcp_server.write_timeout == 0 {
            return Err("invalid tcp write timeout: cannot be 0 seconds".to_string());
        }
        if self.tcp_server.threads == 0 {
            return Err("invalid tcp threads: 0".to_string());
        }

        // Zone confs.
        if let Err(err) = dns::Name::from_string(&self.zone.zone) {
            return Err(format!("auth zone top node {} invalid: {:?}", self.zone.zone, err));
        }
        for sub_zone_conf in &self.zone.sub_zones {
            if let Err(err) = dns::Name::from_string(&sub_zone_conf.zone) {
                return Err(format!("sub zone top node {} invalid: {:?}", sub_zone_conf.zone, err));
            }
        }

        Ok(())
    }
}
