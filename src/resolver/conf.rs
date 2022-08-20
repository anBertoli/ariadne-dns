use serde::{Deserialize, Serialize};
use std::fs;
use std::net;
use std::str::FromStr;

/// Configuration values obtained parsing the configuration file.
#[derive(Debug, Serialize, Deserialize)]
pub struct Conf {
    pub log_level: log::Level,
    pub udp_server: UdpServerConf,
    pub tcp_server: TcpServerConf,
    pub resolver: ResolverConf,
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
pub struct ResolverConf {
    pub max_ns_queried: usize,
    pub max_ns_retries: usize,
    pub max_cname_redir: usize,
    pub read_timeout: u64,
    pub write_timeout: u64,
    pub cache_conf: CacheConf,
    pub trace_conf: TraceConf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CacheConf {
    pub clean_period: u64,
    pub entries_cleaned: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TraceConf {
    pub silent: bool,
    pub verbose: bool,
    pub color: bool,
}

impl Conf {
    /// Read and parse the configuration values from a file. The file must
    /// be JSON-encoded and follow the organization of the [Conf] struct.
    pub fn from_file(path: &str) -> Result<Self, String> {
        let file_bytes = match fs::read_to_string(path) {
            Err(err) => return Err(err.to_string()),
            Ok(v) => v,
        };
        let conf = match serde_json::from_str::<Conf>(&file_bytes) {
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

        // Resolver confs.
        if self.resolver.max_ns_queried == 0 {
            return Err("invalid 'max_ns_queried' resolver param: cannot be 0".to_string());
        }
        if self.resolver.max_ns_retries == 0 {
            return Err("invalid 'max_ns_retries' resolver param: cannot be 0".to_string());
        }
        if self.resolver.max_cname_redir == 0 {
            return Err("invalid 'max_cname_redir' resolver param: cannot be 0".to_string());
        }
        if self.resolver.read_timeout == 0 || self.resolver.write_timeout == 0 {
            return Err("invalid resolver write/read timeouts: cannot be 0".to_string());
        }

        // Cache confs.
        if self.resolver.cache_conf.clean_period == 0 {
            return Err("invalid 'clean_period' cache param: cannot be 0".to_string());
        }
        if self.resolver.cache_conf.entries_cleaned == 0 {
            return Err("invalid 'entries_cleaned' cache param: cannot be 0".to_string());
        }

        Ok(())
    }
}
