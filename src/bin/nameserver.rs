use ariadne_dns::nameserver::conf::ZoneConf;
use ariadne_dns::nameserver::*;
use ariadne_dns::shared::net::{start_servers, TcpParams, UdpParams};
use ariadne_dns::shared::{dns, log};
use std::sync::Arc;
use std::{env, process, time};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        log::init_log(log::LogLevel::Debug);
        print_usage();
        process::exit(1);
    }

    // Process configuration file.
    let conf = match conf::Conf::from_file(&args[1]) {
        Ok(conf) => {
            log::init_log(conf.log_level);
            log::info!("Configuration parsed: {:?}.", conf);
            conf
        }
        Err(err) => {
            log::init_log(log::LogLevel::Debug);
            log::error!("Parsing configuration file: {}", err);
            process::exit(1);
        }
    };

    let parsing_params = process_zones_confs(&conf.zone);
    let zones = match parse_zone_files(parsing_params) {
        Ok(v) => v,
        Err(err) => {
            log::error!("Parsing zone files: {:?}", err);
            process::exit(1);
        }
    };

    // Instantiate the nameserver handler and start the servers.
    let nameserver_handler = NameserverHandler(zones);
    let nameserver_handler_arc = Arc::new(nameserver_handler);

    let udp_params = UdpParams {
        address: conf.udp_server.address,
        port: conf.udp_server.port,
        write_timeout: time::Duration::new(conf.udp_server.write_timeout, 0),
        threads: conf.udp_server.threads,
    };
    let tcp_params = TcpParams {
        address: conf.tcp_server.address,
        port: conf.tcp_server.port,
        write_timeout: time::Duration::new(conf.tcp_server.write_timeout, 0),
        read_timeout: time::Duration::new(conf.tcp_server.read_timeout, 0),
        threads: conf.tcp_server.threads,
    };

    start_servers(nameserver_handler_arc, udp_params, tcp_params);
}

fn process_zones_confs(zone_conf: &ZoneConf) -> ParsingParams {
    let sub_zone_params: Vec<SubParsingParams> = zone_conf
        .sub_zones
        .iter()
        .map(|sub_zone_conf| SubParsingParams {
            file_path: sub_zone_conf.file.clone(),
            zone: dns::Name::from_string(&sub_zone_conf.zone).unwrap(),
            starting_ttl: sub_zone_conf.starting_ttl,
            min_ttl: sub_zone_conf.min_ttl,
        })
        .collect();

    ParsingParams {
        file_path: zone_conf.file.clone(),
        zone: dns::Name::from_string(&zone_conf.zone).unwrap(),
        starting_ttl: zone_conf.starting_ttl,
        sub_zones: sub_zone_params,
    }
}

fn print_usage() {
    log::error!(
        "One argument should be provided when starting the resolver: the path of the configuration file.
    Usage: {} {}",
        "path/to/resolver/binary".bold(),
        "path/to/config/file".bold().bright_green()
    )
}
