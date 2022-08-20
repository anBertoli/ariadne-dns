use ariadne_dns::resolver::*;
use ariadne_dns::shared::log::{init_log, set_max_level};
use ariadne_dns::shared::net::*;
use colored::Colorize;
use std::sync::Arc;
use std::{env, process, time};

fn main() {
    init_log();

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        print_usage();
        process::exit(1);
    }

    let conf = match conf::Conf::from_file(&args[1]) {
        Ok(conf) => {
            set_max_level(conf.log_level);
            log::info!("Parsed configuration: {:?}.", conf);
            conf
        }
        Err(err) => {
            log::error!("Parsing configuration file: {}", err);
            process::exit(1);
        }
    };

    // Instantiate the resolver cache collecting all necessary
    // configuration values. Start a thread to clean the cache.
    let cache_conf = CacheConf {
        clean_period: time::Duration::new(conf.resolver.cache_conf.clean_period, 0),
        max_cleaned: conf.resolver.cache_conf.entries_cleaned,
    };
    let cache = Arc::new(Cache::new(cache_conf));
    cache.start_clean_routine();

    // Instantiate the resolver collecting all necessary configuration values.
    let resolver_conf = ResolverParams {
        max_ns_queried: conf.resolver.max_ns_queried,
        max_upd_retries: conf.resolver.max_ns_retries,
        max_cname_redir: conf.resolver.max_cname_redir,
        read_timeout: time::Duration::new(conf.resolver.read_timeout, 0),
        write_timeout: time::Duration::new(conf.resolver.write_timeout, 0),
        no_follow_cname: false,
    };
    let trace_conf = TraceParams {
        silent: conf.resolver.trace_conf.silent,
        verbose: conf.resolver.trace_conf.verbose,
        color: conf.resolver.trace_conf.color,
    };

    let resolver = Resolver::new(&cache, resolver_conf, trace_conf);
    let resolver_handler = ResolverHandler(resolver);
    let resolver_handler_ptr = Arc::new(resolver_handler);

    // Start the servers.
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

    start_servers(resolver_handler_ptr, udp_params, tcp_params);
}

fn print_usage() {
    log::error!(
        "One argument should be provided when starting the resolver: the path of the configuration file.
Usage: {} {}",
        "path/to/resolver/binary".bold(),
        "path/to/config/file".bold().bright_green()
    )
}
