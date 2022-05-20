use crate::shared::log;
use crate::shared::net::tcp_server::*;
use crate::shared::net::traits::*;
use crate::shared::net::udp_server::*;
use std::io::Write;
use std::sync::{atomic, mpsc, Arc};
use std::{net, thread, time};

/// Setup and start UDP and TCP dns servers. Every server runs in its own
/// thread, when one of them errors or exits, the current thread is notified
/// and also the other server is teared down.
pub fn start_servers<H: DnsHandler>(handler: Arc<H>, udp_params: UdpParams, tcp_params: TcpParams) {
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(atomic::AtomicBool::new(false));

    // Setup udp parameters and spawn the udp server in a new thread.
    let udp_params_clone = udp_params.clone();
    let handler_clone = Arc::clone(&handler);
    let stop_clone = Arc::clone(&stop);
    let tx_clone = tx.clone();
    thread::spawn(move || {
        start_udp_server(handler_clone, udp_params_clone, &stop_clone);
        log::warn!("UDP server shut down.");
        tx_clone.send(()).unwrap();
    });

    // Setup tcp parameters and spawn the tcp server in a new thread.
    let tcp_params_clone = tcp_params.clone();
    let handler_clone = Arc::clone(&handler);
    let stop_clone = Arc::clone(&stop);
    let tx_clone = tx.clone();
    thread::spawn(move || {
        start_tcp_server(handler_clone, tcp_params_clone, &stop_clone);
        log::warn!("TCP server shut down.");
        tx_clone.send(()).unwrap();
    });

    // Wait for errors or teardowns. Note that in any case
    // we have a timeout on the second recv to avoid locks.
    rx.recv().unwrap();
    stop.store(true, atomic::Ordering::SeqCst);
    wake_up_servers(&udp_params, &tcp_params);
    rx.recv_timeout(time::Duration::from_secs(4)).unwrap();
}

/// Dirty hack. The only way to interrupt the UDP 'recv' and the TCP 'accept' calls
/// is sending them a message. Those calls are blocking and without this hack the
/// servers cannot unblock and check the stop signal (and so exit properly).
#[allow(unused_must_use)]
fn wake_up_servers(udp_conf: &UdpParams, tcp_conf: &TcpParams) {
    let udp_server_addr: (&str, u16) = (&udp_conf.address, udp_conf.port);
    match net::UdpSocket::bind("0.0.0.0:0") {
        Ok(udp_sock) => udp_sock.send_to(&[0], udp_server_addr),
        Err(_) => return,
    };
    let tcp_server_addr: (&str, u16) = (&tcp_conf.address, tcp_conf.port);
    match net::TcpStream::connect(tcp_server_addr) {
        Ok(mut tcp_sock) => tcp_sock.write_all(&[0]),
        Err(_) => return,
    };
}
