use crate::shared::net::traits::*;
use crate::shared::{log, thread_pool};
use std::sync::{atomic, Arc};
use std::{io, net, time};

/// The request coming from resolver UDP clients. Implements [DnsRead]
/// by reading directly from the bytes read form the UDP request.
pub struct UdpRequest<'a>(io::Cursor<&'a [u8]>);

impl<'a> io::Read for UdpRequest<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<'a> DnsRead for UdpRequest<'a> {}

/// A wrapper around the socket and the address to be used to respond
/// to a resolver UDP request. Implements [DnsWrite], writing directly
/// into the underlying OS socket.
pub struct UdpResponse {
    socket: net::UdpSocket,
    addr: net::SocketAddr,
}

impl io::Write for UdpResponse {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.socket.send_to(buf, self.addr)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl DnsWrite for UdpResponse {
    fn len_required(&self) -> bool {
        false
    }
}

/// Parameters to be used when starting
/// the UDP server with [start_udp_server].
#[derive(Clone)]
pub struct UdpParams {
    pub address: String,
    pub port: u16,
    pub write_timeout: time::Duration,
    pub threads: usize,
}

/// Starts a new UDP server generic over a request handler ([DnsHandler]). The function
/// spawns a threads pool to handle requests and loops over new UDP messages. When a new
/// one arrives a new task for the thread pool is created. The task will use the dns handler
/// to serve the request. The [UdpParams] is used to setup the server properly, while the
/// `stop` argument can be used to stop the server.
pub fn start_udp_server<H>(handler: Arc<H>, params: UdpParams, stop: &atomic::AtomicBool)
where
    H: DnsHandler,
{
    let threads_pool = thread_pool::ThreadPool::new(params.threads, "udp");
    let socket = match setup_listening_socket(&params) {
        Ok(v) => v,
        Err(err) => {
            log::error!("Cannot setup socket: {}", err);
            return;
        }
    };

    // Loop receiving UDP messages. When a new request arrives, read
    // it and delegate request handling to a thread in the pool.
    loop {
        let mut buffer = [0; 2048];
        let (n_read, src_addr) = match socket.recv_from(&mut buffer) {
            Ok(read_data) => read_data,
            Err(err) => {
                log::warn!("Cannot recv_from socket: {}", err);
                continue;
            }
        };

        // Check if we got a signal to exit.
        if stop.load(atomic::Ordering::SeqCst) {
            drop(threads_pool);
            return;
        }

        let socket_clone = match socket.try_clone() {
            Ok(socket) => socket,
            Err(err) => {
                log::warn!("Cannot clone socket: {}", err);
                continue;
            }
        };

        // Create and send a new task to the worker pool: compose request and
        // response objects and call the handler function to serve the request.
        let handler = Arc::clone(&handler);
        threads_pool.execute(move || {
            let request = UdpRequest(io::Cursor::new(&buffer[0..n_read]));
            let response = UdpResponse {
                socket: socket_clone,
                addr: src_addr,
            };
            handler.handle_request(request, response);
        });
    }
}

fn setup_listening_socket(server_conf: &UdpParams) -> Result<net::UdpSocket, io::Error> {
    let listen_address: (&str, u16) = (&server_conf.address, server_conf.port);
    let socket = net::UdpSocket::bind(listen_address)?;
    socket.set_write_timeout(Some(server_conf.write_timeout))?;
    Ok(socket)
}
