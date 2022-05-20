use crate::shared::net::traits::*;
use crate::shared::{log, thread_pool};
use std::io::Read;
use std::sync::{atomic, Arc};
use std::{io, net, time};

/// The request coming from resolver TCP clients. Implements [DnsRead]
/// by reading directly from the bytes read form the TCP request. The
/// amount of bytes is determined by the two first bytes of the TCP
/// message.
pub struct TcpRequest<'a>(io::Cursor<&'a [u8]>);

impl<'a> io::Read for TcpRequest<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<'a> DnsRead for TcpRequest<'a> {}

/// A wrapper around the an established TCP connection. Implements [DnsWrite],
/// writing directly into the underlying connection. It is required to write
/// the length of the message itself before writing the actual response.
pub struct TcpResponse(net::TcpStream);

impl io::Write for TcpResponse {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl DnsWrite for TcpResponse {
    fn len_required(&self) -> bool {
        true
    }
}

/// Parameters to be used when starting
/// the TCP server with [start_tcp_server].
#[derive(Clone)]
pub struct TcpParams {
    pub address: String,
    pub port: u16,
    pub write_timeout: time::Duration,
    pub read_timeout: time::Duration,
    pub threads: usize,
}

/// Starts a new TCP server generic over a request handler ([DnsHandler]). The function
/// spawns a threads pool to handle requests and loops over new TCP connections messages.
/// When a new client establish a new TCP connection, a new task for the thread pool is
/// created. The task will use the dns handler to serve the request. The [TcpParams] is
/// used to setup the server, while the `stop` argument can be used to stop the server.
pub fn start_tcp_server<H>(handler: Arc<H>, params: TcpParams, stop: &atomic::AtomicBool)
where
    H: DnsHandler,
{
    let threads_pool = thread_pool::ThreadPool::new(params.threads, "tcp");
    let listen_address: (&str, u16) = (&params.address, params.port);
    let tcp_socket = match net::TcpListener::bind(listen_address) {
        Ok(v) => v,
        Err(err) => {
            log::error!("Cannot setup socket: {}", err);
            return;
        }
    };

    // Loop accepting TCP connections. When a new one is accepted, read
    // it and delegate the request processing to a thread in the pool.
    loop {
        let (mut tcp_stream, _) = match tcp_socket.accept() {
            Ok(v) => v,
            Err(err) => {
                log::error!("Accepting tcp connection: {}", err);
                continue;
            }
        };

        // Check if we got a signal to exit.
        if stop.load(atomic::Ordering::SeqCst) {
            drop(threads_pool);
            return;
        }

        // Create and send a new task to the worker pool: setup the connection
        // parameters, read the request, compose request and response and call
        // the handler to serve the request.
        let handler = Arc::clone(&handler);
        threads_pool.execute(move || {
            let setup_ok = setup_connection(&mut tcp_stream, (params.read_timeout, params.write_timeout));
            if let Err(err) = setup_ok {
                log::error!("Setting the conn: {}", err);
                return;
            };

            let req_bytes = match read_request(&mut tcp_stream) {
                Ok(v) => v,
                Err(err) => {
                    log::warn!("Reading request: {}", err);
                    return;
                }
            };

            let request = TcpRequest(io::Cursor::new(&req_bytes));
            let response = TcpResponse(tcp_stream);
            handler.handle_request(request, response);
        })
    }
}

// When using TCP the first two bytes are extra and indicate how
// long is the dns message. We read exactly that amount of bytes.
fn read_request(tcp_stream: &mut net::TcpStream) -> Result<Vec<u8>, io::Error> {
    let mut buf: [u8; 2] = [0; 2];
    tcp_stream.read_exact(&mut buf)?;
    let req_len = ((buf[0] as u16) << 8) | (buf[1] as u16);
    let mut buf = vec![0_u8; req_len as usize];
    tcp_stream.read(&mut buf)?;
    Ok(buf)
}

fn setup_connection(
    tcp_stream: &mut net::TcpStream,
    (r_timeout, w_timeout): (time::Duration, time::Duration),
) -> io::Result<()> {
    tcp_stream.set_read_timeout(Some(r_timeout))?;
    tcp_stream.set_write_timeout(Some(w_timeout))?;
    Ok(())
}
