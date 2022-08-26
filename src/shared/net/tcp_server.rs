use crate::shared::net::traits::*;
use crate::shared::{dns, thread_pool};
use std::io::{Read, Write};
use std::sync::{atomic, Arc};
use std::{io, net, time};

/// The request coming from resolver TCP clients. Implements [DnsRead]
/// by reading directly from the bytes read form the TCP request. The
/// amount of bytes is determined by the two first bytes of the TCP
/// message.
pub struct TcpRequest(net::TcpStream);

impl DnsRead for TcpRequest {
    fn read(mut self) -> DnsReadResult {
        let mut buf: [u8; 2] = [0; 2];
        if let Err(err) = self.0.read_exact(&mut buf) {
            return DnsReadResult::IoErr(err);
        };
        let req_len = ((buf[0] as u16) << 8) | (buf[1] as u16);
        let mut buf = vec![0_u8; req_len as usize];
        if let Err(err) = self.0.read_exact(&mut buf) {
            return DnsReadResult::IoErr(err);
        };

        let req = dns::Message::decode_from_bytes(&buf);
        let err = match req {
            Ok(req) => return DnsReadResult::FullMessage(req),
            Err(err) => err,
        };
        match dns::Header::decode_from_bytes(&buf) {
            Ok(v) => DnsReadResult::HeaderOnly(v, err),
            Err(err_h) => DnsReadResult::ParseErr(err, err_h),
        }
    }
}

/// A wrapper around the an established TCP connection. Implements [DnsWrite],
/// writing directly into the underlying connection. It is required to write
/// the length of the message itself before writing the actual response.
pub struct TcpResponse(net::TcpStream);

impl DnsWrite for TcpResponse {
    fn reply(mut self, response: dns::Message) -> io::Result<()> {
        let resp_bytes = response.encode_to_bytes().unwrap();
        let resp_len = resp_bytes.len() as u16;
        let buf = [(resp_len >> 8) as u8, (resp_len) as u8];
        self.0.write_all(&buf)?;
        self.0.write_all(&resp_bytes)
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
        Ok(v) => {
            log::info!("Starting TCP server, address: '{}:{}'.", &params.address, params.port);
            v
        }
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

            let request = TcpRequest(tcp_stream.try_clone().unwrap());
            let response = TcpResponse(tcp_stream);
            handler.handle_request(request, response);
        })
    }
}

fn setup_connection(
    tcp_stream: &mut net::TcpStream,
    (r_timeout, w_timeout): (time::Duration, time::Duration),
) -> io::Result<()> {
    tcp_stream.set_read_timeout(Some(r_timeout))?;
    tcp_stream.set_write_timeout(Some(w_timeout))?;
    Ok(())
}
