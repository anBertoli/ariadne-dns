use crate::shared::dns;
use std::io;

/// Results of reading and parsing a DNS request with a [DnsRead] implementor.
pub enum DnsReadResult {
    FullMessage(dns::Message),
    HeaderOnly(dns::Header, dns::MessageErr),
    ParseErr(dns::MessageErr, dns::ParsingErr),
    IoErr(io::Error),
}

/// A type implementing the [DnsRead] trait is able to read and parse a dns
/// response form an underlying source, usually a OS socket. **The trait decouples
/// the request handling from the server communication mechanism**. Note that
/// the method takes self, this is intentional: only one request should be read.
pub trait DnsRead {
    fn read(self) -> DnsReadResult;
}

/// A type implementing the [DnsWrite] trait is able to write a dns response
/// to an underlying destination, usually a OS socket. **The trait decouples
/// the request handling from the server communication mechanism**. Note that
/// the method takes self, this is intentional: only one response should be sent.
pub trait DnsWrite {
    fn reply(self, response: dns::Message) -> io::Result<()>;
}

/// A type implementing the [DnsHandler] is able to handle dns requests. The
/// [handle_request](DnsHandler::handle_request) method receives a generic type
/// implementing [DnsRead] (the dns request) and a generic type implementing [DnsWrite].
pub trait DnsHandler: Send + Sync + 'static {
    fn handle_request<R, W>(&self, req: R, resp: W)
    where
        R: DnsRead,
        W: DnsWrite;
}
