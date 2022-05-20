use std::io;

/// A type implementing the [DnsWrite] trait is able to write a dns response
/// to an underlying destination, usually a OS socket. It's mostly an extension
/// of the [io::Write] trait. The [len_required](DnsWrite::len_required) method
/// must be used to determine if if the length of the response (in bytes) must
/// be written before the actual response. **The trait decouples the request
/// handling from the server communication mechanism**.  
pub trait DnsWrite: io::Write {
    fn len_required(&self) -> bool;
}

/// A type implementing the [DnsRead] trait is able to read a dns request
/// from an underlying source, usually a OS socket. It's basically a marker
/// trait, extending the [io::Read] trait. **The trait decouples the request
/// handling from the server communication mechanism**.    
pub trait DnsRead: io::Read {}

/// A type implementing the [DnsHandler] is able to handle dns requests. It
/// is able to to do this via its [handle_request](DnsHandler::handle_request)
/// method, which receives a generic type implementing [DnsRead] (the dns request)
/// and a generic type implementing [DnsWrite] (the dns response).
pub trait DnsHandler: Send + Sync + 'static {
    fn handle_request<R, W>(&self, req: R, resp: W)
    where
        R: DnsRead,
        W: DnsWrite;
}
