use crate::resolver::*;
use crate::shared::dns;
use crate::shared::log;
use crate::shared::net::*;

/// The resolver handler able to serve dns requests via its [`DnsHandler`] implementation.
pub struct ResolverHandler(pub Resolver);

impl DnsHandler for ResolverHandler {
    fn handle_request<R: DnsRead, W: DnsWrite>(&self, req: R, resp: W) {
        handle_request(req, resp, &self.0);
    }
}

fn handle_request<R: DnsRead, W: DnsWrite>(req: R, resp: W, resolver: &Resolver) {
    let dns_request = match req.read() {
        DnsReadResult::FullMessage(req) => req,
        DnsReadResult::HeaderOnly(header, err) => {
            handle_decode_err(resp, header, err);
            return;
        }
        DnsReadResult::ParseErr(msg_err, hdr_err) => {
            log::warn!("Decoding request: {:?}, decoding header: {:?}", msg_err, hdr_err);
            return;
        }
        DnsReadResult::IoErr(err) => {
            log::warn!("IO error: {:?}", err);
            return;
        }
    };

    if let Err(err) = validate_dns_request(&dns_request) {
        log::warn!("[{}] Response malformed: {}.", dns_request.id(), err);
        handle_err(resp, &dns_request, dns::RespCode::FormErr);
        return;
    }

    let dns::Question { node, record_type: t, .. } = &dns_request.questions[0];
    log::info!("[{}] Start handling request: {}, type {:?}.", dns_request.id(), node, t);
    log::debug!("[{}] Complete request: {:?}", dns_request.id(), dns_request);
    handle_query(dns_request, resp, resolver);
}

/// Resolve the dns query fetching the records of the given name and type. The
/// response can be found in cache or querying external nameservers. The function
/// performs uses a new [Lookup] object and a lookup trace is optionally printed.
fn handle_query<W: DnsWrite>(req: dns::Message, resp: W, resolver: &Resolver) {
    let dns::Question { node, record_type, .. } = &req.questions[0];
    let lookup = resolver.new_lookup(node, *record_type);
    let (lookup_result, lookup_trace) = lookup.perform();
    if !lookup_trace.is_empty() {
        log::info!("[{}] Lookup trace:\n{}", req.id(), lookup_trace);
    }

    // If we have no records use 'nx_domain' else 'serv_fail' always.
    let LookupResponse(answers, authorities, additionals, _) = match lookup_result {
        Err(err) => {
            log::error!("[{}] Performing lookup: {:?}", req.id(), err);
            handle_err(resp, &req, dns::RespCode::ServFail);
            return;
        }
        Ok(res) if res.3 => {
            handle_err(resp, &req, dns::RespCode::NxDomain);
            return;
        }
        Ok(v) => v,
    };

    // An invariant that we must maintain is that dns messages formed
    // internally must be valid, so it's fine to unwrap after encoding.
    let mut resp_header = resp_header_from_req_header(&req.header, dns::RespCode::NoError);
    resp_header.answers_count = answers.len() as u16;
    resp_header.authorities_count = authorities.len() as u16;
    resp_header.additionals_count = additionals.len() as u16;
    let dns_response = dns::Message {
        header: resp_header,
        questions: req.questions,
        answers: answers,
        authorities: authorities,
        additionals: additionals,
    };

    reply(resp, dns_response);
}

/// Handle decoding errors, either malformed messages or unsupported features.
/// If we cannot decode the header we cannot compose a valid response header,
/// so simply drop the request in these cases.
fn handle_decode_err<W: DnsWrite>(resp: W, req_header: dns::Header, msg_err: dns::MessageErr) {
    let parsing_err = msg_err.inner_err();
    let resp_code = match parsing_err {
        dns::ParsingErr::UnsupportedOpCode(_) => dns::RespCode::NotImp,
        dns::ParsingErr::UnsupportedClass(_) => dns::RespCode::NotImp,
        dns::ParsingErr::UnsupportedType(_) => dns::RespCode::NotImp,
        _ => dns::RespCode::FormErr,
    };
    let resp_header = resp_header_from_req_header(&req_header, resp_code);
    let dns_response = dns::Message {
        header: resp_header,
        questions: vec![],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    };

    reply(resp, dns_response);
}

/// Generic error handler used to reply to a client with a specific error code.
/// Questions are included in the response.
fn handle_err<W: DnsWrite>(resp: W, dns_req: &dns::Message, resp_code: dns::RespCode) {
    let mut resp_header = resp_header_from_req_header(&dns_req.header, resp_code);
    resp_header.answers_count = 0;
    resp_header.authorities_count = 0;
    resp_header.additionals_count = 0;
    let dns_response = dns::Message {
        header: resp_header,
        questions: dns_req.questions.clone(),
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    };

    reply(resp, dns_response);
}

/// Reply to the client and log the outcome.
fn reply<W: DnsWrite>(resp: W, dns_response: dns::Message) {
    let response_id = dns_response.id();
    let response_code = dns_response.header.resp_code;
    log::debug!("[{}] Complete response: {:?}", response_id, dns_response);
    match resp.reply(dns_response) {
        Ok(_) => log::info!("[{}] Request served [{:?}].", response_id, response_code),
        Err(err) => log::error!("[{}] Error replying: {}", response_id, err),
    };
}

/// Creates a proper header from the request header, suitable to be used in
/// the corresponding response. The passed code is used in the resp header.
fn resp_header_from_req_header(req_header: &dns::Header, resp_code: dns::RespCode) -> dns::Header {
    dns::Header {
        query_resp: true,
        auth_answer: false,
        recursion_available: true,
        z: 0,
        resp_code,
        ..req_header.clone()
    }
}

/// Validate a client dns request against some minimal requirements.
fn validate_dns_request(dns_req: &dns::Message) -> Result<(), String> {
    if !dns_req.header.is_request() {
        return Err(format!("resp flag set in query"));
    }
    if dns_req.header.questions_count != 1 {
        return Err(format!("invalid # of questions: {:?}", dns_req.header.questions_count));
    }
    if dns_req.header.answers_count != 0 {
        return Err(format!("invalid # of answers: {:?}", dns_req.header.answers_count));
    }
    if dns_req.header.authorities_count != 0 {
        return Err(format!(
            "invalid # of authorities: {:?}",
            dns_req.header.authorities_count
        ));
    }
    Ok(())
}
