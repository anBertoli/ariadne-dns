use crate::nameserver::zones::*;
use crate::shared::net::*;
use crate::shared::{dns, log};

/// The nameserver handler able to serve dns requests via its [`DnsHandler`] implementation.
pub struct NameserverHandler(pub ManagedZone);

impl DnsHandler for NameserverHandler {
    fn handle_request<R: DnsRead, W: DnsWrite>(&self, req: R, resp: W) {
        handle_dns_request(req, resp, &self.0);
    }
}

fn handle_dns_request<R: DnsRead, W: DnsWrite>(mut req: R, resp: W, zones: &ManagedZone) {
    let mut request_bytes = [0; 2048];
    let request_bytes = match req.read(&mut request_bytes) {
        Ok(0) => {
            log::warn!("Read request of 0 bytes.");
            return;
        }
        Ok(n_read) => &request_bytes[..n_read],
        Err(err) => {
            log::error!("Reading request: {}.", err);
            return;
        }
    };

    let request = dns::Message::decode_from_bytes(request_bytes);
    let request = match request {
        Ok(req) => req,
        Err(err) => {
            log::warn!("Decoding request: {:?}", err);
            handle_decode_err(resp, request_bytes, &err);
            return;
        }
    };
    if let Err(err) = validate_dns_request(&request) {
        log::warn!("[{}] Response malformed: {}.", request.id(), err);
        handle_err(resp, &request, dns::RespCode::FormErr);
        return;
    }

    let dns::Question { node, record_type: t, .. } = &request.questions[0];
    log::info!(
        "[{}] Start handling request: node '{}', type {:?}",
        request.id(),
        node,
        t
    );
    log::debug!("[{}] Complete request: {:?}", request.id(), request);
    handle_query(request, resp, zones);
}

/// Resolve the dns query. First of all the records are checked to see if they are
/// contained in the managed zone. If yes search in subzones, then in the auth data.    
fn handle_query<W: DnsWrite>(request: dns::Message, resp: W, zones: &ManagedZone) {
    let dns::Question { node, .. } = &request.questions[0];
    if !node.is_in_zone(&zones.auth_zone.zone) {
        log::warn!("[{}] Requested node not in zone: '{}'.", request.id(), node);
        handle_err(resp, &request, dns::RespCode::Refused);
        return;
    }

    // Check if the records are in subzone, if yes delegate to it.
    for subzone in &zones.sub_zones {
        if node.is_in_zone(&subzone.zone) {
            handle_subzone(resp, request, subzone, zones);
            return;
        }
    }

    handle_auth_zone(resp, request, &zones.auth_zone)
}

/// Handle request for names in the authoritative zone. Search response in zone, if
/// not found look for cnames, else reply with code 'nx_domain' and the SOA record.
fn handle_auth_zone<W: DnsWrite>(resp: W, request: dns::Message, auth_zone: &Zone) {
    let dns::Question { node, record_type, .. } = &request.questions[0];
    let mut searched_records = match auth_zone.get(node, *record_type) {
        Some(v) => v.clone(),
        None => vec![],
    };

    if searched_records.is_empty() {
        match auth_zone.get(node, dns::RecordType::CNAME) {
            Some(cname) => searched_records = cname.clone(),
            None => {
                let soa_records = auth_zone.get(&auth_zone.zone, dns::RecordType::SOA);
                let soa_record = soa_records.unwrap().first().unwrap().clone();
                handle_nx_err(resp, &request, soa_record);
                return;
            }
        };
    }

    // Reply to client, this is an authoritative response.
    let mut resp_header = resp_header_from_req_header(&request.header, dns::RespCode::NoError);
    resp_header.auth_answer = true;
    resp_header.questions_count = 1;
    resp_header.answers_count = searched_records.len() as u16;
    resp_header.authorities_count = 0;
    resp_header.additionals_count = 0;
    let response = dns::Message {
        header: resp_header,
        questions: request.questions,
        answers: searched_records,
        authorities: vec![],
        additionals: vec![],
    };

    reply(resp, response);
}

/// Respond to clients with delegation data. Extract from the subzone data all the
/// records necessary to reply to the client (NS records and eventually glue records).
fn handle_subzone<W: DnsWrite>(resp: W, request: dns::Message, sub_zone: &Zone, zones: &ManagedZone) {
    let ns_records = sub_zone.get(&sub_zone.zone, dns::RecordType::NS).unwrap();
    assert!(ns_records.len() > 0);

    let mut authorities: Vec<dns::Record> = vec![];
    let mut additionals: Vec<dns::Record> = vec![];
    for ns_record in ns_records {
        let glue_records = search_a_additionals_for_subzone_ns(ns_record.ns_data(), &zones.sub_zones);
        authorities.push(ns_record.clone());
        additionals.extend(glue_records);
    }

    // Reply to client, this is NOT an authoritative response.
    let mut resp_header = resp_header_from_req_header(&request.header, dns::RespCode::NoError);
    resp_header.auth_answer = false;
    resp_header.questions_count = 1;
    resp_header.answers_count = 0;
    resp_header.authorities_count = authorities.len() as u16;
    resp_header.additionals_count = additionals.len() as u16;
    let response = dns::Message {
        header: resp_header,
        questions: request.questions,
        answers: vec![],
        authorities,
        additionals,
    };

    reply(resp, response);
}

fn search_a_additionals_for_subzone_ns<'a>(
    ns_name: &'a dns::Name,
    sub_zones: &'a [Zone],
) -> impl Iterator<Item = dns::Record> + 'a {
    sub_zones
        .iter()
        .filter(|sub_zone| ns_name.is_in_zone(&sub_zone.zone))
        .filter_map(|sub_zone| sub_zone.get(ns_name, dns::RecordType::A))
        .flatten()
        .map(|r| r.clone())
}

/// Handle decoding errors, either malformed messages or unsupported features.
/// If we cannot decode the header we cannot compose a valid response header,
/// so simply drop the request in these cases.
fn handle_decode_err<W: DnsWrite>(resp: W, request_bytes: &[u8], msg_err: &dns::MessageErr) {
    let req_header = match dns::Header::decode_from_bytes(request_bytes) {
        Ok(v) => v,
        Err(err) => {
            log::warn!("Cannot decode header: {:?}", err);
            return;
        }
    };
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

/// Handle domains not found in zone with the resp code 'nx_domain' and the zone
/// SOA record. The response is authoritative.
fn handle_nx_err<W: DnsWrite>(resp: W, dns_req: &dns::Message, soa_record: dns::Record) {
    assert_eq!(soa_record.record_type(), dns::RecordType::SOA);

    let mut resp_header = resp_header_from_req_header(&dns_req.header, dns::RespCode::NxDomain);
    resp_header.auth_answer = true;
    resp_header.answers_count = 0;
    resp_header.authorities_count = 1;
    resp_header.additionals_count = 0;
    let response = dns::Message {
        header: resp_header,
        questions: dns_req.questions.clone(),
        answers: vec![],
        authorities: vec![soa_record],
        additionals: vec![],
    };

    reply(resp, response);
}

/// Generic error handler used to reply to a client with a specific error code.
/// Questions are included. NOTE: by default the response is authoritative.
fn handle_err<W: DnsWrite>(resp: W, dns_req: &dns::Message, resp_code: dns::RespCode) {
    let mut resp_header = resp_header_from_req_header(&dns_req.header, resp_code);
    resp_header.auth_answer = true;
    resp_header.answers_count = 0;
    resp_header.authorities_count = 0;
    resp_header.additionals_count = 0;
    let dns_resp = dns::Message {
        header: resp_header,
        questions: dns_req.questions.clone(),
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    };

    reply(resp, dns_resp);
}

/// Reply to the client and log the outcome. If the generic [`DnsWrite`] needs
/// the length of the response at the beginning is it written as expected.
fn reply<W: DnsWrite>(mut resp: W, dns_response: dns::Message) {
    log::debug!("[{}] Complete response: {:?}", dns_response.id(), dns_response);
    let response_bytes = dns_response.encode_to_bytes().unwrap();
    let response_code = dns_response.header.resp_code;
    let response_id = dns_response.id();

    if resp.len_required() {
        let resp_len = response_bytes.len() as u16;
        let buf = [(resp_len >> 8) as u8, (resp_len) as u8];
        if let Err(err) = resp.write_all(&buf) {
            log::error!("[{}] Error writing len: {}", response_id, err);
            return;
        };
    }

    match resp.write_all(&response_bytes) {
        Ok(_) => log::info!("[{}] Request served [{:?}].", response_id, response_code),
        Err(err) => log::error!("[{}] Error replying: {}", response_id, err),
    };
}

// Creates a proper header from the request header, suitable to be used in
// the corresponding response. The passed code is used in the resp header.
fn resp_header_from_req_header(req_header: &dns::Header, resp_code: dns::RespCode) -> dns::Header {
    dns::Header {
        query_resp: true,
        auth_answer: false,
        recursion_available: false,
        z: 0,
        resp_code,
        ..req_header.clone()
    }
}

// Validate a client dns request against some minimal requirements.
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
