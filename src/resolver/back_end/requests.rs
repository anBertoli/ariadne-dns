use crate::resolver::back_end::errors::*;
use crate::resolver::back_end::trace::*;
use crate::resolver::back_end::utils::*;
use crate::shared::dns;
use crate::shared::dns::Name;
use std::fmt::Debug;
use std::net::IpAddr;
use std::{io, mem, net, time};

/// The request to be made to an external nameserver. Contains data and several
/// parameters to control. The nameserver address is contained in a [NextNsData].
#[derive(Debug)]
pub struct NsRequest<'a> {
    pub searched_node: Name,
    pub searched_type: dns::RecordType,
    pub nameserver: &'a NextSubzoneNs,
    pub retries: usize,
    pub r_timeout: time::Duration,
    pub w_timeout: time::Duration,
}

/// Parsed response from a nameserver. Different variants represent different
/// 'meanings' of the response (as interpreted by this resolver implementation).
#[derive(Debug)]
pub enum NsResponse {
    NoDomain {
        header: dns::Header,
        soa_rec: Option<dns::Record>,
    },
    Answer {
        header: dns::Header,
        answers: Vec<dns::Record>,
        additionals: Vec<dns::Record>,
    },
    Alias {
        header: dns::Header,
        cname_rec: dns::Record,
        next_nss: Vec<NextSubzoneNs>,
    },
    Delegation {
        header: dns::Header,
        next_nss: Vec<NextSubzoneNs>,
    },
}

/// Wrapper for all records related to a sub zone delegation.
#[derive(Clone, Debug)]
pub struct NextSubzoneNs {
    pub ns_record: dns::Record,
    pub a_records: Vec<dns::Record>,
}

impl NextSubzoneNs {
    pub fn node(&self) -> &Name {
        self.ns_record.ns_data()
    }
    pub fn zone(&self) -> &Name {
        self.ns_record.node()
    }
    pub fn addrs(&self) -> Vec<IpAddr> {
        self.a_records
            .iter()
            .map(|r| r.a_data())
            .map(|r| net::IpAddr::from(*r))
            .collect()
    }
}

/// Performs the [`NsRequest`] to the specified nameserver. The response is analyzed
/// and a [`NsResponse`] is returned. In general we filter out records not related
/// to the "meaning" of the returned response.
pub fn perform_request(ns_req: NsRequest, trace: &mut Trace) -> Result<NsResponse, LookupErr> {
    let mut dns_resp = send_query_with_retries(&ns_req)?;
    trace.t_raw_resp(&dns_resp);

    // The upstream should only use the nx_domain code with the auth flag.
    let NsRequest { searched_node, searched_type, .. } = &ns_req;
    match dns_resp.header.resp_code {
        dns::RespCode::NoError => {}
        dns::RespCode::NxDomain if dns_resp.header.auth_answer => {
            let soa_rec = extract_record(&mut dns_resp.authorities, dns::RecordType::SOA, searched_node);
            return Ok(NsResponse::NoDomain { header: dns_resp.header, soa_rec });
        }
        resp_code => {
            let err = LookupErr::UnexpectedRespCode(resp_code);
            return Err(err);
        }
    }

    // Analyze the response. Start looking for answers, then cnames (note: only
    // one is valid). Otherwise search for sub zones delegations. If nothing is
    // found is an error (even if it should be signaled via nx_domain flag).
    let answers = extract_records(&mut dns_resp.answers, *searched_type, searched_node);
    if answers.len() > 0 {
        return Ok(NsResponse::Answer {
            additionals: dns_resp.additionals,
            header: dns_resp.header,
            answers,
        });
    }

    let cname = extract_record(&mut dns_resp.answers, dns::RecordType::CNAME, searched_node);
    if let Some(cname_rec) = cname {
        let cname = cname_rec.cname_data();
        let next_nss = extract_next_nss_for_cname(&mut dns_resp, cname);
        return Ok(NsResponse::Alias {
            header: dns_resp.header,
            cname_rec,
            next_nss,
        });
    }

    let current_zone = ns_req.nameserver.zone();
    let next_nss = extract_next_nss_for_subzone(&mut dns_resp, searched_node, current_zone.as_ref());
    if next_nss.len() > 0 {
        return Ok(NsResponse::Delegation {
            header: dns_resp.header,
            next_nss: next_nss,
        });
    }

    Err(LookupErr::UnexpectedEmptyResp)
}

/// Extracts from the [`dns::Message`] response all records useful to re-start
/// the cname resolution. Those are typically NS records and their addresses.
fn extract_next_nss_for_cname(response: &mut dns::Message, cname: &Name) -> Vec<NextSubzoneNs> {
    let authority_records = mem::take(&mut response.authorities);
    authority_records
        .into_iter()
        .filter(|rec| rec.record_type() == dns::RecordType::NS)
        .filter(|rec| cname.as_ref().ends_with(rec.node().as_ref()))
        .map(|next_record| {
            let ns_node = next_record.ns_data();
            let ns_addrs = extract_records(&mut response.additionals, dns::RecordType::A, ns_node);
            NextSubzoneNs {
                ns_record: next_record,
                a_records: ns_addrs,
            }
        })
        .collect()
}

/// Extract from the [`dns::Message`] response all records related to a sub zone
/// delegation. Some validation is performed so some records could be discarded.
fn extract_next_nss_for_subzone(resp: &mut dns::Message, node: &Name, zone: &str) -> Vec<NextSubzoneNs> {
    let authority_records = mem::take(&mut resp.authorities);
    authority_records
        .into_iter()
        .filter(|rec| rec.record_type() == dns::RecordType::NS)
        .filter(|rec| {
            let is_auth = is_nameserver_authoritative_over_node(rec.node(), node);
            let is_sub = is_nameserver_authority_a_subzone(rec.node(), zone);
            is_auth && is_sub
        })
        .map(|ns_record| {
            let ns_node = ns_record.ns_data();
            let ns_addrs = extract_records(&mut resp.additionals, dns::RecordType::A, ns_node);
            NextSubzoneNs {
                ns_record: ns_record,
                a_records: ns_addrs,
            }
        })
        .filter(|next_subzone_ns| {
            // Bad servers or truncation of messages could lead to ns in subzones
            // without glue records. Anyway, we cannot use those records (without
            // re-issuing the query with TCP). TODO: check if it's ok.
            !is_nameserver_in_subzone_without_glue(
                next_subzone_ns.node(),
                next_subzone_ns.zone(),
                next_subzone_ns.addrs().is_empty(),
            )
        })
        .collect()
}

// Make sure the zone managed by the queried nameserver contains the node we
// are looking for. Example: if we are looking for "company.com." the ns
// record returned here cannot be authoritative over "pizza.com.".
fn is_nameserver_authoritative_over_node(ns_zone: &Name, searched_node: &Name) -> bool {
    if !searched_node.as_ref().ends_with(&ns_zone.as_ref()) {
        // TODO: trace?
        return false;
    }
    true
}

// Make sure the zone controlled by this nameserver is closer to the searched
// node than the current zone. Example: if we are looking for "s3.company.com."
// and the ".com." nameserver responds with a NS record, the zone must be 'more'
// than simply ".com.".
fn is_nameserver_authority_a_subzone(ns_zone: &Name, current_zone: &str) -> bool {
    if ns_zone.as_ref().len() <= current_zone.len() {
        // TODO: trace?
        return false;
    }
    true
}

// A loop arises if the indicated sub zone nameserver is in a child zone of the queried
// nameserver and no addresses are present for it. Example: the nameserver managing
// '.com' is 'dns.com' and without an address we enter in a loop.
fn is_nameserver_in_subzone_without_glue(ns_node: &Name, ns_zone: &Name, no_addr: bool) -> bool {
    if ns_node.as_ref().ends_with(ns_zone.as_ref()) && no_addr {
        // TODO: trace?
        return true;
    }
    false
}

/// Encode a [`NsRequest`] appropriately as a [`dns::Message`] and send it to the
/// destination nameserver. Retries are performed until a configurable maximum.
fn send_query_with_retries(next_ns_request: &NsRequest) -> Result<dns::Message, LookupErr> {
    let mut err = None;
    let mut i = 0;
    loop {
        if i >= next_ns_request.retries {
            return Err(err.unwrap());
        }
        match send_query(next_ns_request) {
            Ok(resp) => return Ok(resp),
            Err(er) => err = Some(er),
        };
        i += 1;
    }
}

fn send_query(ns_request: &NsRequest) -> Result<dns::Message, LookupErr> {
    let request = build_dns_request(ns_request);
    let request_bytes = request.encode_to_bytes().unwrap();

    let (response_bytes, n_recv) = send_udp_packet(ns_request, &request_bytes)?;
    let response = dns::Message::decode_from_bytes(&response_bytes[..n_recv]);
    let response = match response {
        Ok(v) => v,
        Err(err) => {
            let err_msg = format!("decoding error: {:?}", err);
            return Err(LookupErr::MalformedResp(err_msg));
        }
    };

    if response.header.id != request.header.id {
        return Err(LookupErr::MalformedResp(format!(
            "expected header id: {}, got: {}",
            request.id(),
            response.id()
        )));
    }

    return Ok(response);
}

fn build_dns_request(ns_request: &NsRequest) -> dns::Message {
    let mut header = dns::Header::default();
    header.questions_count = 1;
    let question = dns::Question {
        node: ns_request.searched_node.clone(),
        record_type: ns_request.searched_type,
        class: dns::Class::IN,
    };
    dns::Message {
        header: header,
        questions: vec![question],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    }
}

fn send_udp_packet(request: &NsRequest, bytes: &[u8]) -> io::Result<([u8; 512], usize)> {
    let addr = *request.nameserver.addrs().first().unwrap();
    let udp_socket = net::UdpSocket::bind("0.0.0.0:0")?;
    udp_socket.set_write_timeout(Some(request.w_timeout))?;
    udp_socket.set_read_timeout(Some(request.r_timeout))?;
    udp_socket.send_to(&bytes, (addr, 53))?;
    let mut buffer = [0_u8; 512];
    let (n_recv, _) = udp_socket.recv_from(&mut buffer)?;
    Ok((buffer, n_recv))
}
