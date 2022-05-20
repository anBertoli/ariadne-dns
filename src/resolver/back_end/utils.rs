use crate::resolver::back_end::errors::*;
use crate::resolver::back_end::requests::*;
use crate::shared::dns;
use crate::shared::dns::*;
use std::cmp;

// The list of root nameservers of the domain name system.
const ROOT_SERVERS: [(&str, &str, [u8; 4]); 13] = [
    (".", "a.root-servers.net.", [198, 41, 0, 4]),
    (".", "b.root-servers.net.", [199, 9, 14, 201]),
    (".", "c.root-servers.net.", [192, 33, 4, 12]),
    (".", "d.root-servers.net.", [199, 7, 91, 13]),
    (".", "e.root-servers.net.", [192, 203, 230, 10]),
    (".", "f.root-servers.net.", [192, 5, 5, 241]),
    (".", "g.root-servers.net.", [192, 112, 36, 4]),
    (".", "h.root-servers.net.", [198, 97, 190, 53]),
    (".", "i.root-servers.net.", [192, 36, 148, 17]),
    (".", "j.root-servers.net.", [192, 58, 128, 30]),
    (".", "k.root-servers.net.", [193, 0, 14, 129]),
    (".", "l.root-servers.net.", [199, 7, 83, 42]),
    (".", "m.root-servers.net.", [202, 12, 27, 33]),
];

/// Generate a list of synthetic [`NextSubzoneNs`]  for the root nameservers.
pub fn root_zone_nameservers() -> Vec<NextSubzoneNs> {
    ROOT_SERVERS
        .iter()
        .map(|root_ns| NextSubzoneNs {
            ns_record: dns::Record::NS {
                node: Name::from_string(root_ns.0).unwrap(),
                class: Class::IN,
                ttl: 100000,
                data_len: 0,
                name: Name::from_string(root_ns.1).unwrap(),
            },
            a_records: vec![dns::Record::A {
                node: Name::from_string(root_ns.1).unwrap(),
                class: Class::IN,
                ttl: 10000,
                data_len: 0,
                address: root_ns.2,
            }],
        })
        .collect()
}

/// Extract and return all records of the given type and node from the
/// passed vector. The records are removed from the vector, not cloned.
pub fn extract_records(records: &mut Vec<Record>, kind: RecordType, node: &Name) -> Vec<Record> {
    let mut searched_records = vec![];
    let mut start_from = 0;
    loop {
        if start_from >= records.len() {
            return searched_records;
        }

        let record_index = records[start_from..]
            .iter()
            .enumerate()
            .filter(|(_, rec)| rec.node() == node)
            .find(|(_, rec)| rec.record_type() == kind)
            .map(|(i, _)| i + start_from);

        match record_index {
            None => return searched_records,
            Some(i) => {
                let record = records.swap_remove(i);
                searched_records.push(record);
                start_from = i;
            }
        }
    }
}

/// Extract and return the first record of the given type and node from the
/// passed vector. The record is removed from the vector, not cloned.
pub fn extract_record(records: &mut Vec<Record>, kind: RecordType, node: &Name) -> Option<Record> {
    let record_index = records
        .iter()
        .enumerate()
        .filter(|(_, rec)| rec.node() == node)
        .find(|(_, rec)| rec.record_type() == kind)
        .map(|(i, _)| i)?;

    Some(records.swap_remove(record_index))
}

/// Sort nameservers placing the ones with at least one address in the first positions.
pub fn sort_nameservers(nameservers: &mut Vec<NextSubzoneNs>) {
    nameservers.sort_by(|a, b| match (!a.addrs().is_empty(), !b.addrs().is_empty()) {
        (true, false) => cmp::Ordering::Less,
        (false, true) => cmp::Ordering::Greater,
        _ => cmp::Ordering::Equal,
    });
}

/// Detect if the passed cname record points to one of the cnames already
/// encountered. If yes, a loop is detected and a proper error is returned.
pub fn detect_cname_loops(cname_record: &Record, previous_cnames: &Vec<Record>) -> Result<(), LookupErrCtx> {
    for prev_cname in previous_cnames {
        if prev_cname.node() == cname_record.cname_data() {
            let err_msg = format!("record: {:?}, previous cnames: '{:?}'", prev_cname, previous_cnames);
            return Err((err_msg, LookupErr::CnamesLoop));
        }
    }
    Ok(())
}

/// Detect if the passed zone was already encountered (and not still resolved)
/// while trying to find nameservers for the passed zone. If yes, this is a loop.
pub fn detect_zones_loop(next_zone: &Name, previous_zones: &[Name]) -> Result<(), LookupErrCtx> {
    for prev_zone in previous_zones {
        if prev_zone == next_zone {
            let err_msg = format!("next zone: '{}', previous zones: {:?}", prev_zone, previous_zones);
            return Err((err_msg, LookupErr::ZonesLoop));
        }
    }
    Ok(())
}
