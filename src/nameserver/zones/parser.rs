use crate::nameserver::zones::errors::*;
use crate::nameserver::zones::parser_auth::*;
use crate::nameserver::zones::parser_sub::*;
use crate::shared::dns;
use std::collections::HashMap;

/// The configuration options to be specified when parsing a auth zone file via
/// [parse_zone_files]. Subzones are used to discriminate zone records ownership.
#[derive(Debug)]
pub struct ParsingParams {
    pub file_path: String,
    pub zone: dns::Name,
    pub starting_ttl: u32,
    pub sub_zones: Vec<SubParsingParams>,
}

/// The configuration options for the subzone files.
#[derive(Debug)]
pub struct SubParsingParams {
    pub file_path: String,
    pub zone: dns::Name,
    pub starting_ttl: u32,
    pub min_ttl: u32,
}

/// Parse both the authoritative zone file and all sub zones files, returning them as a
/// [`ManagedZone`] struct. For both cases records are validate for inconsistency errors.
pub fn parse_zone_files(zone_conf: ParsingParams) -> Result<ManagedZone, ParseErrCtx> {
    let auth_zone = parse_auth_zone_file(&zone_conf)?;

    let mut sub_zones = vec![];
    for sub_conf in &zone_conf.sub_zones {
        let sub_zone = parse_sub_zone_file(SubParsingParams {
            starting_ttl: sub_conf.starting_ttl,
            file_path: sub_conf.file_path.clone(),
            min_ttl: sub_conf.min_ttl,
            zone: sub_conf.zone.clone(),
        })?;
        sub_zones.push(sub_zone)
    }

    let zones = ManagedZone { auth_zone, sub_zones };
    if let Err(err) = validate_auth_zone(&zones) {
        return Err((err, format!("validating auth zone: {}", zones.auth_zone.zone)));
    }
    for subzone in &zones.sub_zones {
        if let Err(err) = validate_subzone(subzone, &zones) {
            return Err((err, format!("validating subzone: {}", subzone.zone)));
        }
    }

    Ok(zones)
}

/// Validate entries found in the auth zone file. The following checks are performed:
/// - NS records must be present (SOA record is already checked during parsing),
/// - NS records must be owned by the top node of the zone
fn validate_auth_zone(zones: &ManagedZone) -> Result<(), ParseErr> {
    let ns_records = zones.auth_zone.get_all_of_type(dns::RecordType::NS);
    if ns_records.is_empty() {
        let err_msg = format!("no NS records in auth file '{}'", zones.auth_zone.zone);
        return Err(ParseErr::MalformedZone(err_msg));
    }

    // Validate NS records of sub zone.
    for ns_record in ns_records {
        if !ns_record.node().is_in_zone_root(&zones.auth_zone.zone) {
            let err_msg = format!("NS record must be in top node '{}'", zones.auth_zone.zone);
            return Err(ParseErr::NameNotInRootNode(err_msg));
        }
    }

    Ok(())
}

/// Validate entries found in the sub zone file. The following checks are performed:
/// - only NS and A records can be present in subzones, NS records must be in top node
/// - NS records: if the pointed nameserver is outside the authoritative zone we don't
///   need any extra check, if it's contained in ANY subzone it must have glue records
/// - A records: should provide the address of one of the pointed nameservers.
fn validate_subzone(subzone: &Zone, zones: &ManagedZone) -> Result<(), ParseErr> {
    let ns_records = subzone.get_all_of_type(dns::RecordType::NS);
    if ns_records.is_empty() {
        let err_msg = format!("no NS records in subzone file '{}'", subzone.zone);
        return Err(ParseErr::MalformedZone(err_msg));
    }

    // Validate NS records of sub zone.
    for ns_record in ns_records {
        if !ns_record.node().is_in_zone_root(&subzone.zone) {
            let err_msg = format!("NS record must be in top node '{}'", subzone.zone);
            return Err(ParseErr::NameNotInRootNode(err_msg));
        }

        let pointed_ns = ns_record.ns_data();
        if !pointed_ns.is_in_zone(&zones.auth_zone.zone) {
            continue;
        }

        for sub_zone in &zones.sub_zones {
            if pointed_ns.is_in_zone(&sub_zone.zone) {
                if !search_glue_records(pointed_ns, sub_zone) {
                    let err_msg = format!("missing glue records for {:?}", ns_record);
                    return Err(ParseErr::MalformedZone(err_msg));
                }
            }
        }
    }

    // Validate A records of sub zone.
    let a_records = subzone.get_all_of_type(dns::RecordType::A);
    for a_record in a_records {
        let referred_ns_in_sub_zone = zones
            .sub_zones
            .iter()
            .find(|sub_zone| search_referred_ns(a_record.node(), sub_zone));

        if let None = referred_ns_in_sub_zone {
            let err_msg = format!("A record doesn't refer to a NS {:?}", a_record);
            return Err(ParseErr::MalformedZone(err_msg));
        }
    }

    Ok(())
}

// Find A records in the sub zone for the nameserver name passed in.
fn search_glue_records(ns_name: &dns::Name, sub_zone: &Zone) -> bool {
    let a_records = sub_zone.get(ns_name, dns::RecordType::A);
    let a_records = match a_records {
        None => return false,
        Some(v) => v,
    };
    for record in a_records {
        if ns_name == record.node() {
            return true;
        }
    }
    false
}

// Find NS records whose address is provided by the A record passed in.
fn search_referred_ns(a_node: &dns::Name, sub_zone: &Zone) -> bool {
    let ns_records = sub_zone.get(&sub_zone.zone, dns::RecordType::NS);
    let ns_records = match ns_records {
        None => return false,
        Some(v) => v,
    };
    for record in ns_records {
        if a_node == record.ns_data() {
            return true;
        }
    }
    false
}

/// Collector for zones. Contains the authoritative [`Zone`] directly managed
/// by the nameserver and records about subzone (to support delegation).
pub struct ManagedZone {
    pub auth_zone: Zone,
    pub sub_zones: Vec<Zone>,
}

pub struct Zone {
    records: HashMap<dns::Name, HashMap<dns::RecordType, Vec<dns::Record>>>,
    pub zone: dns::Name,
}

impl Zone {
    /// Create a new [`Zone`] object.
    pub fn new(zone: &dns::Name) -> Self {
        Self {
            records: Default::default(),
            zone: zone.clone(),
        }
    }

    /// Insert a new [`dns::Record`] into the zone records collection.
    pub fn insert(&mut self, record: dns::Record) {
        let outer_entry = self.records.entry(record.node().clone());
        let inner_map = outer_entry.or_default();
        let inner_entry = inner_map.entry(record.record_type());
        let records = inner_entry.or_default();
        records.push(record);
    }

    /// Get the &[`dns::Record`] corresponding to the passed node and record type.
    pub fn get(&self, node: &dns::Name, kind: dns::RecordType) -> Option<&Vec<dns::Record>> {
        let inner_map = self.records.get(node)?;
        let records = inner_map.get(&kind)?;
        debug_assert!(records.iter().all(|r| r.record_type() == kind));
        debug_assert!(records.iter().all(|r| r.node() == node));
        assert!(!records.is_empty());
        Some(records)
    }

    /// Get all [`dns::Record`] of the record type passed in, returned as references.
    pub fn get_all_of_type(&self, kind: dns::RecordType) -> Vec<&dns::Record> {
        self.records
            .iter()
            .map(|(_, r)| r.get(&kind))
            .filter_map(|r| r)
            .flatten()
            .collect()
    }

    /// Merge another [`Zone`] into the current one.
    pub fn extend(&mut self, other: Self) {
        for (_, inner) in other.records {
            for (_, records) in inner {
                for record in records {
                    self.insert(record)
                }
            }
        }
    }
}
