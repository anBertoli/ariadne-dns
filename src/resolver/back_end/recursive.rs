use crate::resolver::back_end::cache::*;
use crate::resolver::back_end::errors::*;
use crate::resolver::back_end::requests::*;
use crate::resolver::back_end::trace::*;
use crate::resolver::back_end::utils::*;
use crate::shared::dns;
use std::sync::Arc;
use std::{mem, time};

/// The resolver parameters passed to the [`Resolver`] constructor.
/// A good default configuration is provided via the [`Default`] trait.
#[derive(Debug, Clone)]
pub struct ResolverParams {
    pub max_ns_queried: usize,
    pub max_upd_retries: usize,
    pub max_cname_redir: usize,
    pub read_timeout: time::Duration,
    pub write_timeout: time::Duration,
    pub no_follow_cname: bool,
}

impl Default for ResolverParams {
    fn default() -> Self {
        Self {
            max_ns_queried: 3,
            max_upd_retries: 3,
            max_cname_redir: 10,
            read_timeout: time::Duration::new(2, 0),
            write_timeout: time::Duration::new(2, 0),
            no_follow_cname: false,
        }
    }
}

/// The Resolver is a builder for [`Lookup`]s objects. It contains several parameters
/// to tune lookup and tracing and can access the cache. [`Lookup`]s objects generated
/// inherit part of the configuration and the ability to access the same cache. To
/// perform a new lookup use the [new_lookup], which generates a new  [`Lookup`] object.
pub struct Resolver {
    cache: Arc<RecordsCache>,
    rsv_conf: ResolverParams,
    trc_conf: TraceParams,
}

pub type RecordsCache = Cache<(dns::Name, dns::RecordType), Vec<dns::Record>>;

impl Resolver {
    /// Build and return a new [`Resolver`] with the provided config values.
    pub fn new(cache: &Arc<RecordsCache>, rsv_conf: ResolverParams, trc_conf: TraceParams) -> Self {
        Self {
            cache: Arc::clone(cache),
            rsv_conf: rsv_conf,
            trc_conf: trc_conf,
        }
    }

    /// Generates a new [Lookup] object with a copy of the resolver and tracing
    /// params. The generated object can be consumed to perform the lookup.
    pub fn new_lookup(&self, node: &dns::Name, kind: dns::RecordType) -> Lookup {
        let trace = Trace::new(self.trc_conf.clone());
        Lookup {
            searched_node: node.clone(),
            searched_kind: kind,
            previous_zones: vec![],
            previous_cnames: vec![],
            cache: &self.cache,
            next_nss: vec![],
            conf: self.rsv_conf.clone(),
            trace,
        }
    }
}

/// The [Lookup] struct is a consumable object used to perform a single dns lookup.
/// Configs are inherited from the parent [Resolver]. To perform new a new name
/// resolution a new [Lookup] objects should be generated.
pub struct Lookup<'a> {
    searched_node: dns::Name,
    searched_kind: dns::RecordType,
    previous_zones: Vec<dns::Name>,
    previous_cnames: Vec<dns::Record>,
    next_nss: Vec<NextSubzoneNs>,
    cache: &'a RecordsCache,
    trace: Trace,
    conf: ResolverParams,
}

/// The response returned when a lookup is performed. The last field
/// indicates if no records of the searched type were found.
#[derive(Debug)]
pub struct LookupResponse(
    pub Vec<dns::Record>,
    pub Vec<dns::Record>,
    pub Vec<dns::Record>,
    pub bool,
);

impl<'a> Lookup<'a> {
    /// Lookup the records of the type and node set on this [Lookup] object. The cache is
    /// consulted to speed up the lookup, and records found are cached for next lookups.
    /// Cnames found are included in the response. If tracing is disabled, the returned
    /// [`Trace`] is empty.
    pub fn perform(mut self) -> (Result<LookupResponse, LookupErrCtx>, Trace) {
        let res = self.perform_inner();
        (res, self.trace)
    }

    /// Performs the lookup process (private interface). First search in cache for direct
    /// answers, then for cnames. If nothing found query external nameservers. Restart the
    /// process every time a cname is found. Cnames are included in the response.
    fn perform_inner(&mut self) -> Result<LookupResponse, LookupErrCtx> {
        for _ in 0..self.conf.max_cname_redir {
            self.trace.t_start(&self.searched_node, self.searched_kind);

            let cached_answers = self.search_records_in_cache_with_trace(self.searched_kind);
            if cached_answers.len() > 0 {
                let mut answers = mem::take(&mut self.previous_cnames);
                answers.extend(cached_answers);
                return Ok(LookupResponse(answers, vec![], vec![], false));
            }
            let mut cached_cnames = self.search_records_in_cache_with_trace(dns::RecordType::CNAME);
            if cached_cnames.len() > 0 {
                self.handle_cname(cached_cnames.swap_remove(0), vec![])?;
                continue;
            }

            if self.next_nss.is_empty() {
                let cached_nss = self.search_nss_in_cache_with_trace();
                self.next_nss = if cached_nss.is_empty() {
                    root_zone_nameservers()
                } else {
                    cached_nss
                }
            }

            match self.query_nameservers_iteratively()? {
                // Some answers found. Return answers along with previous cnames.
                NsResponse::Answer { answers, additionals, .. } => {
                    debug_assert!(answers.len() > 0);
                    save_records_in_cache(&self.cache, answers.clone());
                    let mut cname_answers = mem::take(&mut self.previous_cnames);
                    cname_answers.extend(answers);
                    return Ok(LookupResponse(cname_answers, vec![], additionals, false));
                }
                // Cname found. Stash the cname, save data in cache and restart.
                NsResponse::Alias { cname_rec, next_nss, .. } => {
                    self.handle_cname(cname_rec, next_nss)?;
                    continue;
                }
                // Nothing found for the searched domain, a SOA record could be present.
                NsResponse::NoDomain { soa_rec, .. } => {
                    let authorities = soa_rec.map_or(vec![], |r| vec![r]);
                    let answers = mem::take(&mut self.previous_cnames);
                    return Ok(LookupResponse(answers, authorities, vec![], true));
                }
                // Delegation to sub zones is not handled here.
                _ => unreachable!(),
            }
        }

        // Make sure strange long cname paths are discarded.
        let err_msg = format!("too many cnames followed: {:?}", self.previous_cnames);
        Err((err_msg, LookupErr::MaxCnameRedir))
    }

    // Collect the cname in the [Lookup] object, and re-set the fields to
    // restart the lookup. Validate against cname loops.
    fn handle_cname(&mut self, cname_record: dns::Record, next_nss: Vec<NextSubzoneNs>) -> Result<(), LookupErrCtx> {
        let cname = cname_record.cname_data().clone();
        detect_cname_loops(&cname_record, &self.previous_cnames)?;
        self.previous_cnames.push(cname_record.clone());
        if self.conf.no_follow_cname {
            return Err((cname.to_string(), LookupErr::UnexpectedCname));
        }
        save_records_in_cache(&self.cache, vec![cname_record]);
        self.next_nss = next_nss;
        self.searched_node = cname;
        Ok(())
    }

    /// Query external nameservers to obtain a response for the searched domain. The function
    /// iterates over subsequent nameservers, getting closer to the searched node/zone, until
    /// the authoritative nameserver is found. The method could start recursive lookups.
    fn query_nameservers_iteratively(&mut self) -> Result<NsResponse, LookupErrCtx> {
        'next_zone: loop {
            assert!(self.next_nss.len() > 0);
            let mut next_nss = mem::take(&mut self.next_nss);
            sort_nameservers(&mut next_nss);
            let next_nss = next_nss.into_iter().take(self.conf.max_ns_queried);
            let mut error: Option<LookupErrCtx> = None;

            for mut next_ns in next_nss {
                // If no address is present start a separate lookup.
                if next_ns.addrs().is_empty() {
                    match self.resolve_ns_subquery(next_ns.node(), next_ns.zone()) {
                        Ok(addrs) => next_ns.a_records = addrs,
                        Err(err) => {
                            let err = LookupErr::SubLookupErr(Box::new(err));
                            error.get_or_insert((format!("{:?}", next_ns), err));
                            continue;
                        }
                    }
                }

                // Query an external nameserver.
                let ns_response = self.perform_request_with_trace(NsRequest {
                    searched_node: self.searched_node.clone(),
                    searched_type: self.searched_kind,
                    retries: self.conf.max_upd_retries,
                    r_timeout: self.conf.read_timeout,
                    w_timeout: self.conf.write_timeout,
                    nameserver: &next_ns,
                });
                let ns_response = match ns_response {
                    Ok(resp) => resp,
                    Err(err) => {
                        let err = (format!("{:?}", next_ns), err);
                        error.get_or_insert(err);
                        continue;
                    }
                };

                // Iterate if a delegation is found.
                match ns_response {
                    NsResponse::NoDomain { .. } => return Ok(ns_response),
                    NsResponse::Answer { .. } => return Ok(ns_response),
                    NsResponse::Alias { .. } => return Ok(ns_response),
                    NsResponse::Delegation { next_nss, .. } => {
                        save_nss_in_cache(&self.cache, next_nss.clone());
                        self.next_nss = next_nss;
                        continue 'next_zone;
                    }
                };
            }

            return Err(error.unwrap());
        }
    }

    /// Create a new [Lookup] object from the current one and start a separate
    /// recursive sub-lookup to resolve the passed nameserver name. Cnames are
    /// not allowed when resolving a nameserver name.
    fn resolve_ns_subquery(&mut self, node: &dns::Name, zone: &dns::Name) -> Result<Vec<dns::Record>, LookupErrCtx> {
        detect_zones_loop(zone, &self.previous_zones)?;
        let mut zones = self.previous_zones.clone();
        zones.push(zone.clone());

        let conf = ResolverParams {
            no_follow_cname: true,
            ..self.conf.clone()
        };
        let resolver = Lookup {
            searched_node: node.clone(),
            searched_kind: dns::RecordType::A,
            previous_zones: zones,
            previous_cnames: vec![],
            cache: &self.cache,
            trace: self.trace.clone_empty(),
            next_nss: vec![],
            conf,
        };

        let (response, sub_trace) = resolver.perform();
        self.trace.add_sub_trace(sub_trace);
        match response {
            Ok(mut v) => Ok(extract_records(&mut v.0, dns::RecordType::A, node)),
            Err(err) => return Err(err),
        }
    }

    // Perform the request to a nameserver and trace the result.
    fn perform_request_with_trace(&mut self, ns_req: NsRequest) -> Result<NsResponse, LookupErr> {
        self.trace
            .t_ns_req(&ns_req.searched_node.as_ref(), ns_req.searched_type, &ns_req.nameserver);
        match perform_request(ns_req, &mut self.trace) {
            Err(err) => {
                self.trace.t_ns_err(&err);
                Err(err)
            }
            Ok(resp) => {
                self.trace.t_ns_resp(&resp);
                Ok(resp)
            }
        }
    }

    // Search records in cache and trace the outcome.
    fn search_records_in_cache_with_trace(&mut self, searched_kind: dns::RecordType) -> Vec<dns::Record> {
        let results = search_records_in_cache(&self.cache, &self.searched_node, searched_kind);
        if results.is_empty() {
            self.trace.t_cache_miss(&self.searched_node.as_ref(), searched_kind);
        } else {
            self.trace
                .t_cache_hit(&self.searched_node.as_ref(), searched_kind, &results);
        }
        results
    }

    // Search records related to nameserver in cache and trace the outcome.
    fn search_nss_in_cache_with_trace(&mut self) -> Vec<NextSubzoneNs> {
        let domains = generate_domain_hierarchy(&self.searched_node.as_ref());
        let ns_records: Option<Vec<dns::Record>> = domains.iter().find_map(|name| {
            let name = dns::Name::from_string(name).unwrap();
            let records = search_records_in_cache(&self.cache, &name, dns::RecordType::NS);
            if records.len() > 0 {
                Some(records)
            } else {
                None
            }
        });

        let ns_records: Vec<dns::Record> = match ns_records {
            Some(v) => v,
            None => {
                self.trace.t_cache_ns_miss(&self.searched_node.as_ref());
                return vec![];
            }
        };

        let cached_next_nss: Vec<NextSubzoneNs> = ns_records
            .into_iter()
            .map(|ns_record| {
                let a_records = search_records_in_cache(&self.cache, ns_record.ns_data(), dns::RecordType::A);
                NextSubzoneNs { ns_record, a_records }
            })
            .collect();

        self.trace
            .t_cache_ns_hit(&self.searched_node.as_ref(), &cached_next_nss);
        cached_next_nss
    }
}

/// Search in cache records of the passed node and type and validate some invariants.
/// All the records should have the same ttl and record type.The TTL of the returned
/// records is properly lowered since they were inserted in the cache in the past.
fn search_records_in_cache(cache: &RecordsCache, node: &dns::Name, kind: dns::RecordType) -> Vec<dns::Record> {
    let before_get = time::Instant::now();
    let cache_entry = cache.get_clone(&(node.clone(), kind));
    let (exp, mut records) = match cache_entry {
        Some(v) if v.1.is_empty() => return vec![],
        None => return vec![],
        Some(v) => v,
    };

    assert!(records.len() > 0);
    let rec_type = records[0].record_type();
    let rec_ttl = records[0].ttl();
    for rec in &records {
        assert_eq!(rec.record_type(), rec_type);
        assert_eq!(rec.ttl(), rec_ttl);
        assert!(exp > before_get);
    }

    // Correct records TTLs.
    for record in &mut records {
        let ttl = (exp - before_get).as_secs();
        let remaining_ttl = u32::try_from(ttl).unwrap();
        record.set_ttl(remaining_ttl);
    }

    records
}

/// Save the passed records in the cache, ensuring they all have same TTLs and same
/// record type. If different TTLs are present they are adjusted to the lower one.
fn save_records_in_cache(cache: &RecordsCache, mut records: Vec<dns::Record>) {
    assert!(records.len() > 0);
    let rec_type = records[0].record_type();
    let min_ttl = *records.iter().map(|rec| rec.ttl()).min().unwrap();
    for rec in &mut records {
        assert_eq!(rec.record_type(), rec_type);
        rec.set_ttl(min_ttl);
    }

    let cache_key = (records[0].node().clone(), records[0].record_type());
    let cache_exp = time::Duration::new(min_ttl.into(), 0);
    cache.set(cache_key, cache_exp, records.clone());
}

// Save nameserver records in cache, both the NS record and eventual A ones.
fn save_nss_in_cache(cache: &RecordsCache, next_nss: Vec<NextSubzoneNs>) {
    let mut ns_records = vec![];
    for next_ns in next_nss {
        ns_records.push(next_ns.ns_record);
        if next_ns.a_records.len() > 0 {
            save_records_in_cache(cache, next_ns.a_records);
        }
    }
    save_records_in_cache(cache, ns_records);
}

// Generate a list of domains from the passed one, in increasing order.
// E.g.: node: "a.b.c." returns ["a.b.c.", "a.b.", "a.", ""].
fn generate_domain_hierarchy(mut node: &str) -> Vec<&str> {
    let mut domains: Vec<&str> = vec![&node];
    while let Some((_, suffix)) = node.split_once('.') {
        if suffix != "" {
            domains.push(suffix);
            node = suffix;
        } else {
            break;
        }
    }
    domains
}
