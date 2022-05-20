use crate::resolver::back_end::errors::*;
use crate::resolver::back_end::requests::*;
use crate::shared::dns::*;
use crate::{skip_if_not_verbose, skip_if_silent};
use colored::*;
use std::fmt::{self, Debug, Display, Formatter, Write};

/// The configuration options passed to the [Trace] constructor. The `silent`
/// field controls whether the trace is collected. The `verbose` field controls
/// whether the trace will also trace records before filtering for erroneous ones.
/// The [Default] implementation is usually a good choice.
#[derive(Debug, Clone)]
pub struct TraceParams {
    pub verbose: bool,
    pub silent: bool,
    pub color: bool,
}

impl Default for TraceParams {
    fn default() -> Self {
        Self {
            verbose: false,
            silent: false,
            color: true,
        }
    }
}

/// A collector of traces related to dns resolutions. The trace object
/// implements both Debug and Display to be easily visualized. Several
/// parameters of [Trace] control the behaviour of the collector.
pub struct Trace {
    lines: Vec<TraceLine>,
    conf: TraceParams,
}

enum TraceLine {
    ResolutionStart(String),
    CacheHit(String, Vec<String>),
    CacheMiss(String),
    NameserverStart(String),
    NameserverResp(String, Vec<String>),
    NameserverErr(String),
    RawResp(Vec<String>),
    SubResolution(Vec<TraceLine>),
}

impl Trace {
    /// Create a new [Trace] object using the provided configs. See
    /// the [TraceConf] struct for more details about the available options.
    pub fn new(conf: TraceParams) -> Self {
        Self {
            lines: Vec::with_capacity(50),
            conf: conf,
        }
    }

    /// Creates a new empty [Trace] using the config values of the
    /// present one, passing the parameters but the the trace lines.
    pub fn clone_empty(&self) -> Self {
        Self::new(self.conf.clone())
    }

    /// Reports if any trace is present in the [Trace].
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }
}

impl Default for Trace {
    fn default() -> Self {
        Self::new(TraceParams::default())
    }
}

impl Trace {
    /// Format and register trace lines related to a new starting lookup.
    pub fn t_start(&mut self, node: &Name, kind: RecordType) {
        skip_if_silent!(self);
        let line = format!("Starting resolution of {} records (type {:?}).", node, kind);
        let item = TraceLine::ResolutionStart(line);
        self.lines.push(item);
    }

    /// Format and register trace lines related to a cache hit.
    pub fn t_cache_hit(&mut self, node: &str, kind: RecordType, records: &[Record]) {
        skip_if_silent!(self);
        let header = format!("Cache hit for '{}' (type {:?}).", node, kind);
        let mut lines = vec![];
        format_records(&mut lines, records);
        let item = TraceLine::CacheHit(header, lines);
        self.lines.push(item);
    }

    /// Format and register trace lines related to a cache miss.
    pub fn t_cache_miss(&mut self, node: &str, kind: RecordType) {
        skip_if_silent!(self);
        let header = format!("Cache miss for '{}' (type {:?}).", node, kind);
        let item = TraceLine::CacheMiss(header);
        self.lines.push(item);
    }

    /// Format and register trace lines related to a nameserver cache hit.
    pub fn t_cache_ns_hit(&mut self, node: &str, next_nss: &[NextSubzoneNs]) {
        skip_if_silent!(self);
        let header = format!("Cache hit searching nameservers for '{}'.", node);
        let mut lines = vec![];
        for next_ns in next_nss {
            lines.push(format!("{:?}", next_ns.ns_record));
            format_records(&mut lines, &next_ns.a_records);
        }
        let item = TraceLine::CacheHit(header, lines);
        self.lines.push(item);
    }

    /// Format and register trace lines related to a nameserver miss hit.
    pub fn t_cache_ns_miss(&mut self, node: &str) {
        skip_if_silent!(self);
        let header = format!("Cache miss searching nameservers for '{}'.", node);
        let item = TraceLine::CacheMiss(header);
        self.lines.push(item);
    }

    /// Format and register trace lines related to a starting nameserver request.
    pub fn t_ns_req(&mut self, node: &str, kind: RecordType, ns: &NextSubzoneNs) {
        skip_if_silent!(self);
        let line = format!(
            "Asking '{}' (record type: '{:?}') to nameserver '{}' (auth over '{}').",
            node,
            kind,
            ns.node(),
            ns.zone()
        );
        let trace_item = TraceLine::NameserverStart(line);
        self.lines.push(trace_item);
    }

    /// Format and register trace lines related to a nameserver response.
    pub fn t_ns_resp(&mut self, ns_resp: &NsResponse) {
        skip_if_silent!(self);
        let mut resp_lines = vec![];
        let resp_header;
        match ns_resp {
            NsResponse::NoDomain { soa_rec, .. } => {
                if soa_rec.is_some() {
                    resp_header = format!("No domain (NX code), SOA record:");
                    resp_lines.push(format!("{:?}", soa_rec.as_ref().unwrap()));
                } else {
                    resp_header = format!("No domain (NX code), no SOA record.");
                };
            }
            NsResponse::Answer { answers, additionals, .. } => {
                resp_header = format!("{}:", "Answers found");
                format_records(&mut resp_lines, answers);
                if additionals.len() > 0 {
                    resp_lines.push(format!("Additionals found:"));
                    format_records(&mut resp_lines, additionals);
                }
            }
            NsResponse::Alias { cname_rec, next_nss, .. } => {
                resp_header = format!("Alias to canonical name found:");
                resp_lines.push(format!("{:?}", cname_rec));
                if next_nss.len() > 0 {
                    resp_lines.push(format!("Delegations (hints) found:"));
                    for next_ns in next_nss {
                        resp_lines.push(format!("{:?}", next_ns.ns_record));
                        format_records(&mut resp_lines, &next_ns.a_records);
                    }
                }
            }
            NsResponse::Delegation { next_nss, .. } => {
                resp_header = format!("Delegation to sub-zone found:");
                for next_ns in next_nss {
                    resp_lines.push(format!("{:?}", next_ns.ns_record));
                }
                for next_ns in next_nss {
                    format_records(&mut resp_lines, &next_ns.a_records);
                }
            }
        }

        let item = TraceLine::NameserverResp(resp_header, resp_lines);
        self.lines.push(item);
    }

    /// Format and register trace lines related to a failed nameserver response.
    pub fn t_ns_err(&mut self, err: &LookupErr) {
        skip_if_silent!(self);
        let err_msg = format!("Asking to nameserver failed: {:?}.", err);
        let item = TraceLine::NameserverErr(err_msg);
        self.lines.push(item);
    }

    /// Format and register trace lines related to a nameserver response before any filtering.
    pub fn t_raw_resp(&mut self, message: &Message) {
        skip_if_silent!(self);
        skip_if_not_verbose!(self);

        let mut lines = vec![];
        lines.push(format!("Header: {:?}", message.header));
        lines.push("Questions:".to_string());
        format_questions(&mut lines, &message.questions);
        lines.push("Answers:".to_string());
        format_records(&mut lines, &message.answers);
        lines.push("Authorities:".to_string());
        format_records(&mut lines, &message.authorities);
        lines.push("Additionals:".to_string());
        format_records(&mut lines, &message.additionals);

        let item = TraceLine::RawResp(lines);
        self.lines.push(item);
    }

    /// Consume another trace and add to the present one as a sub trace.
    pub fn add_sub_trace(&mut self, sub_trace: Trace) {
        let item = TraceLine::SubResolution(sub_trace.lines);
        self.lines.push(item);
    }
}

fn format_questions(lines: &mut Vec<String>, questions: &[Question]) {
    for q in questions {
        lines.push(format!("{:?}", q));
    }
}

fn format_records(lines: &mut Vec<String>, records: &[Record]) {
    for r in records {
        lines.push(format!("{:?}", r));
    }
}

/// Implement Display for the [Trace] object to allow visualizing it. Similarly,
/// implement Debug as a function of the Display implementation.
impl Display for Trace {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.lines.is_empty() {
            return write!(f, "<no trace>");
        }
        display_trace_lines(f, &self.lines, 0, &self.conf)?;
        Ok(())
    }
}

impl Debug for Trace {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

// Recursive function in charge of formatting and printing the collected
// trace. The output may differ based on the config values (e.g. colors).
fn display_trace_lines(f: &mut Formatter<'_>, lines: &[TraceLine], depth: u8, conf: &TraceParams) -> std::fmt::Result {
    for line in lines {
        match line {
            TraceLine::ResolutionStart(header) => {
                indent(f, depth)?;
                if conf.color {
                    writeln!(f, "{}", header.black().bold().on_bright_green())?
                } else {
                    writeln!(f, "{}", header)?
                }
            }
            TraceLine::CacheHit(header, lines) => {
                indent(f, depth)?;
                if conf.color {
                    writeln!(f, "{}", header.black().bold().on_bright_cyan())?
                } else {
                    writeln!(f, "{}", header)?
                }
                for line in lines {
                    indent(f, depth)?;
                    writeln!(f, "{}", line)?;
                }
            }
            TraceLine::CacheMiss(header) => {
                indent(f, depth)?;
                writeln!(f, "{}", header)?
            }
            TraceLine::RawResp(lines) => {
                for line in lines {
                    indent(f, depth)?;
                    if conf.color {
                        writeln!(f, "{}", line.yellow())?
                    } else {
                        writeln!(f, "{}", line)?
                    }
                }
            }
            TraceLine::NameserverStart(header) => {
                indent(f, depth)?;
                if conf.color {
                    writeln!(f, "{}", header.on_bright_cyan().black().bold())?
                } else {
                    writeln!(f, "{}", header)?
                }
            }
            TraceLine::NameserverResp(header, lines) => {
                indent(f, depth)?;
                if conf.color {
                    writeln!(f, "{}", header.underline().italic().bright_white())?
                } else {
                    writeln!(f, "{}", header)?
                }
                for line in lines {
                    indent(f, depth)?;
                    writeln!(f, "{}", line)?;
                }
            }
            TraceLine::NameserverErr(header) => {
                indent(f, depth)?;
                writeln!(f, "{}", header.bold().bright_red())?;
            }
            TraceLine::SubResolution(sub_trace) => {
                display_trace_lines(f, sub_trace, depth + 1, conf)?;
                writeln!(f, "")?;
            }
        }
    }
    Ok(())
}

fn indent(f: &mut Formatter<'_>, n: u8) -> fmt::Result {
    for _ in 0..n {
        f.write_char('\t')?;
    }
    Ok(())
}

#[macro_export]
macro_rules! skip_if_silent {
    ($self: ident) => {
        if $self.conf.silent {
            return;
        }
    };
}

#[macro_export]
macro_rules! skip_if_not_verbose {
    ($self: ident) => {
        if !$self.conf.verbose {
            return;
        }
    };
}
