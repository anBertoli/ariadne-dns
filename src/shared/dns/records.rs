use crate::shared::buffer::*;
use crate::shared::dns::class::*;
use crate::shared::dns::errors::*;
use crate::shared::dns::name::*;
use crate::shared::dns::types::*;
use crate::shared::dns::utils::*;

/// Records present in the answer, authority and additional sections of dns
/// messages. A dns record refers to a specific node of the name system,
/// describing a specific type of resource. Note that not all [RecordType]s
/// have a corresponding [Record] variant since not all types are supported.
#[derive(Debug, Clone)]
pub enum Record {
    A {
        node: Name,
        class: Class,
        ttl: u32,
        data_len: u16,
        address: [u8; 4],
    },
    NS {
        node: Name,
        class: Class,
        ttl: u32,
        data_len: u16,
        name: Name,
    },
    CNAME {
        node: Name,
        class: Class,
        ttl: u32,
        data_len: u16,
        name: Name,
    },
    SOA {
        node: Name,
        class: Class,
        ttl: u32,
        data_len: u16,
        ns_name: Name,
        ml_name: Name,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    WKS {
        node: Name,
        class: Class,
        ttl: u32,
        data_len: u16,
        address: [u8; 4],
        protocol: u8,
        ports: Vec<u32>,
    },
    PTR {
        node: Name,
        class: Class,
        ttl: u32,
        data_len: u16,
        name: Name,
    },
    HINFO {
        node: Name,
        class: Class,
        ttl: u32,
        data_len: u16,
        cpu: String,
        os: String,
    },
    MX {
        node: Name,
        class: Class,
        ttl: u32,
        data_len: u16,
        priority: u16,
        name: Name,
    },
    TXT {
        node: Name,
        class: Class,
        ttl: u32,
        data_len: u16,
        txts: Vec<String>,
    },
}

impl Record {
    /// Decode a dns message [`Record`] from the bytes read from the passed
    /// buffer. Unsupported types/classes are detected and the function returns
    /// proper errors. Unknown records types still cause the bytes of that record
    /// to be consumed (and an error is returned as usual).
    #[rustfmt::skip]
    pub fn decode_from_buf(buffer: &mut BitsBuf) -> Result<Record, ParsingErr> {
        let node = Name::from_bytes(buffer)?;
        let rec_type = decode_record_type(buffer)?;
        let class = decode_class(check_end(buffer.read_u16())?)?;
        let ttl = check_end(buffer.read_u32())?;
        let data_len = check_end(buffer.read_u16())?;

        match rec_type {
            RecordType::A => {
                let address = decode_a_data(buffer, data_len)?;
                Ok(Record::A { node, class, ttl, data_len, address })
            }
            RecordType::NS => {
                let name = decode_ns_data(buffer, data_len)?;
                Ok(Record::NS { node, class, ttl, data_len, name })
            }
            RecordType::CNAME => {
                let name = decode_cname_data(buffer, data_len)?;
                Ok(Record::CNAME { node, class, ttl, data_len, name })
            }
            RecordType::SOA => {
                let data = decode_soa_data(buffer, data_len)?;
                Ok(Record::SOA {
                    node, class, ttl, data_len, ns_name: data.0, ml_name: data.1, serial: data.2,
                    refresh: data.3, retry: data.4, expire: data.5, minimum: data.6,
                })
            }
            RecordType::WKS => {
                let (address, protocol, ports) = decode_wks_data(buffer, data_len)?;
                Ok(Record::WKS {
                    node, class, ttl, data_len,
                    address, protocol, ports,
                })
            }
            RecordType::PTR => {
                let name = decode_ptr_data(buffer, data_len)?;
                Ok(Record::PTR { node, class, ttl, data_len, name })
            }
            RecordType::HINFO => {
                let (cpu, os) = decode_hinfo_data(buffer, data_len)?;
                Ok(Record::HINFO { node, class, ttl, data_len, cpu, os })
            }
            RecordType::MX => {
                let (priority, name) = decode_mx_data(buffer, data_len)?;
                Ok(Record::MX {
                    node, class, ttl,
                    data_len, priority, name,
                })
            }
            RecordType::TXT => {
                let txts = decode_txt_data(buffer, data_len)?;
                Ok(Record::TXT { node, class, ttl, data_len, txts })
            }
            _ => {
                // Unsupported/invalid record types should
                // be already filtered above.
                unreachable!()
            }
        }
    }

    /// Decode a dns message [`Record`] from the bytes slice passed in.
    /// Wrapper function that allows decoding the record from raw bytes,
    /// opposed to [Record::decode_from_buf] method which needs a buffer.
    pub fn decode_from_bytes(bytes: &[u8]) -> Result<Record, ParsingErr> {
        let mut buf = BitsBuf::from_raw_bytes(bytes);
        Record::decode_from_buf(&mut buf)
    }

    /// Encode a dns message [`Record`] to raw bytes, writing them into the
    /// provided buffer. This function panics if some unsupported class or
    /// types are provided (to maintain invariants about supported features).
    #[rustfmt::skip]
    pub fn encode_to_buf(&self, buffer: &mut BitsBuf) -> Result<(), ParsingErr> {
        let node = self.node();
        let class = self.class();
        let ttl = *self.ttl();
        let rec_type = self.record_type();

        assert!(rec_type.is_supported_for_records());
        assert!(matches!(class, Class::IN));

        buffer.write_bytes(&node.to_bytes());
        buffer.write_u16(rec_type.to_num());
        buffer.write_u16(class.to_num());
        buffer.write_u32(ttl);

        match self {
            Record::A { address, .. } => encode_a_data(buffer, address),
            Record::NS { name, .. } => encode_ns_data(buffer, name)?,
            Record::CNAME { name, .. } => encode_cname_data(buffer, name)?,
            Record::WKS { address, protocol, ports, .. } => encode_wks_data(buffer, address, *protocol, ports),
            Record::PTR { name, .. } => encode_ptr_data(buffer, &name)?,
            Record::HINFO { cpu, os, .. } => encode_hinfo_data(buffer, cpu, os)?,
            Record::MX { priority, name, .. } => encode_mx_data(buffer, *priority, name)?,
            Record::TXT { txts, .. } => encode_txt_data(buffer, txts)?,
            Record::SOA { ns_name, ml_name, serial, refresh, retry, expire, minimum, .. } => {
                encode_soa_data(buffer,
                    (&ns_name, &ml_name, *serial,
                     *refresh, *retry, *expire, *minimum),
                )?;
            }
        }

        Ok(())
    }
}

fn decode_record_type(buffer: &mut BitsBuf) -> Result<RecordType, ParsingErr> {
    match RecordType::from_num(check_end(buffer.read_u16())?) {
        Ok(v) if !v.is_supported_for_records() => Err(ParsingErr::UnsupportedType(v)),
        Ok(v) => Ok(v),
        Err(n) => {
            check_end(buffer.read_u16())?;
            check_end(buffer.read_u32())?;
            let data_len = check_end(buffer.read_u16())?;
            check_end(buffer.read_bytes_vec(data_len as usize))?;
            Err(ParsingErr::UnknownType(n))
        }
    }
}

fn decode_class(n: u16) -> Result<Class, ParsingErr> {
    match Class::from_num(n) {
        Ok(v) if !v.is_supported() => Err(ParsingErr::UnsupportedClass(v)),
        Err(n) => Err(ParsingErr::UnknownClass(n)),
        Ok(v) => Ok(v),
    }
}

// The following implementation block is dedicated to getter and setter function.
// Note that some of them are generated via macros, but not all of them. It would
// be nice in the future to reduce the code by using more macros.

macro_rules! getter {
    ($i: ident, $fn_name: ident, $type: ty) => {
        /// Returns the $i contained in the [`Record`].
        pub fn $fn_name(&self) -> $type {
            match self {
                Record::A { $i, .. } => $i,
                Record::NS { $i, .. } => $i,
                Record::CNAME { $i, .. } => $i,
                Record::SOA { $i, .. } => $i,
                Record::WKS { $i, .. } => $i,
                Record::PTR { $i, .. } => $i,
                Record::HINFO { $i, .. } => $i,
                Record::MX { $i, .. } => $i,
                Record::TXT { $i, .. } => $i,
            }
        }
    };
}

macro_rules! setter {
    ($i: ident, $fn_name: ident, $type: ty) => {
        /// Sets the the $i contained in the [`Record`].
        pub fn $fn_name(&mut self, v: $type) {
            match self {
                Record::A { $i, .. } => *$i = v,
                Record::NS { $i, .. } => *$i = v,
                Record::CNAME { $i, .. } => *$i = v,
                Record::SOA { $i, .. } => *$i = v,
                Record::WKS { $i, .. } => *$i = v,
                Record::PTR { $i, .. } => *$i = v,
                Record::HINFO { $i, .. } => *$i = v,
                Record::MX { $i, .. } => *$i = v,
                Record::TXT { $i, .. } => *$i = v,
            }
        }
    };
}

impl Record {
    getter!(node, node, &Name);
    getter!(class, class, &Class);
    getter!(ttl, ttl, &u32);
    getter!(data_len, data_len, &u16);
    setter!(ttl, set_ttl, u32);

    /// Returns the [RecordType] variant corresponding with the [`Record`].
    pub fn record_type(&self) -> RecordType {
        match self {
            Record::A { .. } => RecordType::A,
            Record::NS { .. } => RecordType::NS,
            Record::CNAME { .. } => RecordType::CNAME,
            Record::SOA { .. } => RecordType::SOA,
            Record::WKS { .. } => RecordType::WKS,
            Record::PTR { .. } => RecordType::PTR,
            Record::HINFO { .. } => RecordType::HINFO,
            Record::MX { .. } => RecordType::MX,
            Record::TXT { .. } => RecordType::TXT,
        }
    }

    /// Returns a reference to the A record data.
    /// Panics if the [`Record`] is not of type A.
    pub fn a_data(&self) -> &[u8; 4] {
        match self {
            Record::A { address, .. } => address,
            _ => panic!("a_data"),
        }
    }

    /// Returns a reference to the NS record data.
    /// Panics if the [`Record`] is not of type NS.
    pub fn ns_data(&self) -> &Name {
        match self {
            Record::NS { name, .. } => name,
            _ => panic!("ns_data"),
        }
    }

    /// Returns a reference to the CNAME record data.
    /// Panics if the [`Record`] is not of type CNAME.
    pub fn cname_data(&self) -> &Name {
        match self {
            Record::CNAME { name, .. } => name,
            _ => panic!("cname_data"),
        }
    }
}

// The following functions are all related to decoding/encoding the variable
// data part of different records types. The decoding ones MUST all check for
// correct data length, while encoding ones MUST write the correct value of
// data len before the data.

// A records data encoding and decoding functions.
fn decode_a_data(buffer: &mut BitsBuf, data_len: u16) -> Result<[u8; 4], ParsingErr> {
    if data_len != 4 {
        Err(ParsingErr::DataLenMismatch)
    } else {
        Ok(buffer.read_bytes().ok_or(ParsingErr::BytesEnd)?)
    }
}

fn encode_a_data(buffer: &mut BitsBuf, ip: &[u8; 4]) {
    buffer.write_u16(4);
    buffer.write_bytes(ip);
}

// NS records data encoding and decoding functions.
fn decode_ns_data(buffer: &mut BitsBuf, data_len: u16) -> Result<Name, ParsingErr> {
    let before = buffer.read_pos();
    let nameserver = Name::from_bytes(buffer)?;
    let after = buffer.read_pos();
    if after - before != (data_len * 8) as usize {
        Err(ParsingErr::DataLenMismatch)
    } else {
        Ok(nameserver)
    }
}

fn encode_ns_data(buffer: &mut BitsBuf, name: &Name) -> Result<(), ParsingErr> {
    let domain_name = name.to_bytes();
    buffer.write_u16(domain_name.len() as u16);
    buffer.write_bytes(&domain_name);
    Ok(())
}

// CNAME records data encoding and decoding functions.
fn decode_cname_data(buffer: &mut BitsBuf, data_len: u16) -> Result<Name, ParsingErr> {
    let before = buffer.read_pos();
    let alias = Name::from_bytes(buffer)?;
    let after = buffer.read_pos();
    if after - before != (data_len * 8) as usize {
        Err(ParsingErr::DataLenMismatch)
    } else {
        Ok(alias)
    }
}

fn encode_cname_data(buffer: &mut BitsBuf, name: &Name) -> Result<(), ParsingErr> {
    let domain_name = name.to_bytes();
    buffer.write_u16(domain_name.len() as u16);
    buffer.write_bytes(&domain_name);
    Ok(())
}

// SOA records data encoding and decoding functions.
type SoaData = (Name, Name, u32, u32, u32, u32, u32);

fn decode_soa_data(buffer: &mut BitsBuf, data_len: u16) -> Result<SoaData, ParsingErr> {
    let before = buffer.read_pos();
    let mname = Name::from_bytes(buffer)?;
    let rname = Name::from_bytes(buffer)?;
    let serial = buffer.read_u32().ok_or(ParsingErr::BytesEnd)?;
    let refresh = buffer.read_u32().ok_or(ParsingErr::BytesEnd)?;
    let retry = buffer.read_u32().ok_or(ParsingErr::BytesEnd)?;
    let expire = buffer.read_u32().ok_or(ParsingErr::BytesEnd)?;
    let minimum = buffer.read_u32().ok_or(ParsingErr::BytesEnd)?;
    let after = buffer.read_pos();
    if after - before != (data_len * 8) as usize {
        Err(ParsingErr::DataLenMismatch)
    } else {
        Ok((mname, rname, serial, refresh, retry, expire, minimum))
    }
}

fn encode_soa_data(buffer: &mut BitsBuf, data: (&Name, &Name, u32, u32, u32, u32, u32)) -> Result<(), ParsingErr> {
    let auth_ns_name = &data.0.to_bytes();
    let mail_name = &data.1.to_bytes();
    buffer.write_u16((auth_ns_name.len() + mail_name.len() + 20) as u16);
    buffer.write_bytes(&auth_ns_name);
    buffer.write_bytes(&mail_name);
    buffer.write_u32(data.2);
    buffer.write_u32(data.3);
    buffer.write_u32(data.4);
    buffer.write_u32(data.5);
    buffer.write_u32(data.6);
    Ok(())
}

// WKS records data encoding and decoding functions.
type WksData = ([u8; 4], u8, Vec<u32>);

fn decode_wks_data(buffer: &mut BitsBuf, data_len: u16) -> Result<WksData, ParsingErr> {
    let address = buffer.read_bytes().ok_or(ParsingErr::BytesEnd)?;
    let protocol = buffer.read_u8().ok_or(ParsingErr::BytesEnd)?;
    let ports = if data_len > 5 {
        let ports_bytes = buffer.read_bytes_vec((data_len - 5) as usize).unwrap();
        parse_wks_ports(&ports_bytes)
    } else {
        vec![]
    };

    Ok((address, protocol, ports))
}

fn encode_wks_data(buffer: &mut BitsBuf, address: &[u8; 4], protocol: u8, ports: &[u32]) {
    buffer.write_u16((5 + ports.len()) as u16);
    buffer.write_bytes(address);
    buffer.write_u8(protocol);
    for p in ports {
        buffer.write_u32(*p);
    }
}

fn parse_wks_ports(ports_bytes: &[u8]) -> Vec<u32> {
    let mut ports = vec![];
    for (i, &byte) in ports_bytes.iter().enumerate() {
        if byte == 0 {
            continue;
        }
        for j in 1.. {
            if byte << j == 0 {
                ports.push((i * 8 + j - 1) as u32);
            };
        }
    }
    ports
}

// PTR records data encoding and decoding functions.
fn decode_ptr_data(buffer: &mut BitsBuf, data_len: u16) -> Result<Name, ParsingErr> {
    let before = buffer.read_pos();
    let name = Name::from_bytes(buffer)?;
    let after = buffer.read_pos();
    if after - before != (data_len * 8) as usize {
        Err(ParsingErr::DataLenMismatch)
    } else {
        Ok(name)
    }
}

fn encode_ptr_data(buffer: &mut BitsBuf, name: &Name) -> Result<(), ParsingErr> {
    let domain_name = name.to_bytes();
    buffer.write_u16(domain_name.len() as u16);
    buffer.write_bytes(&domain_name);
    Ok(())
}

// HINFO records data encoding and decoding functions.
fn decode_hinfo_data(buffer: &mut BitsBuf, data_len: u16) -> Result<(String, String), ParsingErr> {
    let before = buffer.read_pos();
    let cpu = decode_character_string(buffer)?;
    let os = decode_character_string(buffer)?;
    let after = buffer.read_pos();
    if after - before != (data_len * 8) as usize {
        Err(ParsingErr::DataLenMismatch)
    } else {
        Ok((cpu, os))
    }
}

fn encode_hinfo_data(buffer: &mut BitsBuf, cpu: &str, os: &str) -> Result<(), ParsingErr> {
    let cpu = encode_character_string(cpu)?;
    let os = encode_character_string(os)?;
    buffer.write_u16((cpu.len() + os.len()) as u16);
    buffer.write_bytes(&cpu);
    buffer.write_bytes(&os);
    Ok(())
}

// MX records data encoding and decoding functions.
fn decode_mx_data(buffer: &mut BitsBuf, data_len: u16) -> Result<(u16, Name), ParsingErr> {
    let before = buffer.read_pos();
    let preference = buffer.read_u16().ok_or(ParsingErr::BytesEnd)?;
    let exchange = Name::from_bytes(buffer)?;
    let after = buffer.read_pos();
    if after - before != (data_len * 8) as usize {
        Err(ParsingErr::DataLenMismatch)
    } else {
        Ok((preference, exchange))
    }
}

fn encode_mx_data(buffer: &mut BitsBuf, priority: u16, name: &Name) -> Result<(), ParsingErr> {
    let domain_name = name.to_bytes();
    buffer.write_u16(2 + domain_name.len() as u16);
    buffer.write_u16(priority);
    buffer.write_bytes(&domain_name);
    Ok(())
}

// TXT records data encoding and decoding functions.
fn decode_txt_data(buffer: &mut BitsBuf, data_len: u16) -> Result<Vec<String>, ParsingErr> {
    let mut strings = vec![];
    let mut read: u16 = 0;
    loop {
        let pos = buffer.read_pos();
        let len = buffer.read_u8().ok_or(ParsingErr::BytesEnd)? as u16;
        buffer.set_read_pos(pos - 1);
        if read + len + 1 > data_len {
            return Err(ParsingErr::DataLenMismatch);
        }
        strings.push(decode_character_string(buffer)?);
        read += len + 1;
        if read == data_len {
            break;
        }
    }
    Ok(strings)
}

fn encode_txt_data(buffer: &mut BitsBuf, strings: &Vec<String>) -> Result<(), ParsingErr> {
    let mut buf = vec![];
    let mut len = 0;
    for str in strings {
        let bytes = encode_character_string(str)?;
        len += bytes.len();
        buf.push(bytes);
    }
    buffer.write_u16(len as u16);
    for b in buf {
        buffer.write_bytes(&b);
    }
    Ok(())
}
