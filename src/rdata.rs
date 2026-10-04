//! Record types and their data: wire format and presentation (zone file) format.
//!
//! The common types are decoded into fields. DNSSEC types (DS, DNSKEY, RRSIG, NSEC, ZONEMD) are
//! understood well enough to read and print zone files that contain them, such as the root zone;
//! no signature is checked. Any other type is kept as raw bytes and written in the RFC 3597
//! generic form `\# length hex`.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::name::Name;
use crate::wire::{Reader, WireError, Writer};

pub mod rtype {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const PTR: u16 = 12;
    pub const HINFO: u16 = 13;
    pub const MX: u16 = 15;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
    pub const SRV: u16 = 33;
    pub const OPT: u16 = 41;
    pub const DS: u16 = 43;
    pub const RRSIG: u16 = 46;
    pub const NSEC: u16 = 47;
    pub const DNSKEY: u16 = 48;
    pub const ZONEMD: u16 = 63;
    pub const IXFR: u16 = 251;
    pub const AXFR: u16 = 252;
    pub const ANY: u16 = 255;
    pub const CAA: u16 = 257;
}

pub mod class {
    pub const IN: u16 = 1;
    pub const CH: u16 = 3;
    pub const NONE: u16 = 254;
    pub const ANY: u16 = 255;
}

const NAMES: &[(u16, &str)] = &[
    (rtype::A, "A"),
    (rtype::NS, "NS"),
    (rtype::CNAME, "CNAME"),
    (rtype::SOA, "SOA"),
    (rtype::PTR, "PTR"),
    (rtype::HINFO, "HINFO"),
    (rtype::MX, "MX"),
    (rtype::TXT, "TXT"),
    (rtype::AAAA, "AAAA"),
    (rtype::SRV, "SRV"),
    (rtype::OPT, "OPT"),
    (rtype::DS, "DS"),
    (rtype::RRSIG, "RRSIG"),
    (rtype::NSEC, "NSEC"),
    (rtype::DNSKEY, "DNSKEY"),
    (rtype::ZONEMD, "ZONEMD"),
    (rtype::IXFR, "IXFR"),
    (rtype::AXFR, "AXFR"),
    (rtype::ANY, "ANY"),
    (rtype::CAA, "CAA"),
    (99, "SPF"),
    (64, "SVCB"),
    (65, "HTTPS"),
    (50, "NSEC3"),
    (51, "NSEC3PARAM"),
    (52, "TLSA"),
    (59, "CDS"),
    (60, "CDNSKEY"),
    (35, "NAPTR"),
    (44, "SSHFP"),
    (25, "KEY"),
    (24, "SIG"),
    (29, "LOC"),
    (39, "DNAME"),
    (256, "URI"),
];

/// "A", "AAAA", ..., or "TYPE1234" for types without a mnemonic.
pub fn type_name(t: u16) -> String {
    NAMES.iter().find(|(c, _)| *c == t).map(|(_, n)| n.to_string()).unwrap_or_else(|| format!("TYPE{t}"))
}

pub fn type_from_name(s: &str) -> Option<u16> {
    let u = s.to_ascii_uppercase();
    if let Some(n) = u.strip_prefix("TYPE") {
        return n.parse().ok();
    }
    NAMES.iter().find(|(_, n)| *n == u).map(|(c, _)| *c)
}

pub fn class_name(c: u16) -> String {
    match c {
        class::IN => "IN".into(),
        class::CH => "CH".into(),
        class::NONE => "NONE".into(),
        class::ANY => "ANY".into(),
        4 => "HS".into(),
        _ => format!("CLASS{c}"),
    }
}

pub fn class_from_name(s: &str) -> Option<u16> {
    let u = s.to_ascii_uppercase();
    match u.as_str() {
        "IN" => Some(class::IN),
        "CH" | "CHAOS" => Some(class::CH),
        "HS" => Some(4),
        "NONE" => Some(class::NONE),
        "ANY" => Some(class::ANY),
        _ => u.strip_prefix("CLASS").and_then(|n| n.parse().ok()),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ns(Name),
    Cname(Name),
    Ptr(Name),
    Mx {
        preference: u16,
        exchange: Name,
    },
    Soa {
        mname: Name,
        rname: Name,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Txt(Vec<Vec<u8>>),
    Hinfo {
        cpu: Vec<u8>,
        os: Vec<u8>,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: Name,
    },
    Caa {
        flags: u8,
        tag: Vec<u8>,
        value: Vec<u8>,
    },
    Ds {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    },
    Dnskey {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        key: Vec<u8>,
    },
    Rrsig {
        type_covered: u16,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        expiration: u32,
        inception: u32,
        key_tag: u16,
        signer: Name,
        signature: Vec<u8>,
    },
    Nsec {
        next: Name,
        types: Vec<u16>,
    },
    Zonemd {
        serial: u32,
        scheme: u8,
        hash_algorithm: u8,
        digest: Vec<u8>,
    },
    /// Any other type: its data, uninterpreted.
    Unknown {
        rtype: u16,
        data: Vec<u8>,
    },
}

impl RData {
    pub fn rtype(&self) -> u16 {
        match self {
            RData::A(_) => rtype::A,
            RData::Aaaa(_) => rtype::AAAA,
            RData::Ns(_) => rtype::NS,
            RData::Cname(_) => rtype::CNAME,
            RData::Ptr(_) => rtype::PTR,
            RData::Mx { .. } => rtype::MX,
            RData::Soa { .. } => rtype::SOA,
            RData::Txt(_) => rtype::TXT,
            RData::Hinfo { .. } => rtype::HINFO,
            RData::Srv { .. } => rtype::SRV,
            RData::Caa { .. } => rtype::CAA,
            RData::Ds { .. } => rtype::DS,
            RData::Dnskey { .. } => rtype::DNSKEY,
            RData::Rrsig { .. } => rtype::RRSIG,
            RData::Nsec { .. } => rtype::NSEC,
            RData::Zonemd { .. } => rtype::ZONEMD,
            RData::Unknown { rtype, .. } => *rtype,
        }
    }

    /// The name this record points at, for additional-section processing and CNAME chains.
    pub fn target(&self) -> Option<&Name> {
        match self {
            RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) => Some(n),
            RData::Mx { exchange, .. } => Some(exchange),
            RData::Srv { target, .. } => Some(target),
            _ => None,
        }
    }

    /// Writes the data (without the length prefix). Names in the types of RFC 1035 may be
    /// compressed (RFC 3597 section 4); names in later types never are.
    pub fn encode(&self, w: &mut Writer) {
        match self {
            RData::A(a) => w.bytes(&a.octets()),
            RData::Aaaa(a) => w.bytes(&a.octets()),
            RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) => w.name(n, true),
            RData::Mx { preference, exchange } => {
                w.u16(*preference);
                w.name(exchange, true);
            }
            RData::Soa { mname, rname, serial, refresh, retry, expire, minimum } => {
                w.name(mname, true);
                w.name(rname, true);
                for v in [serial, refresh, retry, expire, minimum] {
                    w.u32(*v);
                }
            }
            RData::Txt(strings) => {
                for s in strings {
                    w.u8(s.len() as u8);
                    w.bytes(s);
                }
            }
            RData::Hinfo { cpu, os } => {
                for s in [cpu, os] {
                    w.u8(s.len() as u8);
                    w.bytes(s);
                }
            }
            RData::Srv { priority, weight, port, target } => {
                w.u16(*priority);
                w.u16(*weight);
                w.u16(*port);
                w.name(target, false);
            }
            RData::Caa { flags, tag, value } => {
                w.u8(*flags);
                w.u8(tag.len() as u8);
                w.bytes(tag);
                w.bytes(value);
            }
            RData::Ds { key_tag, algorithm, digest_type, digest } => {
                w.u16(*key_tag);
                w.u8(*algorithm);
                w.u8(*digest_type);
                w.bytes(digest);
            }
            RData::Dnskey { flags, protocol, algorithm, key } => {
                w.u16(*flags);
                w.u8(*protocol);
                w.u8(*algorithm);
                w.bytes(key);
            }
            RData::Rrsig { type_covered, algorithm, labels, original_ttl, expiration, inception, key_tag, signer, signature } => {
                w.u16(*type_covered);
                w.u8(*algorithm);
                w.u8(*labels);
                w.u32(*original_ttl);
                w.u32(*expiration);
                w.u32(*inception);
                w.u16(*key_tag);
                w.name(signer, false);
                w.bytes(signature);
            }
            RData::Nsec { next, types } => {
                w.name(next, false);
                w.bytes(&type_bitmap(types));
            }
            RData::Zonemd { serial, scheme, hash_algorithm, digest } => {
                w.u32(*serial);
                w.u8(*scheme);
                w.u8(*hash_algorithm);
                w.bytes(digest);
            }
            RData::Unknown { data, .. } => w.bytes(data),
        }
    }

    /// Reads `len` bytes of data at the reader's position. Names may be compressed in any type
    /// (being lenient on input), and the data must be used exactly.
    pub fn decode(t: u16, r: &mut Reader, len: usize) -> Result<RData, WireError> {
        let end = r.pos() + len;
        if end > r.len() {
            return Err(WireError::new("record data runs past the message"));
        }
        let d = match t {
            rtype::A if len == 4 => RData::A(Ipv4Addr::from(<[u8; 4]>::try_from(r.bytes(4)?).unwrap())),
            rtype::AAAA if len == 16 => RData::Aaaa(Ipv6Addr::from(<[u8; 16]>::try_from(r.bytes(16)?).unwrap())),
            rtype::A | rtype::AAAA => return Err(WireError::new("address of the wrong length")),
            rtype::NS => RData::Ns(r.name()?),
            rtype::CNAME => RData::Cname(r.name()?),
            rtype::PTR => RData::Ptr(r.name()?),
            rtype::MX => RData::Mx { preference: r.u16()?, exchange: r.name()? },
            rtype::SOA => RData::Soa {
                mname: r.name()?,
                rname: r.name()?,
                serial: r.u32()?,
                refresh: r.u32()?,
                retry: r.u32()?,
                expire: r.u32()?,
                minimum: r.u32()?,
            },
            rtype::TXT => {
                let mut v = Vec::new();
                while r.pos() < end {
                    let n = r.u8()? as usize;
                    v.push(r.bytes(n)?.to_vec());
                }
                if v.is_empty() {
                    return Err(WireError::new("TXT record without a string"));
                }
                RData::Txt(v)
            }
            rtype::HINFO => {
                let n = r.u8()? as usize;
                let cpu = r.bytes(n)?.to_vec();
                let n = r.u8()? as usize;
                RData::Hinfo { cpu, os: r.bytes(n)?.to_vec() }
            }
            rtype::SRV => RData::Srv { priority: r.u16()?, weight: r.u16()?, port: r.u16()?, target: r.name()? },
            rtype::CAA => {
                let flags = r.u8()?;
                let n = r.u8()? as usize;
                let tag = r.bytes(n)?.to_vec();
                RData::Caa { flags, tag, value: r.bytes(end.saturating_sub(r.pos()))?.to_vec() }
            }
            rtype::DS => RData::Ds { key_tag: r.u16()?, algorithm: r.u8()?, digest_type: r.u8()?, digest: r.rest(end)?.to_vec() },
            rtype::DNSKEY => RData::Dnskey { flags: r.u16()?, protocol: r.u8()?, algorithm: r.u8()?, key: r.rest(end)?.to_vec() },
            rtype::RRSIG => RData::Rrsig {
                type_covered: r.u16()?,
                algorithm: r.u8()?,
                labels: r.u8()?,
                original_ttl: r.u32()?,
                expiration: r.u32()?,
                inception: r.u32()?,
                key_tag: r.u16()?,
                signer: r.name()?,
                signature: r.rest(end)?.to_vec(),
            },
            rtype::NSEC => {
                let next = r.name()?;
                let types = parse_bitmap(r.rest(end)?)?;
                RData::Nsec { next, types }
            }
            rtype::ZONEMD => {
                RData::Zonemd { serial: r.u32()?, scheme: r.u8()?, hash_algorithm: r.u8()?, digest: r.rest(end)?.to_vec() }
            }
            _ => RData::Unknown { rtype: t, data: r.bytes(len)?.to_vec() },
        };
        if r.pos() != end {
            return Err(WireError::new(format!(
                "{} record data has {} bytes left over",
                type_name(t),
                end as isize - r.pos() as isize
            )));
        }
        Ok(d)
    }

    /// Presentation format, as in a zone file.
    pub fn to_text(&self) -> String {
        match self {
            RData::A(a) => a.to_string(),
            RData::Aaaa(a) => a.to_string(),
            RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) => n.to_string(),
            RData::Mx { preference, exchange } => format!("{preference} {exchange}"),
            RData::Soa { mname, rname, serial, refresh, retry, expire, minimum } => {
                format!("{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}")
            }
            RData::Txt(v) => v.iter().map(|s| quote(s)).collect::<Vec<_>>().join(" "),
            RData::Hinfo { cpu, os } => format!("{} {}", quote(cpu), quote(os)),
            RData::Srv { priority, weight, port, target } => format!("{priority} {weight} {port} {target}"),
            RData::Caa { flags, tag, value } => format!("{flags} {} {}", String::from_utf8_lossy(tag), quote(value)),
            RData::Ds { key_tag, algorithm, digest_type, digest } => {
                format!("{key_tag} {algorithm} {digest_type} {}", hex(digest).to_uppercase())
            }
            RData::Dnskey { flags, protocol, algorithm, key } => format!("{flags} {protocol} {algorithm} {}", base64(key)),
            RData::Rrsig { type_covered, algorithm, labels, original_ttl, expiration, inception, key_tag, signer, signature } => {
                format!(
                    "{} {algorithm} {labels} {original_ttl} {} {} {key_tag} {signer} {}",
                    type_name(*type_covered),
                    sig_time(*expiration),
                    sig_time(*inception),
                    base64(signature)
                )
            }
            RData::Nsec { next, types } => {
                let mut s = next.to_string();
                for t in types {
                    s.push(' ');
                    s.push_str(&type_name(*t));
                }
                s
            }
            RData::Zonemd { serial, scheme, hash_algorithm, digest } => {
                format!("{serial} {scheme} {hash_algorithm} {}", hex(digest).to_uppercase())
            }
            RData::Unknown { data, .. } => {
                if data.is_empty() {
                    "\\# 0".into()
                } else {
                    format!("\\# {} {}", data.len(), hex(data))
                }
            }
        }
    }

    /// Parses presentation-format data for type `t` from zone file tokens. Relative names are
    /// completed with `origin`.
    pub fn parse(t: u16, tokens: &[Token], origin: &Name) -> Result<RData, String> {
        let mut it = Fields { tokens, i: 0, t };
        // The RFC 3597 generic form works for every type.
        if tokens.first().is_some_and(|tok| !tok.quoted && tok.text == "\\#") {
            it.i = 1;
            let len: usize = it.num("length")?;
            let hexstr: String = tokens[2..].iter().map(|t| t.text.as_str()).collect();
            let data = unhex(&hexstr).ok_or("bad hex in generic data")?;
            if data.len() != len {
                return Err(format!("generic data says {len} bytes but has {}", data.len()));
            }
            if NAMES.iter().any(|(c, _)| *c == t)
                && !matches!(t, 99 | 64 | 65 | 50 | 51 | 52 | 59 | 60 | 35 | 44 | 25 | 24 | 29 | 39 | 256)
            {
                // A known type in generic form: decode it so it compares equal to the usual form.
                let mut r = Reader::new(&data);
                return RData::decode(t, &mut r, data.len()).map_err(|e| e.to_string());
            }
            return Ok(RData::Unknown { rtype: t, data });
        }
        let d = match t {
            rtype::A => RData::A(it.word("address")?.parse().map_err(|_| "bad IPv4 address")?),
            rtype::AAAA => RData::Aaaa(it.word("address")?.parse().map_err(|_| "bad IPv6 address")?),
            rtype::NS => RData::Ns(it.name(origin)?),
            rtype::CNAME => RData::Cname(it.name(origin)?),
            rtype::PTR => RData::Ptr(it.name(origin)?),
            rtype::MX => RData::Mx { preference: it.num("preference")?, exchange: it.name(origin)? },
            rtype::SOA => RData::Soa {
                mname: it.name(origin)?,
                rname: it.name(origin)?,
                serial: it.num("serial")?,
                refresh: it.ttl("refresh")?,
                retry: it.ttl("retry")?,
                expire: it.ttl("expire")?,
                minimum: it.ttl("minimum")?,
            },
            rtype::TXT | 99 => {
                let mut v = Vec::new();
                while it.i < tokens.len() {
                    v.push(it.string()?);
                }
                if v.is_empty() {
                    return Err("TXT needs at least one string".into());
                }
                if t == 99 {
                    let mut w = Writer::new();
                    RData::Txt(v).encode(&mut w);
                    return Ok(RData::Unknown { rtype: 99, data: w.finish() });
                }
                RData::Txt(v)
            }
            rtype::HINFO => RData::Hinfo { cpu: it.string()?, os: it.string()? },
            rtype::SRV => RData::Srv {
                priority: it.num("priority")?,
                weight: it.num("weight")?,
                port: it.num("port")?,
                target: it.name(origin)?,
            },
            rtype::CAA => {
                let flags = it.num("flags")?;
                let tag = it.word("tag")?.as_bytes().to_vec();
                if tag.is_empty() || !tag.iter().all(u8::is_ascii_alphanumeric) {
                    return Err("CAA tag must be letters and digits".into());
                }
                RData::Caa { flags, tag, value: it.string()? }
            }
            rtype::DS => RData::Ds {
                key_tag: it.num("key tag")?,
                algorithm: it.num("algorithm")?,
                digest_type: it.num("digest type")?,
                digest: unhex(&it.rest_joined()).ok_or("bad hex digest")?,
            },
            rtype::DNSKEY => RData::Dnskey {
                flags: it.num("flags")?,
                protocol: it.num("protocol")?,
                algorithm: it.num("algorithm")?,
                key: unbase64(&it.rest_joined()).ok_or("bad base64 key")?,
            },
            rtype::RRSIG => RData::Rrsig {
                type_covered: type_from_name(it.word("type covered")?).ok_or("unknown type covered")?,
                algorithm: it.num("algorithm")?,
                labels: it.num("labels")?,
                original_ttl: it.ttl("original TTL")?,
                expiration: parse_sig_time(it.word("expiration")?)?,
                inception: parse_sig_time(it.word("inception")?)?,
                key_tag: it.num("key tag")?,
                signer: it.name(origin)?,
                signature: unbase64(&it.rest_joined()).ok_or("bad base64 signature")?,
            },
            rtype::NSEC => {
                let next = it.name(origin)?;
                let mut types = Vec::new();
                while it.i < tokens.len() {
                    let w = it.word("type")?;
                    types.push(type_from_name(w).ok_or_else(|| format!("unknown type {w}"))?);
                }
                types.sort_unstable();
                types.dedup();
                RData::Nsec { next, types }
            }
            rtype::ZONEMD => RData::Zonemd {
                serial: it.num("serial")?,
                scheme: it.num("scheme")?,
                hash_algorithm: it.num("hash algorithm")?,
                digest: unhex(&it.rest_joined()).ok_or("bad hex digest")?,
            },
            _ => return Err(format!("type {} needs the generic form \\# length hex", type_name(t))),
        };
        if it.i != tokens.len() {
            return Err(format!("unexpected '{}' after {} data", tokens[it.i].text, type_name(t)));
        }
        Ok(d)
    }
}

/// A zone file token: its text as written (escapes not yet decoded) and whether it was quoted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub text: String,
    pub quoted: bool,
}

struct Fields<'a> {
    tokens: &'a [Token],
    i: usize,
    t: u16,
}

impl<'a> Fields<'a> {
    fn next(&mut self, what: &str) -> Result<&'a Token, String> {
        let t = self.tokens.get(self.i).ok_or_else(|| format!("{} record is missing its {what}", type_name(self.t)))?;
        self.i += 1;
        Ok(t)
    }

    fn word(&mut self, what: &str) -> Result<&'a str, String> {
        Ok(&self.next(what)?.text)
    }

    fn num<T: std::str::FromStr>(&mut self, what: &str) -> Result<T, String> {
        let w = self.word(what)?;
        w.parse().map_err(|_| format!("bad {what} '{w}'"))
    }

    fn ttl(&mut self, what: &str) -> Result<u32, String> {
        let w = self.word(what)?;
        parse_ttl(w).ok_or_else(|| format!("bad {what} '{w}'"))
    }

    fn name(&mut self, origin: &Name) -> Result<Name, String> {
        let w = self.word("name")?;
        Name::parse(w, Some(origin)).map_err(|e| e.to_string())
    }

    fn string(&mut self) -> Result<Vec<u8>, String> {
        let t = self.next("string")?;
        let b = unescape(&t.text)?;
        if b.len() > 255 {
            return Err("character string longer than 255 bytes".into());
        }
        Ok(b)
    }

    fn rest_joined(&mut self) -> String {
        let s: String = self.tokens[self.i..].iter().map(|t| t.text.as_str()).collect();
        self.i = self.tokens.len();
        s
    }
}

/// Decodes `\X` and `\DDD` escapes in a character string.
pub fn unescape(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            if i + 4 <= b.len() && b[i + 1..i + 4].iter().all(u8::is_ascii_digit) {
                let v: u32 = s[i + 1..i + 4].parse().unwrap();
                if v > 255 {
                    return Err(format!("escape \\{v} is more than 255"));
                }
                out.push(v as u8);
                i += 4;
            } else if i + 1 < b.len() {
                out.push(b[i + 1]);
                i += 2;
            } else {
                return Err("string ends with a backslash".into());
            }
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(out)
}

/// A character string in quotes, escaping `"`, `\` and anything unprintable.
pub fn quote(s: &[u8]) -> String {
    let mut out = String::from("\"");
    for &c in s {
        match c {
            b'"' | b'\\' => {
                out.push('\\');
                out.push(c as char);
            }
            0x20..=0x7e => out.push(c as char),
            _ => {
                let _ = write!(out, "\\{c:03}");
            }
        }
    }
    out.push('"');
    out
}

/// A TTL in seconds, or with BIND's units: `1h30m`, `2d`, `1w`.
pub fn parse_ttl(s: &str) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    if s.bytes().all(|c| c.is_ascii_digit()) {
        return s.parse::<u64>().ok().filter(|&v| v <= u32::MAX as u64).map(|v| v as u32);
    }
    let mut total: u64 = 0;
    let mut cur: u64 = 0;
    let mut have = false;
    for c in s.chars() {
        if let Some(d) = c.to_digit(10) {
            cur = cur.checked_mul(10)?.checked_add(d as u64)?;
            have = true;
        } else {
            if !have {
                return None;
            }
            let mult = match c.to_ascii_lowercase() {
                'w' => 604_800,
                'd' => 86_400,
                'h' => 3600,
                'm' => 60,
                's' => 1,
                _ => return None,
            };
            total = total.checked_add(cur.checked_mul(mult)?)?;
            cur = 0;
            have = false;
        }
    }
    if have {
        return None; // a number without a unit after a unit ("1h30") is not accepted
    }
    u32::try_from(total).ok()
}

/// The NSEC type bitmap (RFC 4034 section 4.1.2) for a set of types.
fn type_bitmap(types: &[u16]) -> Vec<u8> {
    let mut sorted = types.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut out = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let window = sorted[i] >> 8;
        let mut bits = [0u8; 32];
        let mut used = 0;
        while i < sorted.len() && sorted[i] >> 8 == window {
            let low = (sorted[i] & 0xff) as usize;
            bits[low / 8] |= 0x80 >> (low % 8);
            used = used.max(low / 8 + 1);
            i += 1;
        }
        out.push(window as u8);
        out.push(used as u8);
        out.extend_from_slice(&bits[..used]);
    }
    out
}

fn parse_bitmap(b: &[u8]) -> Result<Vec<u16>, WireError> {
    let mut types = Vec::new();
    let mut i = 0;
    let mut last_window = -1i32;
    while i < b.len() {
        if i + 2 > b.len() {
            return Err(WireError::new("truncated type bitmap"));
        }
        let (window, len) = (b[i] as i32, b[i + 1] as usize);
        if window <= last_window || len == 0 || len > 32 || i + 2 + len > b.len() {
            return Err(WireError::new("bad type bitmap"));
        }
        last_window = window;
        for (j, &byte) in b[i + 2..i + 2 + len].iter().enumerate() {
            for bit in 0..8 {
                if byte & (0x80 >> bit) != 0 {
                    types.push(((window as u16) << 8) | (j * 8 + bit) as u16);
                }
            }
        }
        i += 2 + len;
    }
    Ok(types)
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for chunk in b.chunks(3) {
        let n = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        for k in 0..4 {
            if k <= chunk.len() {
                out.push(B64[(n >> (18 - 6 * k)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub fn unbase64(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let v = B64.iter().position(|&x| x == c)? as u32;
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // Leftover bits must be padding zeros, and one leftover character is never valid.
    if bits >= 6 || acc & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

/// RRSIG times: YYYYMMDDHHmmSS in UTC, or a plain number of seconds.
fn parse_sig_time(s: &str) -> Result<u32, String> {
    if s.len() == 14 && s.bytes().all(|c| c.is_ascii_digit()) {
        let p = |a: usize, b: usize| s[a..b].parse::<i64>().unwrap();
        let (y, mo, d, h, mi, se) = (p(0, 4), p(4, 6), p(6, 8), p(8, 10), p(10, 12), p(12, 14));
        let days = days_from_civil(y, mo, d);
        let t = days * 86_400 + h * 3600 + mi * 60 + se;
        // Serial number arithmetic: the value is the time modulo 2^32.
        return Ok(t.rem_euclid(1 << 32) as u32);
    }
    s.parse().map_err(|_| format!("bad signature time '{s}'"))
}

fn sig_time(t: u32) -> String {
    let secs = t as i64;
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let r = secs.rem_euclid(86_400);
    format!("{y:04}{m:02}{d:02}{:02}{:02}{:02}", r / 3600, r % 3600 / 60, r % 60)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + if m <= 2 { 1 } else { 0 }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttls() {
        assert_eq!(parse_ttl("3600"), Some(3600));
        assert_eq!(parse_ttl("1h30m"), Some(5400));
        assert_eq!(parse_ttl("1W2D"), Some(777_600));
        assert_eq!(parse_ttl("1h30"), None);
        assert_eq!(parse_ttl("h"), None);
        assert_eq!(parse_ttl("4294967296"), None);
    }

    #[test]
    fn base64_round_trip() {
        for n in 0..40 {
            let b: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(unbase64(&base64(&b)).unwrap(), b);
        }
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert!(unbase64("Zm9=").is_none(), "non-zero padding bits");
        assert!(unbase64("Z").is_none());
    }

    #[test]
    fn bitmaps() {
        let types = vec![1, 2, 6, 46, 47, 48, 257, 65535];
        assert_eq!(parse_bitmap(&type_bitmap(&types)).unwrap(), types);
        // RFC 4034 section 4.3 example: A MX RRSIG NSEC TYPE1234.
        let b = type_bitmap(&[1, 15, 46, 47, 1234]);
        assert_eq!(hex(&b), "0006400100000003041b000000000000000000000000000000000000000000000000000020");
    }

    #[test]
    fn signature_times() {
        assert_eq!(parse_sig_time("20240101000000").unwrap(), 1_704_067_200);
        assert_eq!(sig_time(1_704_067_200), "20240101000000");
        assert_eq!(sig_time(parse_sig_time("21060207062815").unwrap()), "21060207062815");
        assert_eq!(parse_sig_time("21060207062815").unwrap(), u32::MAX);
    }
}
