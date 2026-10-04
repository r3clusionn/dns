//! DNS messages in wire format (RFC 1035 section 4, EDNS from RFC 6891): decoding with checks on
//! every length and compression pointer, and encoding with name compression and truncation.

use std::collections::HashMap;
use std::fmt;

use crate::name::{Name, MAX_WIRE};
use crate::rdata::{rtype, RData};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError(pub String);

impl WireError {
    pub fn new(m: impl Into<String>) -> WireError {
        WireError(m.into())
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WireError {}

pub mod rcode {
    pub const NOERROR: u16 = 0;
    pub const FORMERR: u16 = 1;
    pub const SERVFAIL: u16 = 2;
    pub const NXDOMAIN: u16 = 3;
    pub const NOTIMP: u16 = 4;
    pub const REFUSED: u16 = 5;
    pub const NOTAUTH: u16 = 9;
    pub const BADVERS: u16 = 16;

    pub fn name(r: u16) -> String {
        match r {
            NOERROR => "NOERROR".into(),
            FORMERR => "FORMERR".into(),
            SERVFAIL => "SERVFAIL".into(),
            NXDOMAIN => "NXDOMAIN".into(),
            NOTIMP => "NOTIMP".into(),
            REFUSED => "REFUSED".into(),
            NOTAUTH => "NOTAUTH".into(),
            BADVERS => "BADVERS".into(),
            _ => format!("RCODE{r}"),
        }
    }
}

/// Reads a message, keeping the whole buffer for compression pointers.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.buf.len()).ok_or_else(|| WireError::new("message ends early"))?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    /// Everything up to `end` (the end of the current record's data).
    pub fn rest(&mut self, end: usize) -> Result<&'a [u8], WireError> {
        if end < self.pos {
            return Err(WireError::new("record data overrun"));
        }
        self.bytes(end - self.pos)
    }

    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.bytes(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, WireError> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32, WireError> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a possibly compressed name. Every pointer must point strictly backwards to before
    /// where the current name started, which rules out loops; the expanded name must fit in 255
    /// bytes.
    pub fn name(&mut self) -> Result<Name, WireError> {
        let mut labels = Vec::new();
        let mut pos = self.pos;
        let mut limit = self.pos; // pointers must go below this
        let mut jumped = false;
        let mut total = 1;
        loop {
            let len = *self.buf.get(pos).ok_or_else(|| WireError::new("name runs past the message"))? as usize;
            match len >> 6 {
                0 => {
                    if len == 0 {
                        pos += 1;
                        break;
                    }
                    let label =
                        self.buf.get(pos + 1..pos + 1 + len).ok_or_else(|| WireError::new("label runs past the message"))?;
                    total += len + 1;
                    if total > MAX_WIRE {
                        return Err(WireError::new("name longer than 255 bytes"));
                    }
                    labels.push(label.to_vec());
                    pos += 1 + len;
                }
                3 => {
                    let b2 = *self.buf.get(pos + 1).ok_or_else(|| WireError::new("pointer runs past the message"))? as usize;
                    let target = (len & 0x3f) << 8 | b2;
                    if target >= limit {
                        return Err(WireError::new("compression pointer does not point backwards"));
                    }
                    if !jumped {
                        self.pos = pos + 2;
                        jumped = true;
                    }
                    limit = target;
                    pos = target;
                }
                _ => return Err(WireError::new("unknown label type")),
            }
        }
        if !jumped {
            self.pos = pos;
        }
        Name::from_labels(labels).map_err(|e| WireError::new(e.0))
    }
}

/// Builds a message, remembering where names were written so later ones can point at them.
pub struct Writer {
    buf: Vec<u8>,
    names: HashMap<Name, u16>,
    compress: bool,
}

impl Default for Writer {
    fn default() -> Writer {
        Writer::new()
    }
}

impl Writer {
    pub fn new() -> Writer {
        Writer { buf: Vec::with_capacity(512), names: HashMap::new(), compress: true }
    }

    /// A writer that never compresses names (record data on its own, as in a zone file).
    pub fn uncompressed() -> Writer {
        Writer { compress: false, ..Writer::new() }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    pub fn set_u16(&mut self, at: usize, v: u16) {
        self.buf[at..at + 2].copy_from_slice(&v.to_be_bytes());
    }

    /// Writes a name. With `compress`, the longest suffix already in the message becomes a
    /// pointer; either way the suffixes written here become targets for later names.
    pub fn name(&mut self, n: &Name, compress: bool) {
        let labels = n.labels();
        for (i, label) in labels.iter().enumerate() {
            let suffix = n.trim(i);
            if compress && self.compress {
                if let Some(&off) = self.names.get(&suffix) {
                    self.u16(0xc000 | off);
                    return;
                }
            }
            if self.buf.len() < 0x3fff {
                self.names.entry(suffix).or_insert(self.buf.len() as u16);
            }
            self.buf.push(label.len() as u8);
            self.buf.extend_from_slice(label);
        }
        self.buf.push(0);
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    pub fn truncate(&mut self, len: usize) {
        self.buf.truncate(len);
        self.names.retain(|_, &mut off| (off as usize) < len);
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    pub qr: bool,
    pub opcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub ad: bool,
    pub cd: bool,
    /// The full response code: the header's four bits plus EDNS's extended eight.
    pub rcode: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Question {
    pub name: Name,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Record {
    pub name: Name,
    pub class: u16,
    pub ttl: u32,
    pub data: RData,
}

impl Record {
    pub fn new(name: Name, ttl: u32, data: RData) -> Record {
        Record { name, class: crate::rdata::class::IN, ttl, data }
    }

    pub fn rtype(&self) -> u16 {
        self.data.rtype()
    }

    /// One zone-file line.
    pub fn to_text(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.name,
            self.ttl,
            crate::rdata::class_name(self.class),
            crate::rdata::type_name(self.rtype()),
            self.data.to_text()
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edns {
    pub udp_size: u16,
    pub version: u8,
    pub dnssec_ok: bool,
    pub options: Vec<(u16, Vec<u8>)>,
}

impl Default for Edns {
    fn default() -> Edns {
        Edns { udp_size: 1232, version: 0, dnssec_ok: false, options: Vec::new() }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
    pub edns: Option<Edns>,
}

impl Message {
    /// A query for one name and type, with EDNS.
    pub fn query(id: u16, name: Name, qtype: u16, rd: bool) -> Message {
        Message {
            header: Header { id, rd, ..Header::default() },
            questions: vec![Question { name, qtype, qclass: crate::rdata::class::IN }],
            edns: Some(Edns::default()),
            ..Message::default()
        }
    }

    /// The start of a response to `q`: same id, question, opcode and RD flag.
    pub fn response_to(q: &Message) -> Message {
        Message {
            header: Header {
                id: q.header.id,
                qr: true,
                opcode: q.header.opcode,
                rd: q.header.rd,
                cd: q.header.cd,
                ..Header::default()
            },
            questions: q.questions.clone(),
            edns: q.edns.as_ref().map(|_| Edns::default()),
            ..Message::default()
        }
    }

    pub fn decode(buf: &[u8]) -> Result<Message, WireError> {
        let mut r = Reader::new(buf);
        let id = r.u16()?;
        let flags = r.u16()?;
        let counts = [r.u16()?, r.u16()?, r.u16()?, r.u16()?];
        let mut m = Message {
            header: Header {
                id,
                qr: flags & 0x8000 != 0,
                opcode: ((flags >> 11) & 0xf) as u8,
                aa: flags & 0x0400 != 0,
                tc: flags & 0x0200 != 0,
                rd: flags & 0x0100 != 0,
                ra: flags & 0x0080 != 0,
                ad: flags & 0x0020 != 0,
                cd: flags & 0x0010 != 0,
                rcode: flags & 0xf,
            },
            ..Message::default()
        };
        for _ in 0..counts[0] {
            m.questions.push(Question { name: r.name()?, qtype: r.u16()?, qclass: r.u16()? });
        }
        for (section, &count) in counts[1..].iter().enumerate() {
            for _ in 0..count {
                let name = r.name()?;
                let t = r.u16()?;
                let class = r.u16()?;
                let ttl = r.u32()?;
                let len = r.u16()? as usize;
                if t == rtype::OPT {
                    if section != 2 || m.edns.is_some() || !name.is_root() {
                        return Err(WireError::new("misplaced or repeated OPT record"));
                    }
                    let end = r.pos() + len;
                    let mut options = Vec::new();
                    while r.pos() < end {
                        let code = r.u16()?;
                        let olen = r.u16()? as usize;
                        options.push((code, r.bytes(olen)?.to_vec()));
                    }
                    if r.pos() != end {
                        return Err(WireError::new("OPT options overrun"));
                    }
                    m.header.rcode |= ((ttl >> 24) as u16) << 4;
                    m.edns = Some(Edns { udp_size: class, version: (ttl >> 16) as u8, dnssec_ok: ttl & 0x8000 != 0, options });
                    continue;
                }
                let data = RData::decode(t, &mut r, len)?;
                let rec = Record { name, class, ttl, data };
                match section {
                    0 => m.answers.push(rec),
                    1 => m.authority.push(rec),
                    _ => m.additional.push(rec),
                }
            }
        }
        if r.pos() != buf.len() {
            return Err(WireError::new(format!("{} bytes after the last record", buf.len() - r.pos())));
        }
        Ok(m)
    }

    pub fn encode(&self) -> Vec<u8> {
        self.encode_limited(usize::MAX)
    }

    /// Encodes within `max` bytes. Whole records that do not fit are dropped from the end; if any
    /// answer or authority record had to go, the TC bit is set so the client retries over TCP
    /// (dropping only additional records does not need it, RFC 2181 section 9).
    pub fn encode_limited(&self, max: usize) -> Vec<u8> {
        let mut w = Writer::new();
        let h = &self.header;
        w.u16(h.id);
        let flags_at = w.len();
        w.u16(0);
        w.u16(self.questions.len() as u16);
        let counts_at = w.len();
        w.u16(0);
        w.u16(0);
        w.u16(0);
        for q in &self.questions {
            w.name(&q.name, true);
            w.u16(q.qtype);
            w.u16(q.qclass);
        }
        // Room for the OPT record, which must survive truncation.
        let opt_len = self.edns.as_ref().map_or(0, |e| 11 + e.options.iter().map(|(_, d)| 4 + d.len()).sum::<usize>());
        let budget = max.saturating_sub(opt_len);
        let mut counts = [0u16; 3];
        let mut tc = h.tc;
        'sections: for (s, recs) in [&self.answers, &self.authority, &self.additional].into_iter().enumerate() {
            for rec in recs {
                let before = w.len();
                write_record(&mut w, rec);
                if w.len() > budget {
                    w.truncate(before);
                    if s < 2 {
                        tc = true;
                    }
                    break 'sections;
                }
                counts[s] += 1;
            }
        }
        let mut additional = counts[2];
        if let Some(e) = &self.edns {
            w.u8(0);
            w.u16(rtype::OPT);
            w.u16(e.udp_size);
            w.u32(((h.rcode >> 4) as u32) << 24 | (e.version as u32) << 16 | if e.dnssec_ok { 0x8000 } else { 0 });
            let len: usize = e.options.iter().map(|(_, d)| 4 + d.len()).sum();
            w.u16(len as u16);
            for (code, d) in &e.options {
                w.u16(*code);
                w.u16(d.len() as u16);
                w.bytes(d);
            }
            additional += 1;
        }
        let flags = (h.qr as u16) << 15
            | ((h.opcode as u16) & 0xf) << 11
            | (h.aa as u16) << 10
            | (tc as u16) << 9
            | (h.rd as u16) << 8
            | (h.ra as u16) << 7
            | (h.ad as u16) << 5
            | (h.cd as u16) << 4
            | (h.rcode & 0xf);
        w.set_u16(flags_at, flags);
        w.set_u16(counts_at, counts[0]);
        w.set_u16(counts_at + 2, counts[1]);
        w.set_u16(counts_at + 4, additional);
        w.finish()
    }
}

fn write_record(w: &mut Writer, rec: &Record) {
    w.name(&rec.name, true);
    w.u16(rec.rtype());
    w.u16(rec.class);
    w.u32(rec.ttl);
    let len_at = w.len();
    w.u16(0);
    rec.data.encode(w);
    let len = w.len() - len_at - 2;
    w.set_u16(len_at, len as u16);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_loops_are_refused() {
        // Header, then a question whose name is a pointer to itself.
        let mut m = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend([0xc0, 12, 0, 1, 0, 1]);
        assert!(Message::decode(&m).unwrap_err().0.contains("backwards"));
        // Two names pointing at each other.
        let mut m = vec![0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0];
        m.extend([1, b'a', 0xc0, 20, 0, 1, 0, 1, 1, b'b', 0xc0, 12, 0, 1, 0, 1]);
        assert!(Message::decode(&m).is_err());
    }

    #[test]
    fn compression_shrinks_and_round_trips() {
        let n = |s: &str| Name::parse_fqdn(s).unwrap();
        let mut m = Message::query(7, n("www.example.com"), rtype::A, true);
        m.header.qr = true;
        for i in 0..5 {
            m.answers.push(Record::new(n("www.example.com"), 300, RData::Cname(n(&format!("host{i}.Example.com")))));
        }
        let b = m.encode();
        assert_eq!(Message::decode(&b).unwrap(), m);
        // Uncompressed the five CNAMEs alone would be over 5 * (17 + 10 + 19) bytes.
        assert!(b.len() < 160, "{}", b.len());
    }

    #[test]
    fn truncation_sets_tc_only_for_answers() {
        let n = |s: &str| Name::parse_fqdn(s).unwrap();
        let mut m = Message::query(1, n("big.example"), rtype::TXT, false);
        m.header.qr = true;
        for _ in 0..10 {
            m.answers.push(Record::new(n("big.example"), 60, RData::Txt(vec![vec![b'x'; 200]])));
        }
        let b = m.encode_limited(512);
        assert!(b.len() <= 512);
        let d = Message::decode(&b).unwrap();
        assert!(d.header.tc);
        assert!(d.answers.len() < 10);
        assert!(d.edns.is_some(), "the OPT record survives truncation");
    }
}
