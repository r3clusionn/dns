//! Zone files (RFC 1035 section 5, with `$TTL` from RFC 2308 and the generic syntax of
//! RFC 3597) and the in-memory zone they load into.

use std::collections::BTreeMap;
use std::fmt;

use crate::name::Name;
use crate::rdata::{self, class, parse_ttl, rtype, RData, Token};
use crate::wire::Record;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for ZoneError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.line > 0 {
            write!(f, "line {}: {}", self.line, self.message)
        } else {
            f.write_str(&self.message)
        }
    }
}

impl std::error::Error for ZoneError {}

/// The records of one name and type. All share one TTL (RFC 2181 section 5.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RRset {
    pub ttl: u32,
    pub data: Vec<RData>,
}

/// The data at one name. Signatures are kept as one set per type they cover (each with its own
/// TTL), the way they travel with that type's records.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Node {
    rrsets: BTreeMap<u32, RRset>,
}

/// The map key: the type, plus the covered type above it for RRSIG.
fn key(d: &RData) -> u32 {
    match d {
        RData::Rrsig { type_covered, .. } => (*type_covered as u32) << 16 | rtype::RRSIG as u32,
        _ => d.rtype() as u32,
    }
}

impl Node {
    /// The set of type `t` (for RRSIG, use [`Node::sets_of`]).
    pub fn get(&self, t: u16) -> Option<&RRset> {
        self.rrsets.get(&(t as u32))
    }

    pub fn has(&self, t: u16) -> bool {
        self.rrsets.keys().any(|&k| k as u16 == t)
    }

    /// Every set of type `t`: one, or for RRSIG one per covered type.
    pub fn sets_of(&self, t: u16) -> impl Iterator<Item = &RRset> {
        self.rrsets.iter().filter(move |(&k, _)| k as u16 == t).map(|(_, s)| s)
    }

    /// All sets with their types.
    pub fn sets(&self) -> impl Iterator<Item = (u16, &RRset)> {
        self.rrsets.iter().map(|(&k, s)| (k as u16, s))
    }
}

#[derive(Clone, Debug)]
pub struct Zone {
    pub origin: Name,
    nodes: BTreeMap<Name, Node>,
    /// Problems that did not stop loading (differing TTLs in one RRset).
    pub warnings: Vec<String>,
}

/// One logical line: tokens after joining parenthesised continuation lines.
struct Entry {
    line: usize,
    blank_owner: bool,
    tokens: Vec<Token>,
}

fn tokenize(text: &str) -> Result<Vec<Entry>, ZoneError> {
    let mut out = Vec::new();
    let mut tokens: Vec<Token> = Vec::new();
    let mut cur = String::new();
    let mut have_cur = false;
    let mut depth = 0usize;
    let mut line = 1usize;
    let mut entry_line = 1usize;
    let mut blank_owner = false;
    let mut at_line_start = true;
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    let err = |line: usize, m: &str| ZoneError { line, message: m.to_string() };
    macro_rules! end_token {
        () => {
            if have_cur {
                tokens.push(Token { text: std::mem::take(&mut cur), quoted: false });
                have_cur = false;
            }
        };
    }
    while i < chars.len() {
        let c = chars[i];
        if at_line_start && depth == 0 {
            entry_line = line;
            blank_owner = c == ' ' || c == '\t';
            at_line_start = false;
        }
        match c {
            '\n' => {
                end_token!();
                line += 1;
                if depth == 0 {
                    if !tokens.is_empty() {
                        out.push(Entry { line: entry_line, blank_owner, tokens: std::mem::take(&mut tokens) });
                    }
                    at_line_start = true;
                }
                i += 1;
            }
            '\r' | ' ' | '\t' => {
                end_token!();
                i += 1;
            }
            ';' => {
                end_token!();
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '(' => {
                end_token!();
                depth += 1;
                i += 1;
            }
            ')' => {
                end_token!();
                if depth == 0 {
                    return Err(err(line, "')' without '('"));
                }
                depth -= 1;
                i += 1;
            }
            '"' => {
                end_token!();
                let mut s = String::new();
                i += 1;
                loop {
                    match chars.get(i) {
                        None => return Err(err(line, "unterminated quoted string")),
                        Some('"') => {
                            i += 1;
                            break;
                        }
                        Some('\\') => {
                            s.push('\\');
                            if let Some(&n) = chars.get(i + 1) {
                                s.push(n);
                                if n == '\n' {
                                    line += 1;
                                }
                            }
                            i += 2;
                        }
                        Some(&ch) => {
                            if ch == '\n' {
                                line += 1;
                            }
                            s.push(ch);
                            i += 1;
                        }
                    }
                }
                tokens.push(Token { text: s, quoted: true });
            }
            '\\' => {
                // Keep the escape for the name or string parser; it also protects the next char.
                cur.push('\\');
                if let Some(&n) = chars.get(i + 1) {
                    cur.push(n);
                }
                have_cur = true;
                i += 2;
            }
            _ => {
                cur.push(c);
                have_cur = true;
                i += 1;
            }
        }
    }
    if have_cur {
        tokens.push(Token { text: cur, quoted: false });
    }
    if depth != 0 {
        return Err(err(line, "'(' without ')'"));
    }
    if !tokens.is_empty() {
        out.push(Entry { line: entry_line, blank_owner, tokens });
    }
    Ok(out)
}

impl Zone {
    pub fn new(origin: Name) -> Zone {
        Zone { origin, nodes: BTreeMap::new(), warnings: Vec::new() }
    }

    /// Parses a zone file whose apex is `origin`. Checks that the zone has exactly one SOA, at
    /// the apex, that it has NS records there, that every name is inside the zone, and that no
    /// name has a CNAME next to other data.
    pub fn parse(text: &str, origin: &Name) -> Result<Zone, ZoneError> {
        let mut zone = Zone::new(origin.clone());
        let mut cur_origin = origin.clone();
        let mut default_ttl: Option<u32> = None;
        let mut last_ttl: Option<u32> = None;
        let mut last_owner: Option<Name> = None;
        for e in tokenize(text)? {
            let err = |m: String| ZoneError { line: e.line, message: m };
            let t = &e.tokens;
            if !e.blank_owner && t[0].text.starts_with('$') && !t[0].quoted {
                match t[0].text.to_ascii_uppercase().as_str() {
                    "$ORIGIN" => {
                        let n = t.get(1).ok_or_else(|| err("$ORIGIN needs a name".into()))?;
                        cur_origin = Name::parse(&n.text, Some(&cur_origin)).map_err(|x| err(x.to_string()))?;
                    }
                    "$TTL" => {
                        let v = t.get(1).ok_or_else(|| err("$TTL needs a value".into()))?;
                        default_ttl = Some(parse_ttl(&v.text).ok_or_else(|| err(format!("bad $TTL '{}'", v.text)))?);
                    }
                    d => return Err(err(format!("{d} is not supported"))),
                }
                continue;
            }
            let mut i = 0;
            let owner = if e.blank_owner {
                last_owner.clone().ok_or_else(|| err("the first record has no owner name".into()))?
            } else {
                i = 1;
                Name::parse(&t[0].text, Some(&cur_origin)).map_err(|x| err(x.to_string()))?
            };
            // TTL and class, in either order, both optional.
            let mut ttl = None;
            let mut cls = None;
            while i < t.len() && !t[i].quoted {
                if ttl.is_none() && t[i].text.as_bytes()[0].is_ascii_digit() {
                    ttl = Some(parse_ttl(&t[i].text).ok_or_else(|| err(format!("bad TTL '{}'", t[i].text)))?);
                } else if cls.is_none()
                    && rdata::type_from_name(&t[i].text).is_none()
                    && rdata::class_from_name(&t[i].text).is_some()
                {
                    cls = rdata::class_from_name(&t[i].text);
                } else {
                    break;
                }
                i += 1;
            }
            let ty_tok = t.get(i).ok_or_else(|| err("record has no type".into()))?;
            let ty = rdata::type_from_name(&ty_tok.text).ok_or_else(|| err(format!("unknown type '{}'", ty_tok.text)))?;
            if matches!(ty, rtype::OPT | rtype::AXFR | rtype::IXFR | rtype::ANY) {
                return Err(err(format!("{} cannot appear in a zone", ty_tok.text)));
            }
            let data = RData::parse(ty, &t[i + 1..], &cur_origin).map_err(err)?;
            if cls.unwrap_or(class::IN) != class::IN {
                return Err(err("only class IN is supported".into()));
            }
            // The TTL: as given; else $TTL; else the last one given; else (for the SOA itself)
            // its minimum field.
            let ttl = match (ttl, default_ttl, last_ttl, &data) {
                (Some(v), ..) => v,
                (None, Some(v), ..) => v,
                (None, None, Some(v), _) => v,
                (None, None, None, RData::Soa { minimum, .. }) => *minimum,
                _ => return Err(err("no TTL given and no $TTL before it".into())),
            };
            last_ttl = Some(ttl);
            last_owner = Some(owner.clone());
            zone.add(owner, ttl, data).map_err(err)?;
        }
        zone.check().map_err(|m| ZoneError { line: 0, message: m })?;
        Ok(zone)
    }

    /// Adds one record. Repeats of the same data are dropped; a differing TTL in one RRset is
    /// lowered to the smallest, with a warning.
    pub fn add(&mut self, owner: Name, ttl: u32, data: RData) -> Result<(), String> {
        if !owner.is_subdomain_of(&self.origin) {
            return Err(format!("{owner} is outside the zone {}", self.origin));
        }
        let t = data.rtype();
        let node = self.nodes.entry(owner.clone()).or_default();
        let dnssec = |t: u16| matches!(t, rtype::RRSIG | rtype::NSEC | 50);
        if t == rtype::CNAME && node.sets().any(|(k, _)| k != rtype::CNAME && !dnssec(k))
            || t != rtype::CNAME && !dnssec(t) && node.has(rtype::CNAME)
        {
            return Err(format!("{owner} has a CNAME and other data"));
        }
        let set = node.rrsets.entry(key(&data)).or_insert_with(|| RRset { ttl, data: Vec::new() });
        if set.ttl != ttl && !set.data.is_empty() {
            self.warnings.push(format!(
                "{owner} {}: TTLs differ ({} and {ttl}), using the smaller",
                rdata::type_name(t),
                set.ttl
            ));
            set.ttl = set.ttl.min(ttl);
        }
        if t == rtype::CNAME && !set.data.is_empty() && !set.data.contains(&data) {
            return Err(format!("{owner} has more than one CNAME"));
        }
        if !set.data.contains(&data) {
            set.data.push(data);
        }
        Ok(())
    }

    fn check(&self) -> Result<(), String> {
        let apex = self.nodes.get(&self.origin).ok_or_else(|| format!("no records at the apex {}", self.origin))?;
        match apex.get(rtype::SOA) {
            Some(s) if s.data.len() == 1 => {}
            Some(_) => return Err("more than one SOA record".into()),
            None => return Err(format!("no SOA record at {}", self.origin)),
        }
        if !apex.has(rtype::NS) {
            return Err(format!("no NS records at {}", self.origin));
        }
        if let Some((n, _)) = self.nodes.iter().find(|(n, node)| *n != &self.origin && node.has(rtype::SOA)) {
            return Err(format!("SOA record at {n}, which is not the apex"));
        }
        Ok(())
    }

    pub fn node(&self, n: &Name) -> Option<&Node> {
        self.nodes.get(n)
    }

    pub fn get(&self, n: &Name, t: u16) -> Option<&RRset> {
        self.nodes.get(n)?.get(t)
    }

    /// True if some name below `n` has data: then `n` exists as an empty non-terminal.
    pub fn has_descendants(&self, n: &Name) -> bool {
        // In canonical order a name's descendants follow it directly.
        use std::ops::Bound::{Excluded, Unbounded};
        self.nodes.range((Excluded(n), Unbounded)).next().is_some_and(|(m, _)| m.is_subdomain_of(n))
    }

    /// True if `n` has data or is an empty non-terminal.
    pub fn exists(&self, n: &Name) -> bool {
        self.nodes.contains_key(n) || self.has_descendants(n)
    }

    pub fn soa(&self) -> (&RRset, &RData) {
        let s = self.get(&self.origin, rtype::SOA).expect("checked when loaded");
        (s, &s.data[0])
    }

    /// Every record, in canonical order with the SOA first (the body of a zone transfer).
    pub fn records(&self) -> Vec<Record> {
        let mut out = Vec::new();
        let (soa, d) = self.soa();
        out.push(Record::new(self.origin.clone(), soa.ttl, d.clone()));
        for (name, node) in &self.nodes {
            for (t, set) in node.sets() {
                if t == rtype::SOA && *name == self.origin {
                    continue;
                }
                for d in &set.data {
                    out.push(Record::new(name.clone(), set.ttl, d.clone()));
                }
            }
        }
        out
    }

    pub fn len(&self) -> usize {
        self.nodes.values().flat_map(|n| n.rrsets.values()).map(|s| s.data.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn names(&self) -> impl Iterator<Item = &Name> {
        self.nodes.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZONE: &str = r#"
$TTL 1h
$ORIGIN example.com.
@   IN  SOA ns1 hostmaster (
            2026100401 ; serial
            7200 3600 1209600 300 )
    IN  NS  ns1
    IN  NS  ns2.other.net.
    IN  MX  10 mail
ns1     A   192.0.2.1
mail 300 IN A 192.0.2.25
        AAAA 2001:db8::25
www     CNAME   @
txt     TXT "hello world" "with \"quotes\"" plain
*.wild  A   192.0.2.99
sub     NS  ns.sub
ns.sub  A   192.0.2.53
caa     CAA 0 issue "ca.example"
gen     TYPE65280 \# 4 0A000001
"#;

    #[test]
    fn parses_a_typical_zone() {
        let o = Name::parse_fqdn("example.com").unwrap();
        let z = Zone::parse(ZONE, &o).unwrap();
        let n = |s: &str| Name::parse_fqdn(s).unwrap();
        assert_eq!(z.get(&o, rtype::NS).unwrap().data.len(), 2);
        assert_eq!(z.get(&o, rtype::NS).unwrap().ttl, 3600);
        let mail = z.get(&n("mail.example.com"), rtype::AAAA).unwrap();
        assert_eq!(mail.ttl, 3600, "without a TTL of its own a record takes $TTL, not the last TTL given");
        assert_eq!(z.get(&n("mail.example.com"), rtype::A).unwrap().ttl, 300);
        assert_eq!(z.get(&n("www.example.com"), rtype::CNAME).unwrap().data[0], RData::Cname(o.clone()));
        let txt = &z.get(&n("txt.example.com"), rtype::TXT).unwrap().data[0];
        assert_eq!(txt.to_text(), r#""hello world" "with \"quotes\"" "plain""#);
        assert_eq!(z.get(&n("gen.example.com"), 65280).unwrap().data[0].to_text(), "\\# 4 0a000001");
        let RData::Soa { serial, minimum, .. } = z.soa().1 else { panic!() };
        assert_eq!((*serial, *minimum), (2026100401, 300));
        assert!(z.has_descendants(&n("wild.example.com")));
        assert!(!z.has_descendants(&n("www.example.com")));
        assert!(z.exists(&n("sub.example.com")));
        assert_eq!(z.records().len(), z.len());
    }

    #[test]
    fn errors_name_the_line() {
        let o = Name::parse_fqdn("example.com").unwrap();
        let bad = "$TTL 60\n@ SOA a b 1 2 3 4 5\n@ NS a\nx A 999.1.1.1\n";
        let e = Zone::parse(bad, &o).unwrap_err();
        assert_eq!(e.line, 4);
        let e = Zone::parse("$TTL 60\n@ SOA a b 1 2 3 4 5\n@ NS a\nw CNAME a\nw A 1.2.3.4\n", &o).unwrap_err();
        assert!(e.message.contains("CNAME and other data"), "{e}");
        let e = Zone::parse("$TTL 60\n@ SOA a b 1 2 3 4 5\n@ NS a\nx.other. A 1.2.3.4\n", &o).unwrap_err();
        assert!(e.message.contains("outside the zone"), "{e}");
        let e = Zone::parse("$TTL 60\n@ NS a\n", &o).unwrap_err();
        assert!(e.message.contains("SOA"), "{e}");
        assert!(Zone::parse("@ 60 SOA a b ( 1 2 3 4 5\n", &o).is_err());
    }
}
