//! Domain names: a list of labels, compared without regard to ASCII case and ordered in DNSSEC
//! canonical order (RFC 4034 section 6.1), so a sorted map of names keeps every name's
//! descendants right after it.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

#[derive(Clone, Default)]
pub struct Name {
    /// Labels from the leftmost (most specific) to the rightmost; the root has none.
    labels: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameError(pub String);

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NameError {}

pub const MAX_LABEL: usize = 63;
pub const MAX_WIRE: usize = 255;

impl Name {
    pub fn root() -> Name {
        Name { labels: Vec::new() }
    }

    /// Builds a name from labels, checking the length limits.
    pub fn from_labels(labels: Vec<Vec<u8>>) -> Result<Name, NameError> {
        for l in &labels {
            if l.is_empty() {
                return Err(NameError("empty label".into()));
            }
            if l.len() > MAX_LABEL {
                return Err(NameError(format!("label longer than {MAX_LABEL} bytes")));
            }
        }
        let n = Name { labels };
        if n.wire_len() > MAX_WIRE {
            return Err(NameError(format!("name longer than {MAX_WIRE} bytes")));
        }
        Ok(n)
    }

    /// Parses presentation format. An absolute name ends with `.`; a relative one is completed
    /// with `origin` (an error without one). `@` is the origin. `\X` and `\DDD` escapes are
    /// understood.
    pub fn parse(text: &str, origin: Option<&Name>) -> Result<Name, NameError> {
        if text == "@" {
            return origin.cloned().ok_or_else(|| NameError("@ used without an origin".into()));
        }
        if text == "." {
            return Ok(Name::root());
        }
        if text.is_empty() {
            return Err(NameError("empty name".into()));
        }
        let b = text.as_bytes();
        let mut labels = Vec::new();
        let mut cur = Vec::new();
        let mut absolute = false;
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'\\' => {
                    if i + 4 <= b.len() && b[i + 1..i + 4].iter().all(u8::is_ascii_digit) {
                        let v: u32 = std::str::from_utf8(&b[i + 1..i + 4]).unwrap().parse().unwrap();
                        if v > 255 {
                            return Err(NameError(format!("escape \\{v} is more than 255")));
                        }
                        cur.push(v as u8);
                        i += 4;
                    } else if i + 1 < b.len() {
                        cur.push(b[i + 1]);
                        i += 2;
                    } else {
                        return Err(NameError("name ends with a backslash".into()));
                    }
                }
                b'.' => {
                    if cur.is_empty() {
                        return Err(NameError(format!("empty label in '{text}'")));
                    }
                    labels.push(std::mem::take(&mut cur));
                    if i + 1 == b.len() {
                        absolute = true;
                    }
                    i += 1;
                }
                c => {
                    cur.push(c);
                    i += 1;
                }
            }
        }
        if !cur.is_empty() {
            labels.push(cur);
        }
        if !absolute {
            match origin {
                Some(o) => labels.extend(o.labels.iter().cloned()),
                None => return Err(NameError(format!("relative name '{text}' without an origin"))),
            }
        }
        Name::from_labels(labels).map_err(|e| NameError(format!("'{text}': {}", e.0)))
    }

    /// Parses an absolute name, adding the final dot if it is missing (for command lines).
    pub fn parse_fqdn(text: &str) -> Result<Name, NameError> {
        Name::parse(text, Some(&Name::root()))
    }

    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }

    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    /// Length in wire format: each label with its length byte, plus the root's zero byte.
    pub fn wire_len(&self) -> usize {
        self.labels.iter().map(|l| l.len() + 1).sum::<usize>() + 1
    }

    pub fn parent(&self) -> Option<Name> {
        if self.labels.is_empty() {
            None
        } else {
            Some(Name { labels: self.labels[1..].to_vec() })
        }
    }

    /// The name with its leftmost `n` labels removed.
    pub fn trim(&self, n: usize) -> Name {
        Name { labels: self.labels[n.min(self.labels.len())..].to_vec() }
    }

    /// `label.self`.
    pub fn prepend(&self, label: &[u8]) -> Result<Name, NameError> {
        let mut labels = vec![label.to_vec()];
        labels.extend(self.labels.iter().cloned());
        Name::from_labels(labels)
    }

    /// True if `self` is `other` or lies below it.
    pub fn is_subdomain_of(&self, other: &Name) -> bool {
        if other.labels.len() > self.labels.len() {
            return false;
        }
        let skip = self.labels.len() - other.labels.len();
        self.labels[skip..].iter().zip(&other.labels).all(|(a, b)| a.eq_ignore_ascii_case(b))
    }

    pub fn is_wildcard(&self) -> bool {
        self.labels.first().is_some_and(|l| l == b"*")
    }

    /// The name with its labels lowercased (for compression keys and printing in canonical form).
    pub fn to_lowercase(&self) -> Name {
        Name { labels: self.labels.iter().map(|l| l.to_ascii_lowercase()).collect() }
    }

    /// Wire format without compression.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.wire_len());
        for l in &self.labels {
            out.push(l.len() as u8);
            out.extend_from_slice(l);
        }
        out.push(0);
        out
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Name) -> bool {
        self.labels.len() == other.labels.len() && self.labels.iter().zip(&other.labels).all(|(a, b)| a.eq_ignore_ascii_case(b))
    }
}

impl Eq for Name {}

impl Hash for Name {
    fn hash<H: Hasher>(&self, h: &mut H) {
        h.write_usize(self.labels.len());
        for l in &self.labels {
            h.write_usize(l.len());
            for c in l {
                h.write_u8(c.to_ascii_lowercase());
            }
        }
    }
}

impl Ord for Name {
    /// Canonical order: compare labels from the right, each as lowercased bytes; a name sorts
    /// before its own descendants.
    fn cmp(&self, other: &Name) -> Ordering {
        let mut a = self.labels.iter().rev();
        let mut b = other.labels.iter().rev();
        loop {
            match (a.next(), b.next()) {
                (None, None) => return Ordering::Equal,
                (None, Some(_)) => return Ordering::Less,
                (Some(_), None) => return Ordering::Greater,
                (Some(x), Some(y)) => {
                    let o = x.iter().map(u8::to_ascii_lowercase).cmp(y.iter().map(u8::to_ascii_lowercase));
                    if o != Ordering::Equal {
                        return o;
                    }
                }
            }
        }
    }
}

impl PartialOrd for Name {
    fn partial_cmp(&self, other: &Name) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Name {
    /// Presentation format, absolute (ending with a dot), escaping what needs it.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.labels.is_empty() {
            return f.write_str(".");
        }
        for l in &self.labels {
            for &c in l {
                match c {
                    b'.' | b'\\' | b'(' | b')' | b';' | b' ' | b'"' | b'@' | b'$' => write!(f, "\\{}", c as char)?,
                    0x21..=0x7e => write!(f, "{}", c as char)?,
                    _ => write!(f, "\\{c:03}")?,
                }
            }
            f.write_str(".")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Name({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        Name::parse_fqdn(s).unwrap()
    }

    #[test]
    fn parse_and_print() {
        let origin = n("example.com.");
        assert_eq!(Name::parse("www", Some(&origin)).unwrap().to_string(), "www.example.com.");
        assert_eq!(Name::parse("@", Some(&origin)).unwrap(), origin);
        assert_eq!(Name::parse("a\\.b.c.", None).unwrap().label_count(), 2);
        assert_eq!(Name::parse("a\\.b.c.", None).unwrap().to_string(), "a\\.b.c.");
        assert_eq!(Name::parse("\\065bc.", None).unwrap().to_string(), "Abc.");
        assert_eq!(Name::parse("x\\000y.", None).unwrap().to_string(), "x\\000y.");
        assert!(Name::parse("a..b.", None).is_err());
        assert!(Name::parse("rel", None).is_err());
        assert!(Name::parse(&format!("{}.", "a".repeat(64)), None).is_err());
        let long = format!("{}.", vec!["a".repeat(63); 4].join("."));
        assert!(Name::parse(&long, None).is_err(), "4 x 64 + 1 = 257 bytes");
    }

    #[test]
    fn equality_ignores_case() {
        assert_eq!(n("WWW.Example.COM"), n("www.example.com"));
        let mut h = std::collections::HashSet::new();
        h.insert(n("A.b"));
        assert!(h.contains(&n("a.B")));
    }

    #[test]
    fn canonical_order_from_rfc4034() {
        // The example list in RFC 4034 section 6.1, in order.
        let names = [
            "example",
            "a.example",
            "yljkjljk.a.example",
            "Z.a.example",
            "zABC.a.EXAMPLE",
            "z.example",
            "\\001.z.example",
            "*.z.example",
            "\\200.z.example",
        ];
        let parsed: Vec<Name> = names.iter().map(|s| n(s)).collect();
        let mut sorted = parsed.clone();
        sorted.reverse();
        sorted.sort();
        assert_eq!(sorted, parsed);
    }

    #[test]
    fn subdomains() {
        assert!(n("a.b.c").is_subdomain_of(&n("B.c")));
        assert!(n("b.c").is_subdomain_of(&n("b.c")));
        assert!(!n("ab.c").is_subdomain_of(&n("b.c")));
        assert!(n("x").is_subdomain_of(&Name::root()));
    }
}
