//! The resolver's cache: RRsets and negative answers (RFC 2308), each kept until its TTL runs
//! out and handed back with the TTL counted down. Data is ranked by where it came from
//! (RFC 2181 section 5.4.1) so that glue never replaces an authoritative answer, and only
//! answers are given to clients.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::name::Name;
use crate::wire::Record;

/// Where cached data came from, least trusted first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rank {
    /// Addresses in the additional section of a referral.
    Glue,
    /// NS records in the authority section of a referral.
    Referral,
    /// The answer section of an answer.
    Answer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cached {
    /// The records of one RRset, TTLs counted down.
    Records(Vec<Record>),
    /// The name exists but has no data of this type; the SOA to put in the authority section.
    NoData(Option<Record>),
    /// The name does not exist (for any type).
    NxDomain(Option<Record>),
}

struct Entry {
    data: Cached,
    rank: Rank,
    stored: Instant,
    ttl: u32,
}

/// Limits on how long things are kept.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_entries: usize,
    pub max_ttl: u32,
    pub max_negative_ttl: u32,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { max_entries: 100_000, max_ttl: 86_400, max_negative_ttl: 3600 }
    }
}

/// The key for "the name does not exist", whatever the type.
const NX: u16 = 0;

pub struct Cache {
    map: Mutex<HashMap<(Name, u16), Entry>>,
    limits: Limits,
}

impl Cache {
    pub fn new(limits: Limits) -> Cache {
        Cache { map: Mutex::new(HashMap::new()), limits }
    }

    pub fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Looks up `name`/`t` with at least `min_rank`. A cached NXDOMAIN answers every type.
    pub fn get(&self, name: &Name, t: u16, min_rank: Rank) -> Option<Cached> {
        let map = self.map.lock().unwrap();
        let now = Instant::now();
        for key in [(name.clone(), t), (name.clone(), NX)] {
            if let Some(e) = map.get(&key) {
                let age = now.duration_since(e.stored).as_secs();
                if age >= e.ttl as u64 || e.rank < min_rank {
                    continue;
                }
                let left = e.ttl - age as u32;
                let fix = |r: &Record| Record { ttl: r.ttl.min(left), ..r.clone() };
                return Some(match &e.data {
                    Cached::Records(v) => Cached::Records(v.iter().map(fix).collect()),
                    Cached::NoData(s) => Cached::NoData(s.as_ref().map(fix)),
                    Cached::NxDomain(s) => Cached::NxDomain(s.as_ref().map(fix)),
                });
            }
        }
        None
    }

    /// Stores one RRset (all records must share name and type). Replaces what is there unless
    /// that is better ranked and still valid.
    pub fn put_rrset(&self, records: Vec<Record>, rank: Rank) {
        let Some(first) = records.first() else { return };
        let key = (first.name.clone(), first.rtype());
        let ttl = records.iter().map(|r| r.ttl).min().unwrap_or(0).min(self.limits.max_ttl);
        if ttl == 0 {
            return;
        }
        self.put(key, Entry { data: Cached::Records(records), rank, stored: Instant::now(), ttl });
    }

    /// Stores a negative answer. Its TTL is the SOA's (RFC 2308 section 5), capped.
    pub fn put_negative(&self, name: &Name, t: u16, nxdomain: bool, soa: Option<Record>) {
        let ttl = soa.as_ref().map_or(0, |s| s.ttl).min(self.limits.max_negative_ttl);
        if ttl == 0 {
            return;
        }
        let (key, data) =
            if nxdomain { ((name.clone(), NX), Cached::NxDomain(soa)) } else { ((name.clone(), t), Cached::NoData(soa)) };
        self.put(key, Entry { data, rank: Rank::Answer, stored: Instant::now(), ttl });
    }

    fn put(&self, key: (Name, u16), e: Entry) {
        let mut map = self.map.lock().unwrap();
        if let Some(old) = map.get(&key) {
            let alive = old.stored.elapsed() < Duration::from_secs(old.ttl as u64);
            if alive && old.rank > e.rank {
                return;
            }
        }
        if map.len() >= self.limits.max_entries && !map.contains_key(&key) {
            // Drop what has expired; if that is not enough, drop a tenth at random (hash order).
            map.retain(|_, v| v.stored.elapsed() < Duration::from_secs(v.ttl as u64));
            if map.len() >= self.limits.max_entries {
                let drop: Vec<(Name, u16)> = map.keys().take(self.limits.max_entries / 10 + 1).cloned().collect();
                for k in drop {
                    map.remove(&k);
                }
            }
        }
        map.insert(key, e);
    }

    pub fn clear(&self) {
        self.map.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata::{rtype, RData};
    use std::net::Ipv4Addr;

    fn a(name: &str, ttl: u32, last: u8) -> Record {
        Record::new(Name::parse_fqdn(name).unwrap(), ttl, RData::A(Ipv4Addr::new(192, 0, 2, last)))
    }

    #[test]
    fn ranks_protect_answers_from_glue() {
        let c = Cache::new(Limits::default());
        c.put_rrset(vec![a("ns.example", 300, 1)], Rank::Answer);
        c.put_rrset(vec![a("ns.example", 300, 66)], Rank::Glue);
        let Some(Cached::Records(v)) = c.get(&Name::parse_fqdn("ns.example").unwrap(), rtype::A, Rank::Glue) else { panic!() };
        assert_eq!(v[0].data, RData::A(Ipv4Addr::new(192, 0, 2, 1)));
        // Glue alone is not an answer for a client.
        c.put_rrset(vec![a("glue.example", 300, 2)], Rank::Glue);
        assert!(c.get(&Name::parse_fqdn("glue.example").unwrap(), rtype::A, Rank::Answer).is_none());
    }

    #[test]
    fn nxdomain_answers_every_type_and_zero_ttl_is_not_kept() {
        let c = Cache::new(Limits::default());
        let soa = a("example", 60, 0); // any record will do as the SOA stand-in here
        c.put_negative(&Name::parse_fqdn("nope.example").unwrap(), rtype::A, true, Some(soa));
        assert!(matches!(c.get(&Name::parse_fqdn("nope.example").unwrap(), rtype::MX, Rank::Answer), Some(Cached::NxDomain(_))));
        c.put_rrset(vec![a("zero.example", 0, 1)], Rank::Answer);
        assert!(c.is_empty() || c.get(&Name::parse_fqdn("zero.example").unwrap(), rtype::A, Rank::Glue).is_none());
    }

    #[test]
    fn size_limit() {
        let c = Cache::new(Limits { max_entries: 100, ..Limits::default() });
        for i in 0..1000 {
            c.put_rrset(vec![a(&format!("h{i}.example"), 300, 1)], Rank::Answer);
        }
        assert!(c.len() <= 100);
    }
}
