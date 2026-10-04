//! Authoritative answers from loaded zones: the algorithm of RFC 1034 section 4.3.2 with
//! wildcards as clarified by RFC 4592, negative answers as in RFC 2308, and zone transfers.

use std::collections::HashMap;

use crate::name::Name;
use crate::rdata::{rtype, RData};
use crate::wire::{rcode, Record};
use crate::zone::{Node, Zone};

/// The parts of a response an authoritative lookup decides.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reply {
    pub rcode: u16,
    pub aa: bool,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
}

/// Longest CNAME chain followed inside one zone.
const MAX_CHAIN: usize = 16;

/// A set of zones, found by the longest origin that contains the query name.
#[derive(Default)]
pub struct Zones {
    zones: HashMap<Name, Zone>,
}

impl Zones {
    pub fn new() -> Zones {
        Zones::default()
    }

    pub fn insert(&mut self, z: Zone) {
        self.zones.insert(z.origin.clone(), z);
    }

    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    pub fn len(&self) -> usize {
        self.zones.len()
    }

    pub fn get(&self, origin: &Name) -> Option<&Zone> {
        self.zones.get(origin)
    }

    /// The most specific zone containing `n`.
    pub fn find(&self, n: &Name) -> Option<&Zone> {
        (0..=n.label_count()).map(|k| n.trim(k)).find_map(|anc| self.zones.get(&anc))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Zone> {
        self.zones.values()
    }
}

/// Answers `qname`/`qtype` from `zone` (which must contain `qname`).
pub fn answer(zone: &Zone, qname: &Name, qtype: u16) -> Reply {
    let mut r = Reply { aa: true, ..Reply::default() };
    let mut name = qname.clone();
    let mut seen = vec![name.clone()];
    loop {
        // A zone cut at or above the name (below the apex) means the data is elsewhere: refer.
        // At the cut itself a DS query is answered from this side (RFC 4035 section 3.1.4.1).
        if let Some(cut) = find_cut(zone, &name, qtype) {
            refer(zone, &cut, &mut r);
            if r.answers.is_empty() {
                r.aa = false;
            }
            return r;
        }
        let (node, owner) = match zone.node(&name) {
            Some(node) => (node, name.clone()),
            None if zone.has_descendants(&name) => {
                // An empty non-terminal: the name exists, it just has no data.
                negative(zone, &mut r);
                return r;
            }
            None => {
                // Find the closest encloser and its wildcard, the "source of synthesis".
                let ce = (1..=name.label_count())
                    .map(|k| name.trim(k))
                    .find(|a| zone.exists(a))
                    .unwrap_or_else(|| zone.origin.clone());
                let wild = ce.prepend(b"*").ok();
                match wild.as_ref().and_then(|w| zone.node(w)) {
                    Some(node) => (node, name.clone()),
                    None => {
                        r.rcode = rcode::NXDOMAIN;
                        negative(zone, &mut r);
                        return r;
                    }
                }
            }
        };
        match from_node(node, &owner, qtype, &mut r) {
            Step::Done => break,
            Step::NoData => {
                negative(zone, &mut r);
                return r;
            }
            Step::Follow(next) => {
                // Follow a CNAME while it stays in this zone and does not loop; otherwise the
                // answer is the chain so far and the resolver continues from there.
                if !next.is_subdomain_of(&zone.origin) || seen.contains(&next) || seen.len() > MAX_CHAIN {
                    return r;
                }
                seen.push(next.clone());
                name = next;
            }
        }
    }
    add_glue_for_answers(zone, &mut r);
    r
}

enum Step {
    Done,
    Follow(Name),
    NoData,
}

/// Copies the matching data of `node` into the answer, written with `owner` as the name (which
/// differs from the node's for a wildcard).
fn from_node(node: &Node, owner: &Name, qtype: u16, r: &mut Reply) -> Step {
    let push = |r: &mut Reply, t: u16| {
        for set in node.sets_of(t) {
            for d in &set.data {
                r.answers.push(Record::new(owner.clone(), set.ttl, d.clone()));
            }
        }
    };
    if qtype == rtype::ANY {
        for (_, set) in node.sets() {
            for d in &set.data {
                r.answers.push(Record::new(owner.clone(), set.ttl, d.clone()));
            }
        }
        return Step::Done;
    }
    if node.has(qtype) {
        push(r, qtype);
        return Step::Done;
    }
    if let Some(c) = node.get(rtype::CNAME) {
        push(r, rtype::CNAME);
        if let Some(RData::Cname(t)) = c.data.first() {
            return Step::Follow(t.clone());
        }
    }
    Step::NoData
}

fn find_cut(zone: &Zone, name: &Name, qtype: u16) -> Option<Name> {
    let apex_labels = zone.origin.label_count();
    for k in apex_labels + 1..=name.label_count() {
        let anc = name.trim(name.label_count() - k);
        if zone.get(&anc, rtype::NS).is_some() {
            if anc == *name && qtype == rtype::DS {
                return None;
            }
            return Some(anc);
        }
    }
    None
}

/// A referral: the cut's NS records, and addresses for name servers inside this zone (glue).
fn refer(zone: &Zone, cut: &Name, r: &mut Reply) {
    let ns = zone.get(cut, rtype::NS).expect("cut has NS");
    for d in &ns.data {
        r.authority.push(Record::new(cut.clone(), ns.ttl, d.clone()));
    }
    for d in &ns.data {
        if let RData::Ns(host) = d {
            addresses(zone, host, &mut r.additional);
        }
    }
}

fn addresses(zone: &Zone, host: &Name, out: &mut Vec<Record>) {
    if !host.is_subdomain_of(&zone.origin) {
        return;
    }
    for t in [rtype::A, rtype::AAAA] {
        if let Some(set) = zone.get(host, t) {
            for d in &set.data {
                let rec = Record::new(host.clone(), set.ttl, d.clone());
                if !out.contains(&rec) {
                    out.push(rec);
                }
            }
        }
    }
}

/// Additional addresses for the targets of MX, NS and SRV answers.
fn add_glue_for_answers(zone: &Zone, r: &mut Reply) {
    let targets: Vec<Name> = r
        .answers
        .iter()
        .filter(|a| matches!(a.rtype(), rtype::MX | rtype::NS | rtype::SRV))
        .filter_map(|a| a.data.target().cloned())
        .collect();
    for t in targets {
        addresses(zone, &t, &mut r.additional);
    }
}

/// The SOA for a negative answer, with the TTL a resolver may cache it for: the smaller of the
/// SOA's own TTL and its minimum field (RFC 2308 section 3).
fn negative(zone: &Zone, r: &mut Reply) {
    let (set, d) = zone.soa();
    let ttl = match d {
        RData::Soa { minimum, .. } => set.ttl.min(*minimum),
        _ => set.ttl,
    };
    r.authority.push(Record::new(zone.origin.clone(), ttl, d.clone()));
}
