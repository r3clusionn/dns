//! The caching resolver. It either resolves iteratively from the root servers, following
//! referrals the way RFC 1034 section 5.3.3 describes, or forwards every query to upstream
//! servers (plain, TLS or HTTPS). Either way answers are cached and CNAME chains are followed.

use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

use crate::cache::{Cache, Cached, Limits, Rank};
use crate::name::Name;
use crate::rdata::{rtype, type_name, RData};
use crate::transport::{random_u16, Client, Upstream};
use crate::wire::{rcode, Message, Record};

/// The IPv4 addresses of the 13 root servers (a.root-servers.net to m), from IANA's root hints.
pub const ROOT_HINTS: [&str; 13] = [
    "198.41.0.4",
    "170.247.170.2",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33",
];

#[derive(Clone, Debug)]
pub enum Mode {
    /// Iterate from these root server addresses.
    Recursive { roots: Vec<IpAddr> },
    /// Send every query to the first of these that answers.
    Forward { upstreams: Vec<Upstream> },
}

impl Mode {
    pub fn recursive() -> Mode {
        Mode::Recursive { roots: ROOT_HINTS.iter().map(|s| s.parse().unwrap()).collect() }
    }
}

#[derive(Clone, Debug)]
pub struct Options {
    /// The port name servers are asked on (53; tests use another).
    pub port: u16,
    /// How long to wait for one server.
    pub timeout: Duration,
    /// Use IPv6 addresses of name servers too.
    pub ipv6: bool,
    pub limits: Limits,
}

impl Default for Options {
    fn default() -> Options {
        Options { port: 53, timeout: Duration::from_millis(1500), ipv6: false, limits: Limits::default() }
    }
}

/// What a resolution produced, ready to go into a response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolution {
    pub rcode: u16,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
}

/// Name servers to try: the server's name (unknown for root hints) and an address.
type Servers = Vec<(Option<Name>, IpAddr)>;

const MAX_CHAIN: usize = 12;
const MAX_REFERRALS: usize = 20;
const MAX_DEPTH: usize = 5;

pub struct Resolver {
    mode: Mode,
    opts: Options,
    pub cache: Cache,
    client: Client,
    trace: Mutex<Option<Vec<String>>>,
}

impl Resolver {
    pub fn new(mode: Mode, opts: Options) -> Resolver {
        Resolver { cache: Cache::new(opts.limits), mode, opts, client: Client::new(), trace: Mutex::new(None) }
    }

    /// Starts recording each query sent (for `dnsr resolve --trace`).
    pub fn start_trace(&self) {
        *self.trace.lock().unwrap() = Some(Vec::new());
    }

    pub fn take_trace(&self) -> Vec<String> {
        self.trace.lock().unwrap().take().unwrap_or_default()
    }

    fn note(&self, depth: usize, s: String) {
        if let Some(t) = self.trace.lock().unwrap().as_mut() {
            t.push(format!("{}{s}", "  ".repeat(depth)));
        }
    }

    pub fn resolve(&self, name: &Name, qtype: u16) -> Resolution {
        self.resolve_depth(name, qtype, 0)
    }

    fn resolve_depth(&self, qname: &Name, qtype: u16, depth: usize) -> Resolution {
        let mut answers: Vec<Record> = Vec::new();
        let mut name = qname.clone();
        let mut seen = vec![name.clone()];
        let fail = |answers: Vec<Record>| Resolution { rcode: rcode::SERVFAIL, answers, authority: Vec::new() };
        for _ in 0..MAX_CHAIN {
            // From the cache: the data itself, a negative answer, or a CNAME to follow.
            match self.cache.get(&name, qtype, Rank::Answer) {
                Some(Cached::Records(v)) => {
                    answers.extend(v);
                    return Resolution { rcode: rcode::NOERROR, answers, authority: Vec::new() };
                }
                Some(Cached::NoData(soa)) => {
                    return Resolution { rcode: rcode::NOERROR, answers, authority: soa.into_iter().collect() }
                }
                Some(Cached::NxDomain(soa)) => {
                    return Resolution { rcode: rcode::NXDOMAIN, answers, authority: soa.into_iter().collect() }
                }
                None => {}
            }
            if qtype != rtype::CNAME {
                if let Some(Cached::Records(v)) = self.cache.get(&name, rtype::CNAME, Rank::Answer) {
                    let next = v[0].data.target().cloned().expect("CNAME has a target");
                    answers.extend(v);
                    if seen.contains(&next) {
                        return fail(answers);
                    }
                    seen.push(next.clone());
                    name = next;
                    continue;
                }
            }
            // Not cached: ask, keep what is trustworthy, and walk the answer.
            let (resp, zone) = match &self.mode {
                Mode::Forward { upstreams } => match self.forward(upstreams, &name, qtype, depth) {
                    Ok(r) => (r, Name::root()),
                    Err(_) => return fail(answers),
                },
                Mode::Recursive { roots } => match self.iterate(roots, &name, qtype, depth) {
                    Ok(x) => x,
                    Err(e) => {
                        self.note(depth, format!("failed: {e}"));
                        return fail(answers);
                    }
                },
            };
            let usable: Vec<Record> = resp.answers.iter().filter(|r| r.name.is_subdomain_of(&zone)).cloned().collect();
            self.cache_answers(&usable);
            let mut cur = name.clone();
            let mut found = false;
            loop {
                let finals: Vec<Record> =
                    usable.iter().filter(|r| r.name == cur && (r.rtype() == qtype || qtype == rtype::ANY)).cloned().collect();
                if !finals.is_empty() {
                    answers.extend(finals);
                    found = true;
                    break;
                }
                let cname = usable.iter().find(|r| r.name == cur && r.rtype() == rtype::CNAME).cloned();
                match cname {
                    Some(c) if qtype != rtype::CNAME => {
                        let next = c.data.target().cloned().unwrap();
                        answers.push(c);
                        if seen.contains(&next) || seen.len() > MAX_CHAIN {
                            return fail(answers);
                        }
                        seen.push(next.clone());
                        cur = next;
                    }
                    _ => break,
                }
            }
            if found {
                return Resolution { rcode: rcode::NOERROR, answers, authority: Vec::new() };
            }
            // The SOA of a negative answer goes out (and into the cache) with the negative TTL.
            let soa = resp
                .authority
                .iter()
                .find(|r| r.rtype() == rtype::SOA && cur.is_subdomain_of(&r.name) && r.name.is_subdomain_of(&zone))
                .map(negative_ttl);
            if resp.header.rcode == rcode::NXDOMAIN {
                self.cache.put_negative(&cur, qtype, true, soa.clone());
                return Resolution { rcode: rcode::NXDOMAIN, answers, authority: soa.into_iter().collect() };
            }
            if cur != name {
                // The chain left the server's zone: carry on from where it stopped.
                name = cur;
                continue;
            }
            self.cache.put_negative(&cur, qtype, false, soa.clone());
            return Resolution { rcode: rcode::NOERROR, answers, authority: soa.into_iter().collect() };
        }
        fail(answers)
    }

    /// Caches every RRset in a list of answer records.
    fn cache_answers(&self, recs: &[Record]) {
        let mut groups: Vec<Vec<Record>> = Vec::new();
        for r in recs {
            match groups.iter_mut().find(|g| g[0].name == r.name && g[0].rtype() == r.rtype() && !is_rrsig(r)) {
                Some(g) => g.push(r.clone()),
                None if !is_rrsig(r) => groups.push(vec![r.clone()]),
                None => {}
            }
        }
        for g in groups {
            self.cache.put_rrset(g, Rank::Answer);
        }
    }

    fn forward(&self, upstreams: &[Upstream], name: &Name, qtype: u16, depth: usize) -> Result<Message, String> {
        let mut last = String::from("no upstream configured");
        for up in upstreams {
            let q = Message::query(random_u16(), name.clone(), qtype, true);
            match self.client.exchange(up, &q, self.opts.timeout) {
                Ok(r) if matches!(r.header.rcode, rcode::NOERROR | rcode::NXDOMAIN) => {
                    self.note(
                        depth,
                        format!(
                            "{up}: {} {} -> {}, {} answers",
                            name,
                            type_name(qtype),
                            rcode::name(r.header.rcode),
                            r.answers.len()
                        ),
                    );
                    return Ok(r);
                }
                Ok(r) => last = format!("{up}: {}", rcode::name(r.header.rcode)),
                Err(e) => last = format!("{up}: {e}"),
            }
            self.note(depth, last.clone());
        }
        Err(last)
    }

    /// Iterative resolution: start at the closest zone whose servers are known and follow
    /// referrals down to a server that answers for `name`. Returns that server's response and
    /// the zone it was asked as (answers from it are only trusted inside that zone).
    fn iterate(&self, roots: &[IpAddr], name: &Name, qtype: u16, depth: usize) -> Result<(Message, Name), String> {
        if depth > MAX_DEPTH {
            return Err("name server names nested too deep".into());
        }
        let (mut zone, mut servers) = self.closest(roots, name, depth);
        for _ in 0..MAX_REFERRALS {
            let mut last = format!("no address for any name server of {zone}");
            let mut next: Option<(Name, Servers)> = None;
            for (host, ip) in servers.iter().take(6) {
                let label = host.as_ref().map_or_else(|| ip.to_string(), |h| format!("{h} ({ip})"));
                let q = Message::query(random_u16(), name.clone(), qtype, false);
                let up = Upstream::Udp(SocketAddr::new(*ip, self.opts.port));
                let r = match self.client.exchange(&up, &q, self.opts.timeout) {
                    Ok(r) => r,
                    Err(e) => {
                        self.note(depth, format!("{label}: {e}"));
                        last = e.to_string();
                        continue;
                    }
                };
                if r.header.rcode == rcode::NXDOMAIN {
                    self.note(depth, format!("{label}: {name} {} -> NXDOMAIN", type_name(qtype)));
                    return Ok((r, zone));
                }
                if r.header.rcode != rcode::NOERROR {
                    self.note(depth, format!("{label}: {}", rcode::name(r.header.rcode)));
                    last = format!("{label} said {}", rcode::name(r.header.rcode));
                    continue;
                }
                if r.answers
                    .iter()
                    .any(|a| a.name == *name && (a.rtype() == qtype || a.rtype() == rtype::CNAME || qtype == rtype::ANY))
                {
                    self.note(depth, format!("{label}: {name} {} -> {} answers", type_name(qtype), r.answers.len()));
                    return Ok((r, zone));
                }
                // A referral: NS records for a zone below the current one that contains the name.
                let ns: Vec<&Record> = r.authority.iter().filter(|a| a.rtype() == rtype::NS).collect();
                if let Some(cut) = ns.first().map(|a| a.name.clone()) {
                    if cut != zone && cut.is_subdomain_of(&zone) && name.is_subdomain_of(&cut) && !r.header.aa {
                        let hosts: Vec<Name> =
                            ns.iter().filter(|a| a.name == cut).filter_map(|a| a.data.target().cloned()).collect();
                        self.cache.put_rrset(ns.iter().filter(|a| a.name == cut).map(|a| (*a).clone()).collect(), Rank::Referral);
                        // Glue is only believed for names inside the zone of the server that sent it.
                        for t in [rtype::A, rtype::AAAA] {
                            for h in &hosts {
                                let g: Vec<Record> = r
                                    .additional
                                    .iter()
                                    .filter(|a| a.name == *h && a.rtype() == t && a.name.is_subdomain_of(&zone))
                                    .cloned()
                                    .collect();
                                self.cache.put_rrset(g, Rank::Glue);
                            }
                        }
                        self.note(depth, format!("{label}: referral to {cut} ({} name servers)", hosts.len()));
                        let s = self.servers_for(&cut, &hosts, depth);
                        next = Some((cut, s));
                        break;
                    }
                }
                if r.header.aa || r.authority.iter().any(|a| a.rtype() == rtype::SOA) {
                    self.note(depth, format!("{label}: {name} {} -> no data", type_name(qtype)));
                    return Ok((r, zone));
                }
                self.note(depth, format!("{label}: not an answer or a referral (lame)"));
                last = format!("{label} is lame for {zone}");
            }
            match next {
                Some((z, s)) => {
                    zone = z;
                    servers = s;
                }
                None => return Err(last),
            }
        }
        Err("too many referrals".into())
    }

    /// The deepest enclosing zone whose name servers are cached, else the root servers.
    fn closest(&self, roots: &[IpAddr], name: &Name, depth: usize) -> (Name, Servers) {
        for k in 0..name.label_count() {
            let anc = name.trim(k);
            if let Some(Cached::Records(ns)) = self.cache.get(&anc, rtype::NS, Rank::Referral) {
                let hosts: Vec<Name> = ns.iter().filter_map(|r| r.data.target().cloned()).collect();
                let s = self.servers_for(&anc, &hosts, depth);
                if !s.is_empty() {
                    return (anc, s);
                }
            }
        }
        let mut s: Servers = roots.iter().map(|ip| (None, *ip)).collect();
        shuffle(&mut s);
        (Name::root(), s)
    }

    /// Addresses for a zone's name servers: from the cache (glue or answers), otherwise by
    /// resolving the names, skipping names inside the zone itself (those need glue).
    fn servers_for(&self, zone: &Name, hosts: &[Name], depth: usize) -> Servers {
        let types: &[u16] = if self.opts.ipv6 { &[rtype::A, rtype::AAAA] } else { &[rtype::A] };
        let mut out = Vec::new();
        for h in hosts {
            for &t in types {
                if let Some(Cached::Records(v)) = self.cache.get(h, t, Rank::Glue) {
                    out.extend(v.iter().filter_map(|r| address(&r.data)).map(|ip| (Some(h.clone()), ip)));
                }
            }
        }
        if out.is_empty() {
            let mut outside: Vec<&Name> = hosts.iter().filter(|h| !h.is_subdomain_of(zone)).collect();
            shuffle(&mut outside);
            for h in outside.into_iter().take(3) {
                self.note(depth, format!("finding the address of {h}"));
                let r = self.resolve_depth(h, rtype::A, depth + 1);
                out.extend(
                    r.answers.iter().filter(|a| a.name == *h).filter_map(|a| address(&a.data)).map(|ip| (Some(h.clone()), ip)),
                );
                if !out.is_empty() {
                    break;
                }
            }
        }
        shuffle(&mut out);
        out
    }
}

fn is_rrsig(r: &Record) -> bool {
    r.rtype() == rtype::RRSIG
}

fn address(d: &RData) -> Option<IpAddr> {
    match d {
        RData::A(a) => Some(IpAddr::V4(*a)),
        RData::Aaaa(a) => Some(IpAddr::V6(*a)),
        _ => None,
    }
}

/// The SOA with its TTL lowered to the negative-caching TTL: min(TTL, minimum).
fn negative_ttl(soa: &Record) -> Record {
    let mut s = soa.clone();
    if let RData::Soa { minimum, .. } = s.data {
        s.ttl = s.ttl.min(minimum);
    }
    s
}

fn shuffle<T>(v: &mut [T]) {
    for i in (1..v.len()).rev() {
        let j = random_u16() as usize % (i + 1);
        v.swap(i, j);
    }
}
