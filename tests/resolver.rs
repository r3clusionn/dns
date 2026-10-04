//! The recursive resolver against a small DNS tree on loopback addresses: a root server, a
//! server for `test.`, servers below it, a lame one and a hostile one, all on one port.

mod common;

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use common::{free_port, n, start, zone, zones};
use dnscore::rdata::{rtype, RData};
use dnscore::resolver::{Mode, Options, Resolver};
use dnscore::server::Server;
use dnscore::wire::{rcode, Message, Record};

struct Tree {
    port: u16,
    root: Arc<Server>,
    tld: Arc<Server>,
    leaf: Arc<Server>,
}

const ROOT: &str = "$TTL 3600\n@ SOA a.root. admin.root. 1 1800 900 604800 86400\n@ NS a.root.\na.root. A 127.0.0.1\ntest. NS ns1.test.\nns1.test. A 127.0.0.2\n";

const TLD: &str = r#"$TTL 3600
@ SOA ns1 admin 1 1800 900 604800 600
@ NS ns1
ns1 A 127.0.0.2
example NS ns.example
ns.example A 127.0.0.3
; No glue: ns.example.test is in another zone, so the resolver must look it up first.
glueless NS ns.example.test.
; One server that does not answer and one that does.
lame NS ns1.lame
lame NS ns2.lame
ns1.lame A 127.0.0.9
ns2.lame A 127.0.0.3
evil NS ns.evil
ns.evil A 127.0.0.4
"#;

const EXAMPLE: &str = r#"$TTL 300
@ SOA ns admin 1 1800 900 604800 30
@ NS ns
ns A 127.0.0.3
www A 192.0.2.80
alias CNAME www
ext CNAME host.glueless.test.
short 2 A 192.0.2.2
loop1 CNAME loop2
loop2 CNAME loop1
"#;

const GLUELESS: &str = "$TTL 300\n@ SOA ns.example.test. admin 1 1800 900 604800 30\n@ NS ns.example.test.\nhost A 192.0.2.44\n";
const LAME: &str =
    "$TTL 300\n@ SOA ns2 admin 1 1800 900 604800 30\n@ NS ns1\n@ NS ns2\nns1 A 127.0.0.9\nns2 A 127.0.0.3\nwww A 192.0.2.99\n";

/// The tree is shared by all tests (servers run until the test process ends). Tests count the
/// queries the servers receive, so they take turns.
fn tree() -> (&'static Tree, std::sync::MutexGuard<'static, ()>) {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    (shared(), guard)
}

fn shared() -> &'static Tree {
    static T: OnceLock<Tree> = OnceLock::new();
    T.get_or_init(|| {
        let port = free_port();
        let (_, root) = start("127.0.0.1", port, zones(vec![zone(".", ROOT)]), None);
        let (_, tld) = start("127.0.0.2", port, zones(vec![zone("test", TLD)]), None);
        let (_, leaf) = start(
            "127.0.0.3",
            port,
            zones(vec![zone("example.test", EXAMPLE), zone("glueless.test", GLUELESS), zone("lame.test", LAME)]),
            None,
        );
        evil_server(port);
        Tree { port, root, tld, leaf }
    })
}

/// A server for evil.test that answers every query and adds records it has no authority for:
/// an A record for www.example.test in the answer section and in the additional section.
fn evil_server(port: u16) {
    let sock = UdpSocket::bind(("127.0.0.4", port)).unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((len, from)) = sock.recv_from(&mut buf) else { continue };
            let Ok(q) = Message::decode(&buf[..len]) else { continue };
            let mut r = Message::response_to(&q);
            // Names under ref.evil.test get a referral whose glue is for a name in another zone.
            if q.questions[0].name.is_subdomain_of(&n("ref.evil.test")) {
                r.authority.push(Record::new(n("sub.ref.evil.test"), 300, RData::Ns(n("ns.example.test"))));
                r.additional.push(Record::new(n("ns.example.test"), 86_400, RData::A("6.6.6.6".parse().unwrap())));
                let _ = sock.send_to(&r.encode(), from);
                continue;
            }
            // Names under nx.evil.test do not exist, and the SOA's TTL is far above its minimum.
            if q.questions[0].name.is_subdomain_of(&n("nx.evil.test")) {
                r.header.aa = true;
                r.header.rcode = dnscore::wire::rcode::NXDOMAIN;
                let soa = RData::Soa {
                    mname: n("ns.evil.test"),
                    rname: n("admin.evil.test"),
                    serial: 1,
                    refresh: 3600,
                    retry: 600,
                    expire: 86_400,
                    minimum: 5,
                };
                r.authority.push(Record::new(n("evil.test"), 3600, soa));
                let _ = sock.send_to(&r.encode(), from);
                continue;
            }
            r.header.aa = true;
            let poison = Record::new(n("www.example.test"), 86_400, RData::A("6.6.6.6".parse().unwrap()));
            r.answers.push(Record::new(q.questions[0].name.clone(), 300, RData::A("192.0.2.66".parse().unwrap())));
            r.answers.push(poison.clone());
            r.additional.push(poison);
            let _ = sock.send_to(&r.encode(), from);
        }
    });
}

fn resolver(t: &Tree) -> Resolver {
    let opts = Options { port: t.port, timeout: Duration::from_millis(400), ..Options::default() };
    Resolver::new(Mode::Recursive { roots: vec!["127.0.0.1".parse::<IpAddr>().unwrap()] }, opts)
}

fn queries(t: &Tree) -> u64 {
    [&t.root, &t.tld, &t.leaf].iter().map(|s| s.stats.queries.load(Ordering::SeqCst)).sum()
}

fn addrs(r: &dnscore::resolver::Resolution) -> Vec<String> {
    r.answers.iter().filter(|a| a.rtype() == rtype::A).map(|a| a.data.to_text()).collect()
}

#[test]
fn follows_referrals_from_the_root() {
    let (t, _turn) = tree();
    let r = resolver(t);
    r.start_trace();
    let a = r.resolve(&n("www.example.test"), rtype::A);
    assert_eq!(a.rcode, rcode::NOERROR);
    assert_eq!(addrs(&a), ["192.0.2.80"]);
    let trace = r.take_trace().join("\n");
    assert!(trace.contains("referral to test."), "{trace}");
    assert!(trace.contains("referral to example.test."), "{trace}");
    // Everything needed is cached now: no server is asked again.
    let before = queries(t);
    let again = r.resolve(&n("www.example.test"), rtype::A);
    assert_eq!(addrs(&again), ["192.0.2.80"]);
    assert_eq!(queries(t), before);
    // A sibling name only needs the example.test server.
    let before = queries(t);
    r.resolve(&n("alias.example.test"), rtype::A);
    assert_eq!(queries(t), before + 1);
}

#[test]
fn ttls_count_down_in_the_cache() {
    let (t, _turn) = tree();
    let r = resolver(t);
    let a = r.resolve(&n("short.example.test"), rtype::A);
    assert_eq!(a.answers[0].ttl, 2);
    std::thread::sleep(Duration::from_millis(1100));
    assert!(r.resolve(&n("short.example.test"), rtype::A).answers[0].ttl <= 1);
    std::thread::sleep(Duration::from_millis(1100));
    let before = queries(t);
    r.resolve(&n("short.example.test"), rtype::A);
    assert_eq!(queries(t), before + 1, "expired, so asked again");
}

#[test]
fn negative_answers_are_cached() {
    let (t, _turn) = tree();
    let r = resolver(t);
    let a = r.resolve(&n("nope.example.test"), rtype::A);
    assert_eq!(a.rcode, rcode::NXDOMAIN);
    assert_eq!(a.authority[0].rtype(), rtype::SOA);
    assert_eq!(a.authority[0].ttl, 30, "min(SOA TTL, minimum)");
    let before = queries(t);
    // NXDOMAIN covers every type of the name.
    assert_eq!(r.resolve(&n("nope.example.test"), rtype::MX).rcode, rcode::NXDOMAIN);
    assert_eq!(queries(t), before);
    let a = r.resolve(&n("www.example.test"), rtype::MX);
    assert_eq!((a.rcode, a.answers.len()), (rcode::NOERROR, 0));
    let before = queries(t);
    r.resolve(&n("www.example.test"), rtype::MX);
    assert_eq!(queries(t), before, "NODATA is cached too");
}

#[test]
fn cname_into_a_zone_without_glue() {
    let (t, _turn) = tree();
    let r = resolver(t);
    let a = r.resolve(&n("ext.example.test"), rtype::A);
    assert_eq!(a.rcode, rcode::NOERROR);
    assert_eq!(a.answers[0].rtype(), rtype::CNAME);
    assert_eq!(addrs(&a), ["192.0.2.44"]);
}

#[test]
fn a_dead_name_server_is_skipped() {
    let (t, _turn) = tree();
    let r = resolver(t);
    for _ in 0..3 {
        r.cache.clear();
        let a = r.resolve(&n("www.lame.test"), rtype::A);
        assert_eq!(addrs(&a), ["192.0.2.99"]);
    }
}

#[test]
fn records_outside_a_servers_zone_are_not_believed() {
    let (t, _turn) = tree();
    let r = resolver(t);
    let a = r.resolve(&n("host.evil.test"), rtype::A);
    assert_eq!(addrs(&a), ["192.0.2.66"], "the in-zone part of the answer is used");
    let www = r.resolve(&n("www.example.test"), rtype::A);
    assert_eq!(addrs(&www), ["192.0.2.80"], "the planted record for www.example.test was not cached");
}

#[test]
fn unreachable_roots_give_servfail() {
    let (t, _turn) = tree();
    let opts = Options { port: t.port, timeout: Duration::from_millis(200), ..Options::default() };
    let r = Resolver::new(Mode::Recursive { roots: vec!["127.0.0.8".parse().unwrap()] }, opts);
    assert_eq!(r.resolve(&n("www.example.test"), rtype::A).rcode, rcode::SERVFAIL);
}

#[test]
fn a_server_that_forwards() {
    // A forwarding server in front of the tree's example.test server.
    let (t, _turn) = tree();
    let up = format!("udp://127.0.0.3:{}", t.port);
    let fwd =
        Resolver::new(Mode::Forward { upstreams: vec![dnscore::transport::Upstream::parse(&up).unwrap()] }, Options::default());
    let (addr, _) = start("127.0.0.1", 0, zones(vec![]), Some(fwd));
    let q = Message::query(99, n("alias.example.test"), rtype::A, true);
    let r = dnscore::transport::udp_exchange(addr, &q, Duration::from_secs(2)).unwrap();
    assert!(r.header.ra);
    assert_eq!(r.answers.len(), 2);
    // Without RD, a resolver-only server refuses.
    let q = Message::query(100, n("alias.example.test"), rtype::A, false);
    let r = dnscore::transport::udp_exchange(addr, &q, Duration::from_secs(2)).unwrap();
    assert_eq!(r.header.rcode, rcode::REFUSED);
    let _: SocketAddr = addr;
}

#[test]
fn glue_for_names_outside_the_referring_zone_is_ignored() {
    let (t, _turn) = tree();
    let r = resolver(t);
    // evil.test refers x.sub.ref.evil.test to ns.example.test and supplies an address for it.
    r.resolve(&n("x.sub.ref.evil.test"), rtype::A);
    let cached = r.cache.get(&n("ns.example.test"), rtype::A, dnscore::cache::Rank::Glue);
    assert!(
        !matches!(&cached, Some(dnscore::cache::Cached::Records(v)) if v.iter().any(|a| a.data == RData::A("6.6.6.6".parse().unwrap()))),
        "out-of-bailiwick glue was cached: {cached:?}"
    );
}

#[test]
fn a_cname_loop_fails_quickly() {
    let (t, _turn) = tree();
    let r = resolver(t);
    let a = r.resolve(&n("loop1.example.test"), rtype::A);
    assert_eq!(a.rcode, rcode::SERVFAIL);
    assert!(a.answers.len() <= 3, "the loop was followed {} times", a.answers.len());
}

#[test]
fn negative_ttl_is_capped_by_the_soa_minimum() {
    // RFC 2308: a negative answer may be cached for min(SOA TTL, SOA minimum), even when the
    // server sends the SOA with its full TTL.
    let (t, _turn) = tree();
    let r = resolver(t);
    let a = r.resolve(&n("a.nx.evil.test"), rtype::A);
    assert_eq!(a.rcode, rcode::NXDOMAIN);
    assert_eq!(a.authority[0].ttl, 5);
}
