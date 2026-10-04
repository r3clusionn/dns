//! Authoritative answers, starting with the examples of RFC 4592 section 2.2.1.

mod common;

use common::{n, zone};
use dnscore::auth::answer;
use dnscore::rdata::{rtype, RData};
use dnscore::wire::rcode;

/// The example zone of RFC 4592 section 2.2.1.
const RFC4592: &str = r#"
$ORIGIN example.
example.                 3600 IN  SOA   ns.example.com. hostmaster.example. 1 3600 600 86400 300
example.                 3600     NS    ns.example.com.
example.                 3600     NS    ns.example.net.
*.example.               3600     TXT   "this is a wildcard"
*.example.               3600     MX    10 host1.example.
sub.*.example.           3600     TXT   "this is not a wildcard"
host1.example.           3600     A     192.0.2.1
_ssh._tcp.host1.example. 3600     SRV   0 0 22 host1.example.
_ssh._tcp.host2.example. 3600     SRV   0 0 22 host2.example.
subdel.example.          3600     NS    ns.example.com.
subdel.example.          3600     NS    ns.example.net.
"#;

#[test]
fn rfc4592_wildcard_examples() {
    let z = zone("example", RFC4592);
    // Synthesized from *.example.
    let r = answer(&z, &n("host3.example"), rtype::MX);
    assert_eq!((r.rcode, r.answers.len()), (rcode::NOERROR, 1));
    assert_eq!(r.answers[0].name, n("host3.example"), "the owner is the query name, not the wildcard");
    assert_eq!(r.answers[0].data, RData::Mx { preference: 10, exchange: n("host1.example") });
    assert_eq!(r.additional.len(), 1, "host1's address as additional data");
    let r = answer(&z, &n("host3.example"), rtype::A);
    assert_eq!((r.rcode, r.answers.len()), (rcode::NOERROR, 0), "the wildcard has no A: NODATA");
    assert_eq!(r.authority[0].rtype(), rtype::SOA);
    let r = answer(&z, &n("foo.bar.example"), rtype::TXT);
    assert_eq!(r.answers[0].data, RData::Txt(vec![b"this is a wildcard".to_vec()]));
    // Not synthesized:
    let r = answer(&z, &n("host1.example"), rtype::MX);
    assert_eq!((r.rcode, r.answers.len()), (rcode::NOERROR, 0), "host1 exists, so no wildcard");
    let r = answer(&z, &n("sub.*.example"), rtype::MX);
    assert_eq!((r.rcode, r.answers.len()), (rcode::NOERROR, 0));
    let r = answer(&z, &n("_telnet._tcp.host1.example"), rtype::SRV);
    assert_eq!(r.rcode, rcode::NXDOMAIN, "closest encloser _tcp.host1.example has no wildcard");
    let r = answer(&z, &n("host.subdel.example"), rtype::A);
    assert!(!r.aa, "a referral is not authoritative");
    assert_eq!(r.authority.len(), 2);
    assert!(r.authority.iter().all(|a| a.rtype() == rtype::NS && a.name == n("subdel.example")));
    let r = answer(&z, &n("ghost.*.example"), rtype::MX);
    assert_eq!(r.rcode, rcode::NXDOMAIN, "a * label in the query is matched literally");
}

const ZONE: &str = r#"
$TTL 300
@       SOA ns1 admin 2026100401 3600 600 86400 60
@       NS  ns1
@       NS  ns.elsewhere.example.
@       MX  10 mail
ns1     A   192.0.2.1
mail    A   192.0.2.25
www     A   192.0.2.80
alias   CNAME www
chain1  CNAME chain2
chain2  CNAME alias
outside CNAME www.elsewhere.example.
loop1   CNAME loop2
loop2   CNAME loop1
dangling CNAME nothing
deep.ent A  192.0.2.7
kid     NS  ns.kid
kid     NS  ns.elsewhere.example.
ns.kid  A   192.0.2.53
kid     DS  12345 8 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
"#;

#[test]
fn cname_chains_inside_the_zone_are_followed() {
    let z = zone("corp.test", ZONE);
    let r = answer(&z, &n("chain1.corp.test"), rtype::A);
    let types: Vec<u16> = r.answers.iter().map(|a| a.rtype()).collect();
    assert_eq!(types, [rtype::CNAME, rtype::CNAME, rtype::CNAME, rtype::A]);
    assert!(r.aa);
    // A CNAME query returns the CNAME itself.
    let r = answer(&z, &n("alias.corp.test"), rtype::CNAME);
    assert_eq!(r.answers.len(), 1);
    // Leaving the zone: just the CNAME.
    let r = answer(&z, &n("outside.corp.test"), rtype::A);
    assert_eq!(r.answers.len(), 1);
    assert_eq!(r.rcode, rcode::NOERROR);
    // A loop stops; a dangling CNAME ends in NXDOMAIN for the target (RFC 6604).
    let r = answer(&z, &n("loop1.corp.test"), rtype::A);
    assert_eq!(r.answers.len(), 2);
    let r = answer(&z, &n("dangling.corp.test"), rtype::A);
    assert_eq!((r.rcode, r.answers.len()), (rcode::NXDOMAIN, 1));
}

#[test]
fn negative_answers_carry_the_soa_with_the_negative_ttl() {
    let z = zone("corp.test", ZONE);
    let r = answer(&z, &n("nope.corp.test"), rtype::A);
    assert_eq!(r.rcode, rcode::NXDOMAIN);
    assert_eq!(r.authority.len(), 1);
    assert_eq!(r.authority[0].ttl, 60, "min(SOA TTL 300, minimum 60)");
    // An empty non-terminal exists: NODATA, not NXDOMAIN.
    let r = answer(&z, &n("ent.corp.test"), rtype::A);
    assert_eq!((r.rcode, r.answers.len()), (rcode::NOERROR, 0));
}

#[test]
fn delegations_glue_and_ds() {
    let z = zone("corp.test", ZONE);
    let r = answer(&z, &n("www.kid.corp.test"), rtype::A);
    assert!(!r.aa);
    assert_eq!(r.authority.len(), 2);
    assert_eq!(r.additional.len(), 1, "glue for ns.kid only; ns.elsewhere is not ours");
    assert_eq!(r.additional[0].name, n("ns.kid.corp.test"));
    // DS lives on the parent side of the cut.
    let r = answer(&z, &n("kid.corp.test"), rtype::DS);
    assert!(r.aa);
    assert_eq!(r.answers.len(), 1);
    // MX answers bring the mail server's address.
    let r = answer(&z, &n("corp.test"), rtype::MX);
    assert_eq!(r.additional.len(), 1);
    // ANY returns everything at the name.
    let r = answer(&z, &n("corp.test"), rtype::ANY);
    assert_eq!(r.answers.len(), 4);
}
