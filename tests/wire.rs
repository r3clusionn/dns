//! The decoder against hostile input: random bytes and damaged real messages must never panic,
//! and whatever decodes must survive another round trip unchanged.

mod common;

use common::n;
use dnscore::rdata::{rtype, RData};
use dnscore::wire::{Edns, Message, Record};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn sample() -> Vec<Vec<u8>> {
    let mut m = Message::query(0x1234, n("www.example.com"), rtype::A, true);
    m.header.qr = true;
    m.answers.push(Record::new(n("www.example.com"), 300, RData::Cname(n("web.example.com"))));
    m.answers.push(Record::new(n("web.example.com"), 300, RData::A("192.0.2.1".parse().unwrap())));
    m.authority.push(Record::new(
        n("example.com"),
        60,
        RData::Soa {
            mname: n("ns.example.com"),
            rname: n("admin.example.com"),
            serial: 1,
            refresh: 2,
            retry: 3,
            expire: 4,
            minimum: 5,
        },
    ));
    m.additional.push(Record::new(n("example.com"), 60, RData::Txt(vec![b"hello".to_vec(), vec![]])));
    m.additional.push(Record::new(
        n("_sip._tcp.example.com"),
        60,
        RData::Srv { priority: 1, weight: 2, port: 5060, target: n("sip.example.com") },
    ));
    m.additional.push(Record::new(
        n("example.com"),
        60,
        RData::Nsec { next: n("a.example.com"), types: vec![1, 2, 6, 46, 47, 1234] },
    ));
    m.edns = Some(Edns { options: vec![(10, vec![1, 2, 3, 4, 5, 6, 7, 8])], ..Edns::default() });
    let mut q = Message::query(7, n("example.org"), rtype::MX, false);
    q.edns = None;
    vec![m.encode(), q.encode()]
}

fn check(bytes: &[u8]) -> bool {
    match Message::decode(bytes) {
        Ok(m) => {
            let again = Message::decode(&m.encode()).expect("our own encoding decodes");
            assert_eq!(again, m, "round trip changed the message: {bytes:02x?}");
            true
        }
        Err(_) => false,
    }
}

#[test]
fn random_bytes_never_panic() {
    let mut r = Rng(0x9e3779b97f4a7c15);
    let mut ok = 0;
    for _ in 0..200_000 {
        let len = r.below(80);
        let mut b: Vec<u8> = (0..len).map(|_| r.next() as u8).collect();
        // Small counts make it more likely that something parses.
        if b.len() >= 12 {
            for i in [4, 6, 8, 10] {
                b[i] = 0;
                b[i + 1] = (r.below(3)) as u8;
            }
        }
        ok += check(&b) as usize;
    }
    assert!(ok > 10, "some random messages should decode ({ok})");
}

#[test]
fn damaged_messages_never_panic() {
    let mut r = Rng(42);
    let mut decoded = 0;
    let mut total = 0;
    for base in sample() {
        for _ in 0..100_000 {
            let mut b = base.clone();
            match r.below(4) {
                0 => {
                    let i = r.below(b.len());
                    b[i] ^= 1 << r.below(8);
                }
                1 => b.truncate(r.below(b.len())),
                2 => {
                    let i = r.below(b.len());
                    b[i] = r.next() as u8;
                }
                _ => {
                    let i = r.below(b.len());
                    b.insert(i, r.next() as u8);
                }
            }
            total += 1;
            decoded += check(&b) as usize;
        }
    }
    assert!(decoded > 1000 && decoded < total, "{decoded} of {total}");
}

#[test]
fn every_truncation_of_a_valid_message_is_rejected() {
    for base in sample() {
        assert!(check(&base));
        for len in 0..base.len() {
            assert!(Message::decode(&base[..len]).is_err(), "a message cut at {len} bytes was accepted");
        }
    }
}

#[test]
fn bytes_after_the_last_record_are_rejected() {
    for base in sample() {
        let mut b = base.clone();
        b.push(0);
        assert!(Message::decode(&b).is_err());
    }
}
