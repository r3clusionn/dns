//! The server over real sockets, and its handling of bad input.

mod common;

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

use common::{n, start, zone, zones};
use dnscore::rdata::{rtype, RData};
use dnscore::transport::{tcp_exchange, udp_exchange, Client, Upstream};
use dnscore::wire::{rcode, Edns, Message};

fn big_zone() -> String {
    let mut z = String::from("$TTL 300\n@ SOA ns admin 7 3600 600 86400 60\n@ NS ns\nns A 192.0.2.1\nwww A 192.0.2.80\n");
    // Twenty 200-byte TXT records: about 4.5 KB, more than any UDP answer we send.
    for i in 0..20 {
        z.push_str(&format!("big TXT \"{i:02}{}\"\n", "x".repeat(198)));
    }
    for i in 0..3000 {
        z.push_str(&format!("h{i} A 10.0.{}.{}\n", i / 250, i % 250 + 1));
    }
    z
}

const T: Duration = Duration::from_secs(3);

#[test]
fn udp_answers_are_truncated_and_tcp_gets_everything() {
    let (addr, _) = start("127.0.0.1", 0, zones(vec![zone("big.test", &big_zone())]), None);
    let mut q = Message::query(1, n("big.big.test"), rtype::TXT, false);
    q.edns = None;
    let r = udp_exchange(addr, &q, T).unwrap();
    assert!(r.header.tc, "without EDNS the limit is 512 bytes");
    assert!(r.encode().len() <= 512);
    let mut q2 = q.clone();
    q2.edns = Some(Edns { udp_size: 4096, ..Edns::default() });
    let r = udp_exchange(addr, &q2, T).unwrap();
    assert!(r.header.tc && r.encode().len() <= 1232, "EDNS sizes are capped at 1232");
    let r = tcp_exchange(addr, &q, T).unwrap();
    assert!(!r.header.tc);
    assert_eq!(r.answers.len(), 20);
    // The client falls back to TCP by itself.
    let r = Client::new().exchange(&Upstream::Udp(addr), &q, T).unwrap();
    assert_eq!(r.answers.len(), 20);
}

#[test]
fn zone_transfer_over_tcp() {
    let text = big_zone();
    let z = zone("big.test", &text);
    let total = z.len();
    let (addr, _) = start("127.0.0.1", 0, zones(vec![z]), None);
    let q = Message::query(5, n("big.test"), rtype::AXFR, false);
    let mut s = TcpStream::connect(addr).unwrap();
    let body = q.encode();
    s.write_all(&(body.len() as u16).to_be_bytes()).unwrap();
    s.write_all(&body).unwrap();
    let mut recs = Vec::new();
    let mut messages = 0;
    while recs.iter().filter(|r: &&dnscore::wire::Record| r.rtype() == rtype::SOA).count() < 2 {
        let buf = dnscore::transport::read_framed(&mut s).unwrap();
        let m = Message::decode(&buf).unwrap();
        assert_eq!(m.header.rcode, rcode::NOERROR);
        recs.extend(m.answers);
        messages += 1;
    }
    assert_eq!(recs.len(), total + 1, "every record, plus the SOA again at the end");
    assert!(messages > 1, "a large zone takes several messages");
    // Over UDP a transfer is refused.
    let r = udp_exchange(addr, &q, T).unwrap();
    assert_eq!(r.header.rcode, rcode::REFUSED);
}

#[test]
fn transfers_and_recursion_are_refused_to_strangers() {
    let (_, server) = start("127.0.0.1", 0, zones(vec![zone("big.test", &big_zone())]), None);
    let q = Message::query(5, n("big.test"), rtype::AXFR, false).encode();
    let r = Message::decode(&server.handle(&q, "203.0.113.9".parse().unwrap(), true)[0]).unwrap();
    assert_eq!(r.header.rcode, rcode::REFUSED);
    let q = Message::query(6, n("example.com"), rtype::A, true).encode();
    let r = Message::decode(&server.handle(&q, "127.0.0.1".parse().unwrap(), false)[0]).unwrap();
    assert_eq!(r.header.rcode, rcode::REFUSED, "not our zone and no resolver");
    assert!(!r.header.ra);
}

#[test]
fn bad_input() {
    let (addr, server) = start("127.0.0.1", 0, zones(vec![zone("big.test", &big_zone())]), None);
    let ip = "127.0.0.1".parse().unwrap();
    // Too short for a header: no answer at all.
    assert!(server.handle(&[1, 2, 3], ip, false).is_empty());
    // A header and garbage: FORMERR with the same ID.
    let r = Message::decode(&server.handle(&[0xab, 0xcd, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xff], ip, false)[0]).unwrap();
    assert_eq!((r.header.id, r.header.rcode), (0xabcd, rcode::FORMERR));
    // A response is never answered.
    let mut m = Message::query(1, n("www.big.test"), rtype::A, false);
    m.header.qr = true;
    assert!(server.handle(&m.encode(), ip, false).is_empty());
    // An unknown opcode, an EDNS version we do not speak, two questions.
    let mut m = Message::query(2, n("www.big.test"), rtype::A, false);
    m.header.opcode = 2;
    assert_eq!(Message::decode(&server.handle(&m.encode(), ip, false)[0]).unwrap().header.rcode, rcode::NOTIMP);
    let mut m = Message::query(3, n("www.big.test"), rtype::A, false);
    m.edns = Some(Edns { version: 1, ..Edns::default() });
    assert_eq!(Message::decode(&server.handle(&m.encode(), ip, false)[0]).unwrap().header.rcode, rcode::BADVERS);
    let mut m = Message::query(4, n("www.big.test"), rtype::A, false);
    m.questions.push(m.questions[0].clone());
    assert_eq!(Message::decode(&server.handle(&m.encode(), ip, false)[0]).unwrap().header.rcode, rcode::FORMERR);
    // Over a real socket the server keeps working after all that.
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.send_to(&[0u8; 3], addr).unwrap();
    let r = udp_exchange(addr, &Message::query(9, n("www.big.test"), rtype::A, false), T).unwrap();
    assert_eq!(r.answers[0].data, RData::A("192.0.2.80".parse().unwrap()));
    assert!(r.header.aa);
}

#[test]
fn tcp_connections_carry_several_queries_and_idle_ones_are_closed() {
    let (addr, _) = start("127.0.0.1", 0, zones(vec![zone("big.test", &big_zone())]), None);
    let mut s = TcpStream::connect(addr).unwrap();
    for i in 0..5u16 {
        let q = Message::query(i, n(&format!("h{i}.big.test")), rtype::A, false).encode();
        s.write_all(&(q.len() as u16).to_be_bytes()).unwrap();
        s.write_all(&q).unwrap();
        let m = Message::decode(&dnscore::transport::read_framed(&mut s).unwrap()).unwrap();
        assert_eq!(m.header.id, i);
        assert_eq!(m.answers.len(), 1);
    }
    // A client that sends half a length prefix and stops is disconnected after the idle timeout.
    let mut slow = TcpStream::connect(addr).unwrap();
    slow.write_all(&[0]).unwrap();
    slow.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    let mut b = [0u8; 1];
    let start = std::time::Instant::now();
    let n = slow.read(&mut b).unwrap_or(0);
    assert_eq!(n, 0);
    assert!(start.elapsed() < Duration::from_secs(13));
}

#[test]
fn forged_udp_answers_are_ignored() {
    // A fake server that first sends an answer with the wrong ID, then one for another question,
    // then the real one. The client must wait for the real one.
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        let (len, from) = sock.recv_from(&mut buf).unwrap();
        let q = Message::decode(&buf[..len]).unwrap();
        let answer = |m: &mut Message, ip: &str| {
            m.answers.push(dnscore::wire::Record::new(m.questions[0].name.clone(), 60, RData::A(ip.parse().unwrap())))
        };
        let mut wrong_id = Message::response_to(&q);
        wrong_id.header.id ^= 1;
        answer(&mut wrong_id, "6.6.6.1");
        sock.send_to(&wrong_id.encode(), from).unwrap();
        let mut wrong_q = Message::response_to(&q);
        wrong_q.questions[0].name = n("other.test");
        answer(&mut wrong_q, "6.6.6.2");
        sock.send_to(&wrong_q.encode(), from).unwrap();
        let mut real = Message::response_to(&q);
        answer(&mut real, "192.0.2.1");
        sock.send_to(&real.encode(), from).unwrap();
    });
    let r = udp_exchange(addr, &Message::query(77, n("www.real.test"), rtype::A, false), T).unwrap();
    assert_eq!(r.answers[0].data, RData::A("192.0.2.1".parse().unwrap()));
}
