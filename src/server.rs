//! The server: turns a query into a response (authoritative data first, then the resolver for
//! clients allowed to recurse) and serves it over UDP and TCP.

use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::auth::{self, Zones};
use crate::rdata::{class, rtype};
use crate::resolver::Resolver;
use crate::transport::read_framed;
use crate::wire::{rcode, Edns, Header, Message, Record};

/// An address range, for who may recurse or transfer zones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Net {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Net {
    pub fn parse(s: &str) -> Result<Net, String> {
        let (a, p) = s.split_once('/').map_or((s, None), |(a, p)| (a, Some(p)));
        let addr: IpAddr = a.parse().map_err(|_| format!("bad address '{a}'"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => p.parse().ok().filter(|&n| n <= max).ok_or_else(|| format!("bad prefix in '{s}'"))?,
            None => max,
        };
        Ok(Net { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        // An IPv4 client may arrive as an IPv4-mapped IPv6 address on a dual-stack socket.
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(i)) => {
                let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix) };
                u32::from(n) & mask == u32::from(i) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(i)) => {
                let mask = if self.prefix == 0 { 0 } else { u128::MAX << (128 - self.prefix) };
                u128::from(n) & mask == u128::from(i) & mask
            }
            _ => false,
        }
    }
}

#[derive(Default)]
pub struct Stats {
    pub queries: AtomicU64,
    pub authoritative: AtomicU64,
    pub recursive: AtomicU64,
    pub refused: AtomicU64,
}

pub struct Server {
    pub zones: Zones,
    pub resolver: Option<Resolver>,
    pub allow_recursion: Vec<Net>,
    pub allow_transfer: Vec<Net>,
    pub stats: Stats,
}

/// Largest UDP answer we send whatever the client offers (the DNS flag day 2020 value, which
/// avoids IP fragmentation).
const MAX_UDP: usize = 1232;

impl Server {
    pub fn new(zones: Zones, resolver: Option<Resolver>) -> Server {
        Server {
            zones,
            resolver,
            allow_recursion: vec![Net::parse("127.0.0.0/8").unwrap(), Net::parse("::1").unwrap()],
            allow_transfer: vec![Net::parse("127.0.0.0/8").unwrap(), Net::parse("::1").unwrap()],
            stats: Stats::default(),
        }
    }

    /// Answers one query. Returns the messages to send (several for a zone transfer, none for
    /// input that does not deserve an answer).
    pub fn handle(&self, packet: &[u8], client: IpAddr, tcp: bool) -> Vec<Vec<u8>> {
        self.stats.queries.fetch_add(1, Ordering::Relaxed);
        let q = match Message::decode(packet) {
            Ok(q) => q,
            Err(_) => {
                // Unparseable: FORMERR if there is at least a header and it is a query.
                if packet.len() >= 12 && packet[2] & 0x80 == 0 {
                    let h = Header {
                        id: u16::from_be_bytes([packet[0], packet[1]]),
                        qr: true,
                        rcode: rcode::FORMERR,
                        ..Header::default()
                    };
                    return vec![Message { header: h, ..Message::default() }.encode()];
                }
                return Vec::new();
            }
        };
        if q.header.qr {
            return Vec::new(); // never answer an answer
        }
        let limit = if tcp { 65_535 } else { q.edns.as_ref().map_or(512, |e| (e.udp_size as usize).clamp(512, MAX_UDP)) };
        let mut r = Message::response_to(&q);
        let error = |mut r: Message, code: u16| {
            r.header.rcode = code;
            vec![r.encode_limited(limit)]
        };
        if q.header.opcode != 0 {
            return error(r, rcode::NOTIMP);
        }
        if let Some(e) = &q.edns {
            if e.version > 0 {
                r.edns = Some(Edns::default());
                return error(r, rcode::BADVERS);
            }
        }
        if q.questions.len() != 1 {
            return error(r, rcode::FORMERR);
        }
        let qn = &q.questions[0];
        if qn.qclass != class::IN && qn.qclass != class::ANY {
            return error(r, rcode::REFUSED);
        }
        if qn.qtype == rtype::AXFR || qn.qtype == rtype::IXFR {
            return self.transfer(&q, r, client, tcp);
        }
        let may_recurse = self.resolver.is_some() && self.allow_recursion.iter().any(|n| n.contains(client));
        if let Some(zone) = self.zones.find(&qn.name) {
            self.stats.authoritative.fetch_add(1, Ordering::Relaxed);
            let a = auth::answer(zone, &qn.name, qn.qtype);
            r.header.aa = a.aa;
            r.header.rcode = a.rcode;
            r.header.ra = may_recurse;
            r.answers = a.answers;
            r.authority = a.authority;
            r.additional = a.additional;
            return vec![r.encode_limited(limit)];
        }
        match (&self.resolver, q.header.rd && may_recurse) {
            (Some(res), true) => {
                self.stats.recursive.fetch_add(1, Ordering::Relaxed);
                let a = res.resolve(&qn.name, qn.qtype);
                r.header.ra = true;
                r.header.rcode = a.rcode;
                r.answers = a.answers;
                r.authority = a.authority;
                vec![r.encode_limited(limit)]
            }
            _ => {
                self.stats.refused.fetch_add(1, Ordering::Relaxed);
                r.header.ra = may_recurse;
                error(r, rcode::REFUSED)
            }
        }
    }

    /// AXFR over TCP for allowed clients: the zone's records between two copies of its SOA, in
    /// as many messages as it takes (RFC 5936).
    fn transfer(&self, q: &Message, mut r: Message, client: IpAddr, tcp: bool) -> Vec<Vec<u8>> {
        let qn = &q.questions[0];
        let zone = self.zones.get(&qn.name);
        if !tcp || qn.qtype == rtype::IXFR || zone.is_none() || !self.allow_transfer.iter().any(|n| n.contains(client)) {
            r.header.rcode = if zone.is_none() { rcode::NOTAUTH } else { rcode::REFUSED };
            return vec![r.encode()];
        }
        let zone = zone.unwrap();
        let mut recs: Vec<Record> = zone.records();
        recs.push(recs[0].clone());
        r.header.aa = true;
        let mut out = Vec::new();
        let mut batch: Vec<Record> = Vec::new();
        let mut size = 0;
        for rec in recs {
            // Start a new message before the 64 KiB limit (sizes without compression, so an
            // upper bound).
            let mut w = crate::wire::Writer::uncompressed();
            rec.data.encode(&mut w);
            let est = rec.name.wire_len() + 10 + w.len();
            if size + est > 64_000 && !batch.is_empty() {
                let mut m = r.clone();
                m.answers = std::mem::take(&mut batch);
                out.push(m.encode());
                r.questions.clear(); // only the first message repeats the question
                size = 0;
            }
            size += est;
            batch.push(rec);
        }
        let mut m = r;
        m.answers = batch;
        out.push(m.encode());
        out
    }
}

/// Serves UDP on `sock` with `threads` workers until the process ends.
pub fn serve_udp(server: Arc<Server>, sock: UdpSocket, threads: usize) -> io::Result<()> {
    let (tx, rx) = mpsc::sync_channel::<(Vec<u8>, SocketAddr)>(4096);
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..threads.max(1) {
        let rx = Arc::clone(&rx);
        let out = sock.try_clone()?;
        let server = Arc::clone(&server);
        thread::spawn(move || loop {
            let job = rx.lock().unwrap().recv();
            let Ok((pkt, from)) = job else { return };
            for resp in server.handle(&pkt, from.ip(), false) {
                let _ = out.send_to(&resp, from);
            }
        });
    }
    let mut buf = vec![0u8; 65_535];
    loop {
        match sock.recv_from(&mut buf) {
            // When the workers are behind, drop the query: the client will retry.
            Ok((n, from)) => {
                let _ = tx.try_send((buf[..n].to_vec(), from));
            }
            // Windows reports ICMP errors from earlier sends as failed receives; keep going.
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
            Err(e) => return Err(e),
        }
    }
}

/// Serves TCP on `listener`: one thread per connection, at most `max_conns` at once, each
/// answering queries until the client closes or is idle for 10 seconds.
pub fn serve_tcp(server: Arc<Server>, listener: TcpListener, max_conns: usize) -> io::Result<()> {
    let open = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        if open.load(Ordering::Relaxed) >= max_conns {
            continue; // dropped: closes the connection
        }
        open.fetch_add(1, Ordering::Relaxed);
        let server = Arc::clone(&server);
        let open = Arc::clone(&open);
        thread::spawn(move || {
            let _ = tcp_conn(&server, stream);
            open.fetch_sub(1, Ordering::Relaxed);
        });
    }
    Ok(())
}

fn tcp_conn(server: &Server, mut s: TcpStream) -> io::Result<()> {
    let peer = s.peer_addr()?.ip();
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;
    s.set_nodelay(true)?;
    loop {
        let pkt = read_framed(&mut s)?;
        for resp in server.handle(&pkt, peer, true) {
            let mut framed = (resp.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&resp);
            s.write_all(&framed)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nets() {
        let n = Net::parse("192.168.0.0/16").unwrap();
        assert!(n.contains("192.168.4.5".parse().unwrap()));
        assert!(!n.contains("192.169.0.1".parse().unwrap()));
        assert!(n.contains("::ffff:192.168.1.1".parse().unwrap()));
        assert!(Net::parse("::1").unwrap().contains("::1".parse().unwrap()));
        assert!(Net::parse("0.0.0.0/0").unwrap().contains("8.8.8.8".parse().unwrap()));
        assert!(Net::parse("10.0.0.0/33").is_err());
    }
}
