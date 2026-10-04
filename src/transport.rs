//! Sending a query and getting its answer: over UDP (falling back to TCP when the answer is
//! truncated), TCP, DNS over TLS (RFC 7858) and DNS over HTTPS (RFC 8484, HTTP/1.1 POST).
//! TLS connections are kept open and reused.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use crate::wire::Message;

/// A server to send queries to.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Upstream {
    Udp(SocketAddr),
    Tcp(SocketAddr),
    /// DNS over TLS: the address and the name the certificate must carry.
    Tls {
        addr: SocketAddr,
        host: String,
    },
    /// DNS over HTTPS: the address to connect to, the host name and the path.
    Https {
        addr: SocketAddr,
        host: String,
        path: String,
    },
}

impl fmt::Display for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Upstream::Udp(a) => write!(f, "udp://{a}"),
            Upstream::Tcp(a) => write!(f, "tcp://{a}"),
            Upstream::Tls { addr, host } => write!(f, "tls://{addr}#{host}"),
            Upstream::Https { host, path, .. } => write!(f, "https://{host}{path}"),
        }
    }
}

impl Upstream {
    /// Parses `1.1.1.1`, `udp://1.1.1.1:53`, `tcp://[2606:4700::1111]`, `tls://1.1.1.1#cloudflare-dns.com`,
    /// `tls://dns.google` or `https://cloudflare-dns.com/dns-query`. Host names are looked up
    /// with the system resolver once, here.
    pub fn parse(s: &str) -> Result<Upstream, String> {
        let (scheme, rest) = s.split_once("://").unwrap_or(("udp", s));
        let addr = |hostport: &str, port: u16| -> Result<SocketAddr, String> {
            if let Ok(a) = hostport.parse::<SocketAddr>() {
                return Ok(a);
            }
            if let Ok(ip) = hostport.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
                return Ok(SocketAddr::new(ip, port));
            }
            let with_port = if hostport.contains(':') { hostport.to_string() } else { format!("{hostport}:{port}") };
            with_port
                .to_socket_addrs()
                .map_err(|e| format!("{hostport}: {e}"))?
                .next()
                .ok_or_else(|| format!("{hostport}: no address"))
        };
        // The host part of "host", "host:port", "[v6]" or "[v6]:port".
        let host_of = |hp: &str| -> String {
            if let Some(rest) = hp.strip_prefix('[') {
                return rest.split(']').next().unwrap_or("").to_string();
            }
            match hp.split_once(':') {
                Some((h, p)) if !p.contains(':') => h.to_string(),
                _ => hp.to_string(),
            }
        };
        match scheme {
            "udp" => Ok(Upstream::Udp(addr(rest, 53)?)),
            "tcp" => Ok(Upstream::Tcp(addr(rest, 53)?)),
            "tls" => {
                let (hp, name) = match rest.split_once('#') {
                    Some((hp, n)) => (hp, n.to_string()),
                    None => (rest, host_of(rest)),
                };
                Ok(Upstream::Tls { addr: addr(hp, 853)?, host: name })
            }
            "https" => {
                let (hp, path) = match rest.find('/') {
                    Some(i) => (&rest[..i], rest[i..].to_string()),
                    None => (rest, "/dns-query".to_string()),
                };
                Ok(Upstream::Https { addr: addr(hp, 443)?, host: host_of(hp), path })
            }
            _ => Err(format!("unknown scheme '{scheme}' (use udp, tcp, tls or https)")),
        }
    }
}

/// Cryptographically random numbers for query IDs and source ports, so answers cannot be guessed
/// by someone who did not see the query.
pub fn random_u16() -> u16 {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 2];
    ring::rand::SystemRandom::new().fill(&mut b).expect("system random numbers");
    u16::from_be_bytes(b)
}

type TlsStream = StreamOwned<ClientConnection, TcpStream>;

/// Sends queries, keeping TLS connections for reuse.
pub struct Client {
    dot: Arc<ClientConfig>,
    doh: Arc<ClientConfig>,
    idle: Mutex<HashMap<Upstream, Vec<BufReader<TlsStream>>>>,
}

impl Default for Client {
    fn default() -> Client {
        Client::new()
    }
}

fn tls_config(alpn: &[u8]) -> Arc<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut c = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = vec![alpn.to_vec()];
    Arc::new(c)
}

fn bad(m: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.into())
}

impl Client {
    pub fn new() -> Client {
        Client { dot: tls_config(b"dot"), doh: tls_config(b"http/1.1"), idle: Mutex::new(HashMap::new()) }
    }

    /// Sends `q` and returns the matching answer: same ID (except over HTTPS, where the ID is
    /// zero), same question.
    pub fn exchange(&self, up: &Upstream, q: &Message, timeout: Duration) -> io::Result<Message> {
        let r = match up {
            Upstream::Udp(a) => {
                let r = udp_exchange(*a, q, timeout)?;
                if r.header.tc {
                    tcp_exchange(*a, q, timeout)?
                } else {
                    r
                }
            }
            Upstream::Tcp(a) => tcp_exchange(*a, q, timeout)?,
            Upstream::Tls { .. } => self.tls_exchange(up, q, timeout)?,
            Upstream::Https { .. } => {
                let mut q0 = q.clone();
                q0.header.id = 0; // RFC 8484 section 4.1: makes answers cacheable by HTTP caches
                let mut r = self.tls_exchange(up, &q0, timeout)?;
                r.header.id = q.header.id;
                r
            }
        };
        if r.questions != q.questions {
            return Err(bad("the answer is for a different question"));
        }
        Ok(r)
    }

    fn tls_exchange(&self, up: &Upstream, q: &Message, timeout: Duration) -> io::Result<Message> {
        // A kept connection may have been closed by the server; then try once more with a new one.
        let pooled = self.idle.lock().unwrap().get_mut(up).and_then(Vec::pop);
        if let Some(mut s) = pooled {
            if let Ok(r) = self.tls_once(up, &mut s, q, timeout) {
                self.idle.lock().unwrap().entry(up.clone()).or_default().push(s);
                return Ok(r);
            }
        }
        let mut s = self.connect(up, timeout)?;
        let r = self.tls_once(up, &mut s, q, timeout)?;
        let mut idle = self.idle.lock().unwrap();
        let list = idle.entry(up.clone()).or_default();
        if list.len() < 8 {
            list.push(s);
        }
        Ok(r)
    }

    fn connect(&self, up: &Upstream, timeout: Duration) -> io::Result<BufReader<TlsStream>> {
        let (addr, host, cfg) = match up {
            Upstream::Tls { addr, host } => (addr, host, &self.dot),
            Upstream::Https { addr, host, .. } => (addr, host, &self.doh),
            _ => unreachable!(),
        };
        let tcp = TcpStream::connect_timeout(addr, timeout)?;
        tcp.set_nodelay(true)?;
        let name = ServerName::try_from(host.clone()).map_err(|e| bad(format!("{host}: {e}")))?;
        let conn = ClientConnection::new(Arc::clone(cfg), name).map_err(|e| bad(e.to_string()))?;
        Ok(BufReader::new(StreamOwned::new(conn, tcp)))
    }

    fn tls_once(&self, up: &Upstream, s: &mut BufReader<TlsStream>, q: &Message, timeout: Duration) -> io::Result<Message> {
        s.get_ref().sock.set_read_timeout(Some(timeout))?;
        s.get_ref().sock.set_write_timeout(Some(timeout))?;
        let body = q.encode();
        match up {
            Upstream::Tls { .. } => {
                let mut framed = (body.len() as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(&body);
                s.get_mut().write_all(&framed)?;
                s.get_mut().flush()?;
                let mut len = [0u8; 2];
                s.read_exact(&mut len)?;
                let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
                s.read_exact(&mut buf)?;
                let r = Message::decode(&buf).map_err(|e| bad(e.0))?;
                if r.header.id != q.header.id {
                    return Err(bad("answer with the wrong ID"));
                }
                Ok(r)
            }
            Upstream::Https { host, path, .. } => {
                let req = format!(
                    "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let mut out = req.into_bytes();
                out.extend_from_slice(&body);
                s.get_mut().write_all(&out)?;
                s.get_mut().flush()?;
                let (status, headers, payload) = read_http(s)?;
                if status != 200 {
                    return Err(bad(format!("HTTP status {status}")));
                }
                if !headers.iter().any(|(k, v)| k == "content-type" && v.starts_with("application/dns-message")) {
                    return Err(bad("the answer is not application/dns-message"));
                }
                Message::decode(&payload).map_err(|e| bad(e.0))
            }
            _ => unreachable!(),
        }
    }
}

/// Reads one HTTP/1.1 response: status, lowercased headers and the body (by length or chunked).
/// Status, headers and body of an HTTP response.
type HttpResponse = (u16, Vec<(String, String)>, Vec<u8>);

fn read_http(s: &mut impl BufRead) -> io::Result<HttpResponse> {
    let mut line = String::new();
    s.read_line(&mut line)?;
    let status: u16 =
        line.split_whitespace().nth(1).and_then(|c| c.parse().ok()).ok_or_else(|| bad(format!("bad status line {line:?}")))?;
    let mut headers = Vec::new();
    loop {
        line.clear();
        if s.read_line(&mut line)? == 0 {
            return Err(bad("connection closed in the headers"));
        }
        let l = line.trim_end();
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let get = |k: &str| headers.iter().find(|(h, _)| h == k).map(|(_, v)| v.as_str());
    let mut body = Vec::new();
    if get("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        loop {
            line.clear();
            s.read_line(&mut line)?;
            let n = usize::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16).map_err(|_| bad("bad chunk size"))?;
            if n == 0 {
                line.clear();
                s.read_line(&mut line)?;
                break;
            }
            if body.len() + n > 65_535 {
                return Err(bad("answer too large"));
            }
            let start = body.len();
            body.resize(start + n, 0);
            s.read_exact(&mut body[start..])?;
            line.clear();
            s.read_line(&mut line)?;
        }
    } else {
        let n: usize = get("content-length").and_then(|v| v.parse().ok()).ok_or_else(|| bad("no Content-Length"))?;
        if n > 65_535 {
            return Err(bad("answer too large"));
        }
        body.resize(n, 0);
        s.read_exact(&mut body)?;
    }
    Ok((status, headers, body))
}

/// A UDP socket on a random port (the other half of what makes answers hard to forge).
fn random_socket(v6: bool) -> io::Result<UdpSocket> {
    let ip: IpAddr = if v6 { Ipv6Addr::UNSPECIFIED.into() } else { Ipv4Addr::UNSPECIFIED.into() };
    for _ in 0..20 {
        let port = 1024 + random_u16() % (65535 - 1024);
        if let Ok(s) = UdpSocket::bind(SocketAddr::new(ip, port)) {
            return Ok(s);
        }
    }
    UdpSocket::bind(SocketAddr::new(ip, 0))
}

pub fn udp_exchange(addr: SocketAddr, q: &Message, timeout: Duration) -> io::Result<Message> {
    let sock = random_socket(addr.is_ipv6())?;
    sock.connect(addr)?;
    sock.send(&q.encode())?;
    let end = Instant::now() + timeout;
    let mut buf = [0u8; 65_535];
    loop {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, format!("no answer from {addr}")));
        }
        sock.set_read_timeout(Some(left))?;
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, format!("no answer from {addr}")));
            }
            // Windows reports an earlier ICMP "port unreachable" as a reset on the next receive.
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, format!("{addr} refused")))
            }
            Err(e) => return Err(e),
        };
        // A connected socket only receives from `addr`; anything that is not our answer is
        // ignored (and the wait goes on), never accepted.
        if let Ok(r) = Message::decode(&buf[..n]) {
            if r.header.qr && r.header.id == q.header.id && r.questions == q.questions {
                return Ok(r);
            }
        }
    }
}

pub fn tcp_exchange(addr: SocketAddr, q: &Message, timeout: Duration) -> io::Result<Message> {
    let mut s = TcpStream::connect_timeout(&addr, timeout)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    s.set_nodelay(true)?;
    let body = q.encode();
    let mut framed = (body.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&body);
    s.write_all(&framed)?;
    let r = read_framed(&mut s)?;
    let m = Message::decode(&r).map_err(|e| bad(e.0))?;
    if m.header.id != q.header.id {
        return Err(bad("answer with the wrong ID"));
    }
    Ok(m)
}

/// Reads one length-prefixed message from a stream.
pub fn read_framed(s: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    s.read_exact(&mut len)?;
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_forms() {
        assert_eq!(Upstream::parse("1.1.1.1").unwrap(), Upstream::Udp("1.1.1.1:53".parse().unwrap()));
        assert_eq!(Upstream::parse("tcp://[::1]:5353").unwrap(), Upstream::Tcp("[::1]:5353".parse().unwrap()));
        assert_eq!(
            Upstream::parse("tls://1.1.1.1#one.one.one.one").unwrap(),
            Upstream::Tls { addr: "1.1.1.1:853".parse().unwrap(), host: "one.one.one.one".into() }
        );
        assert_eq!(
            Upstream::parse("https://9.9.9.9/dns-query").unwrap(),
            Upstream::Https { addr: "9.9.9.9:443".parse().unwrap(), host: "9.9.9.9".into(), path: "/dns-query".into() }
        );
        assert!(Upstream::parse("quic://x").is_err());
    }

    #[test]
    fn http_bodies() {
        let mut r = io::Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n".to_vec());
        let (st, h, b) = read_http(&mut r).unwrap();
        assert_eq!((st, b.as_slice()), (200, &b"abcde"[..]));
        assert_eq!(h[0].0, "content-type");
        let mut r = io::Cursor::new(b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nno".to_vec());
        assert_eq!(read_http(&mut r).unwrap().0, 404);
    }
}
