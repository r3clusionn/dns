//! Helpers: zones from text and servers on loopback addresses.

#![allow(dead_code)]

use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::sync::Arc;

use dnscore::auth::Zones;
use dnscore::name::Name;
use dnscore::resolver::Resolver;
use dnscore::server::{serve_tcp, serve_udp, Server};
use dnscore::zone::Zone;

pub fn n(s: &str) -> Name {
    Name::parse_fqdn(s).unwrap()
}

pub fn zone(origin: &str, text: &str) -> Zone {
    Zone::parse(text, &n(origin)).unwrap_or_else(|e| panic!("{origin}: {e}"))
}

pub fn zones(list: Vec<Zone>) -> Zones {
    let mut z = Zones::new();
    for x in list {
        z.insert(x);
    }
    z
}

/// Starts a server on `ip:port` (UDP and TCP). Port 0 picks a free one; returns the address.
pub fn start(ip: &str, port: u16, z: Zones, resolver: Option<Resolver>) -> (SocketAddr, Arc<Server>) {
    let ip: IpAddr = ip.parse().unwrap();
    let udp = UdpSocket::bind(SocketAddr::new(ip, port)).unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(addr).unwrap();
    let server = Arc::new(Server::new(z, resolver));
    let s = Arc::clone(&server);
    std::thread::spawn(move || serve_udp(s, udp, 2));
    let s = Arc::clone(&server);
    std::thread::spawn(move || serve_tcp(s, tcp, 16));
    (addr, server)
}

/// A port that is free on 127.0.0.1 for UDP and TCP (used for every fake server, each on its
/// own loopback address).
pub fn free_port() -> u16 {
    loop {
        let u = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = u.local_addr().unwrap().port();
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}
