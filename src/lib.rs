//! A DNS library, authoritative server and resolver: wire format, zone files, authoritative
//! answers, a cache, iterative resolution and DNS over UDP, TCP, TLS and HTTPS.

pub mod auth;
pub mod cache;
pub mod name;
pub mod rdata;
pub mod resolver;
pub mod server;
pub mod transport;
pub mod wire;
pub mod zone;
