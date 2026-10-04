use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use dnscore::auth::Zones;
use dnscore::cache::Limits;
use dnscore::name::Name;
use dnscore::rdata::{self, rtype};
use dnscore::resolver::{Mode, Options, Resolver};
use dnscore::server::{serve_tcp, serve_udp, Net, Server};
use dnscore::transport::{random_u16, Client, Upstream};
use dnscore::wire::{rcode, Message, Record};
use dnscore::zone::Zone;
use serde::Deserialize;

#[derive(Parser)]
#[command(
    name = "dnsr",
    version,
    about = "Authoritative DNS server, caching resolver (recursive or over TLS/HTTPS) and query tool"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve zones and/or resolve for clients
    Serve(ServeArgs),
    /// Send one query and print the answer, like dig
    Query {
        /// The name to look up
        name: String,
        /// Record type (A, AAAA, MX, TXT, NS, SOA, ANY, AXFR, TYPE123, ...)
        #[arg(default_value = "A")]
        qtype: String,
        /// Server: 1.1.1.1, tcp://..., tls://1.1.1.1#cloudflare-dns.com, https://dns.google/dns-query
        #[arg(short, long, default_value = "127.0.0.1")]
        server: String,
        /// Do not ask the server to recurse
        #[arg(long)]
        norec: bool,
        /// Seconds to wait
        #[arg(long, default_value_t = 3.0)]
        timeout: f64,
    },
    /// Resolve a name from the root servers here, without a server, and show each step
    Resolve {
        name: String,
        #[arg(default_value = "A")]
        qtype: String,
        /// Print every query sent on the way
        #[arg(long)]
        trace: bool,
        /// Forward to these instead of iterating from the root (same forms as query --server)
        #[arg(long = "forward", value_name = "UPSTREAM")]
        forward: Vec<String>,
    },
    /// Load a zone file, report problems, and print it in canonical form with --print
    Check {
        file: PathBuf,
        /// The zone's apex (default: the file name without .zone)
        #[arg(long)]
        origin: Option<String>,
        #[arg(long)]
        print: bool,
    },
}

#[derive(clap::Args)]
struct ServeArgs {
    /// Configuration file (see the README); flags below add to it
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Address to listen on, UDP and TCP (repeatable; default 127.0.0.1:53)
    #[arg(short, long = "listen", value_name = "ADDR")]
    listen: Vec<SocketAddr>,
    /// Serve a zone: ORIGIN=FILE (repeatable)
    #[arg(short, long = "zone", value_name = "ORIGIN=FILE")]
    zone: Vec<String>,
    /// Resolve names outside the zones by iterating from the root servers
    #[arg(long)]
    recursive: bool,
    /// Resolve names outside the zones by forwarding to this upstream (repeatable)
    #[arg(long = "forward", value_name = "UPSTREAM")]
    forward: Vec<String>,
    /// Address ranges allowed to use the resolver (repeatable; default loopback only)
    #[arg(long = "allow", value_name = "CIDR")]
    allow: Vec<String>,
    /// Worker threads for UDP
    #[arg(long, default_value_t = 8)]
    threads: usize,
}

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct Config {
    listen: Vec<SocketAddr>,
    threads: Option<usize>,
    #[serde(rename = "zone")]
    zones: Vec<ZoneConfig>,
    resolver: Option<ResolverConfig>,
    allow_transfer: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ZoneConfig {
    origin: String,
    file: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolverConfig {
    /// "recursive" or "forward"
    mode: String,
    #[serde(default)]
    upstreams: Vec<String>,
    #[serde(default)]
    allow: Vec<String>,
    cache_size: Option<usize>,
    max_ttl: Option<u32>,
    #[serde(default)]
    ipv6: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("dnsr: {e}");
            ExitCode::from(2)
        }
    }
}

fn parse_type(s: &str) -> Result<u16, String> {
    rdata::type_from_name(s).ok_or_else(|| format!("unknown type '{s}'"))
}

fn load_zone(origin: &str, file: &PathBuf) -> Result<Zone, String> {
    let text = std::fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
    let o = Name::parse_fqdn(origin).map_err(|e| e.to_string())?;
    let z = Zone::parse(&text, &o).map_err(|e| format!("{}: {e}", file.display()))?;
    for w in &z.warnings {
        eprintln!("{}: warning: {w}", file.display());
    }
    Ok(z)
}

fn run() -> Result<ExitCode, String> {
    match Cli::parse().cmd {
        Cmd::Serve(a) => serve(a).map(|_| ExitCode::SUCCESS),
        Cmd::Query { name, qtype, server, norec, timeout } => query(&name, &qtype, &server, norec, timeout),
        Cmd::Resolve { name, qtype, trace, forward } => {
            let mode = if forward.is_empty() {
                Mode::recursive()
            } else {
                Mode::Forward { upstreams: forward.iter().map(|s| Upstream::parse(s)).collect::<Result<_, _>>()? }
            };
            let r = Resolver::new(mode, Options::default());
            if trace {
                r.start_trace();
            }
            let n = Name::parse_fqdn(&name).map_err(|e| e.to_string())?;
            let t = Instant::now();
            let res = r.resolve(&n, parse_type(&qtype)?);
            let took = t.elapsed();
            for line in r.take_trace() {
                println!(";; {line}");
            }
            println!(";; {} in {:.0} ms", rcode::name(res.rcode), took.as_secs_f64() * 1e3);
            for rec in res.answers.iter().chain(&res.authority) {
                println!("{}", rec.to_text());
            }
            Ok(if res.rcode == rcode::SERVFAIL { ExitCode::from(1) } else { ExitCode::SUCCESS })
        }
        Cmd::Check { file, origin, print } => {
            let origin =
                origin.unwrap_or_else(|| file.file_name().unwrap().to_string_lossy().trim_end_matches(".zone").to_string());
            let t = Instant::now();
            let z = load_zone(&origin, &file)?;
            eprintln!(
                "{}: {} records, {} names, loaded in {:.1} ms",
                z.origin,
                z.len(),
                z.names().count(),
                t.elapsed().as_secs_f64() * 1e3
            );
            if print {
                for r in z.records() {
                    println!("{}", r.to_text());
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn query(name: &str, qtype: &str, server: &str, norec: bool, timeout: f64) -> Result<ExitCode, String> {
    let up = Upstream::parse(server)?;
    let n = Name::parse_fqdn(name).map_err(|e| e.to_string())?;
    let t = parse_type(qtype)?;
    let q = Message::query(random_u16(), n, t, !norec);
    let timeout = Duration::from_secs_f64(timeout);
    let start = Instant::now();
    if t == rtype::AXFR {
        let (Upstream::Tcp(addr) | Upstream::Udp(addr)) = up else { return Err("AXFR needs a plain TCP server".into()) };
        return axfr(addr, &q, timeout);
    }
    let r = Client::new().exchange(&up, &q, timeout).map_err(|e| format!("{up}: {e}"))?;
    let took = start.elapsed();
    print_message(&r);
    println!(";; from {up} in {:.1} ms, {} bytes", took.as_secs_f64() * 1e3, r.encode().len());
    Ok(ExitCode::SUCCESS)
}

fn axfr(addr: SocketAddr, q: &Message, timeout: Duration) -> Result<ExitCode, String> {
    use std::io::Write;
    let mut s = std::net::TcpStream::connect_timeout(&addr, timeout).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    let body = q.encode();
    let mut framed = (body.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&body);
    s.write_all(&framed).map_err(|e| e.to_string())?;
    let mut soas = 0;
    let mut count = 0;
    while soas < 2 {
        let buf = dnscore::transport::read_framed(&mut s).map_err(|e| e.to_string())?;
        let m = Message::decode(&buf).map_err(|e| e.to_string())?;
        if m.header.rcode != rcode::NOERROR {
            println!(";; transfer refused: {}", rcode::name(m.header.rcode));
            return Ok(ExitCode::from(1));
        }
        for r in &m.answers {
            println!("{}", r.to_text());
            count += 1;
            if r.rtype() == rtype::SOA {
                soas += 1;
            }
        }
    }
    println!(";; {count} records");
    Ok(ExitCode::SUCCESS)
}

fn print_message(r: &Message) {
    let h = &r.header;
    let mut flags = Vec::new();
    for (on, f) in [(h.qr, "qr"), (h.aa, "aa"), (h.tc, "tc"), (h.rd, "rd"), (h.ra, "ra"), (h.ad, "ad"), (h.cd, "cd")] {
        if on {
            flags.push(f);
        }
    }
    println!(";; {}, id {}, flags: {}", rcode::name(h.rcode), h.id, flags.join(" "));
    for q in &r.questions {
        println!(";; question: {} {}", q.name, rdata::type_name(q.qtype));
    }
    let section = |title: &str, recs: &[Record]| {
        if !recs.is_empty() {
            println!("\n;; {title}");
            for rec in recs {
                println!("{}", rec.to_text());
            }
        }
    };
    section("answer", &r.answers);
    section("authority", &r.authority);
    section("additional", &r.additional);
    println!();
}

fn serve(a: ServeArgs) -> Result<(), String> {
    let mut cfg: Config = match &a.config {
        Some(p) => {
            let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
            toml::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))?
        }
        None => Config::default(),
    };
    cfg.listen.extend(a.listen.iter().copied());
    if cfg.listen.is_empty() {
        cfg.listen.push("127.0.0.1:53".parse().unwrap());
    }
    for z in &a.zone {
        let (o, f) = z.split_once('=').ok_or_else(|| format!("--zone wants ORIGIN=FILE, got '{z}'"))?;
        cfg.zones.push(ZoneConfig { origin: o.into(), file: f.into() });
    }
    if a.recursive || !a.forward.is_empty() {
        cfg.resolver = Some(ResolverConfig {
            mode: if a.recursive { "recursive".into() } else { "forward".into() },
            upstreams: a.forward.clone(),
            allow: a.allow.clone(),
            cache_size: None,
            max_ttl: None,
            ipv6: false,
        });
    }
    let mut zones = Zones::new();
    for z in &cfg.zones {
        let t = Instant::now();
        let zone = load_zone(&z.origin, &z.file)?;
        eprintln!("zone {}: {} records ({:.0} ms)", zone.origin, zone.len(), t.elapsed().as_secs_f64() * 1e3);
        zones.insert(zone);
    }
    let resolver = match &cfg.resolver {
        None => None,
        Some(rc) => {
            let mode = match rc.mode.as_str() {
                "recursive" => Mode::recursive(),
                "forward" => {
                    if rc.upstreams.is_empty() {
                        return Err("forward mode needs at least one upstream".into());
                    }
                    Mode::Forward { upstreams: rc.upstreams.iter().map(|s| Upstream::parse(s)).collect::<Result<_, _>>()? }
                }
                m => return Err(format!("resolver mode '{m}' (use recursive or forward)")),
            };
            let limits = Limits {
                max_entries: rc.cache_size.unwrap_or(100_000),
                max_ttl: rc.max_ttl.unwrap_or(86_400),
                ..Limits::default()
            };
            eprintln!(
                "resolver: {}",
                match &mode {
                    Mode::Recursive { .. } => "recursive from the root servers".to_string(),
                    Mode::Forward { upstreams } =>
                        format!("forwarding to {}", upstreams.iter().map(|u| u.to_string()).collect::<Vec<_>>().join(", ")),
                }
            );
            Some(Resolver::new(mode, Options { limits, ipv6: rc.ipv6, ..Options::default() }))
        }
    };
    if zones.is_empty() && resolver.is_none() {
        return Err("nothing to serve: give a zone, --recursive or --forward".into());
    }
    let mut server = Server::new(zones, resolver);
    if let Some(rc) = &cfg.resolver {
        if !rc.allow.is_empty() {
            server.allow_recursion = rc.allow.iter().map(|s| Net::parse(s)).collect::<Result<_, _>>()?;
        }
    }
    if let Some(t) = &cfg.allow_transfer {
        server.allow_transfer = t.iter().map(|s| Net::parse(s)).collect::<Result<_, _>>()?;
    }
    let server = Arc::new(server);
    let threads = cfg.threads.unwrap_or(a.threads);
    let mut handles = Vec::new();
    for addr in &cfg.listen {
        let udp = UdpSocket::bind(addr).map_err(|e| format!("UDP {addr}: {e}"))?;
        let tcp = TcpListener::bind(addr).map_err(|e| format!("TCP {addr}: {e}"))?;
        eprintln!("listening on {addr} (UDP and TCP)");
        let s = Arc::clone(&server);
        handles.push(std::thread::spawn(move || serve_udp(s, udp, threads)));
        let s = Arc::clone(&server);
        handles.push(std::thread::spawn(move || serve_tcp(s, tcp, 256)));
    }
    for h in handles {
        if let Ok(Err(e)) = h.join() {
            return Err(e.to_string());
        }
    }
    Ok(())
}
