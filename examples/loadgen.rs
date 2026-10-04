//! A UDP load generator: `threads` sockets, each keeping `window` queries in flight, asking for
//! `h0.ZONE` to `h{names-1}.ZONE` in turn (recursion desired), for `seconds`. Prints answers per second and latency
//! percentiles.
//!
//!     cargo run --release --example loadgen -- 127.0.0.1:5400 bench.test 10000 8 32 10

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dnscore::name::Name;
use dnscore::rdata::rtype;
use dnscore::wire::Message;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let target: SocketAddr = a[0].parse().unwrap();
    let zone = a[1].clone();
    let names: usize = a[2].parse().unwrap();
    let threads: usize = a[3].parse().unwrap();
    let window: usize = a[4].parse().unwrap();
    let seconds: f64 = a[5].parse().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let stop = Arc::clone(&stop);
            let zone = zone.clone();
            std::thread::spawn(move || run(target, &zone, names, window, t, &stop))
        })
        .collect();
    std::thread::sleep(Duration::from_secs_f64(seconds));
    stop.store(true, Ordering::SeqCst);
    let mut lat = Vec::new();
    let (mut answered, mut lost, mut bad) = (0u64, 0u64, 0u64);
    for h in handles {
        let (l, lo, b) = h.join().unwrap();
        answered += l.len() as u64;
        lat.extend(l);
        lost += lo;
        bad += b;
    }
    lat.sort_unstable();
    let p = |q: f64| lat.get(((lat.len() as f64 - 1.0) * q) as usize).copied().unwrap_or(0) as f64 / 1000.0;
    println!(
        "{:.0} answers/s, latency p50 {:.3} ms, p99 {:.3} ms, p99.9 {:.3} ms; {lost} lost, {bad} wrong",
        answered as f64 / seconds,
        p(0.5),
        p(0.99),
        p(0.999)
    );
}

/// Returns latencies in microseconds, lost count and wrong-answer count.
fn run(target: SocketAddr, zone: &str, names: usize, window: usize, seed: usize, stop: &AtomicBool) -> (Vec<u32>, u64, u64) {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.connect(target).unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    // Pre-encode the queries; the ID is patched in per send.
    let queries: Vec<Vec<u8>> = (0..names)
        .map(|i| Message::query(0, Name::parse_fqdn(&format!("h{i}.{zone}")).unwrap(), rtype::A, true).encode())
        .collect();
    let mut sent_at: Vec<Option<Instant>> = vec![None; 65_536];
    let mut next_id: u16 = (seed * 7919) as u16;
    let mut next_name = seed * 1013 % names;
    let mut in_flight = 0usize;
    let mut lat = Vec::with_capacity(1 << 20);
    let (mut lost, mut bad) = (0u64, 0u64);
    let mut buf = [0u8; 4096];
    while !stop.load(Ordering::Relaxed) {
        while in_flight < window {
            let mut q = queries[next_name].clone();
            q[..2].copy_from_slice(&next_id.to_be_bytes());
            sent_at[next_id as usize] = Some(Instant::now());
            if sock.send(&q).is_err() {
                break;
            }
            in_flight += 1;
            next_id = next_id.wrapping_add(1);
            next_name = (next_name + 1) % names;
        }
        match sock.recv(&mut buf) {
            Ok(n) if n >= 12 => {
                let id = u16::from_be_bytes([buf[0], buf[1]]);
                match sent_at[id as usize].take() {
                    Some(t) => {
                        // Answer count must be 1 and the response code NOERROR.
                        if buf[3] & 0xf != 0 || buf[7] != 1 {
                            bad += 1;
                        }
                        lat.push(t.elapsed().as_micros() as u32);
                        in_flight -= 1;
                    }
                    None => bad += 1,
                }
            }
            Ok(_) => bad += 1,
            Err(_) => {
                // Nothing for 200 ms: count what is outstanding as lost and start again.
                lost += in_flight as u64;
                in_flight = 0;
                sent_at.iter_mut().for_each(|s| *s = None);
            }
        }
    }
    (lat, lost, bad)
}
