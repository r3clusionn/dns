//! Loads a zone file and prints every record as `name|type|ttl|hex of the data in wire format`,
//! one per line. `scripts/check_zone.py` compares this with dnspython's reading of the same file.
//!
//!     cargo run --release --example zonedump -- root.zone .

use dnscore::name::Name;
use dnscore::wire::Writer;
use dnscore::zone::Zone;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let text = std::fs::read_to_string(&args[0]).expect("read zone");
    let origin = Name::parse_fqdn(&args[1]).expect("origin");
    let t = std::time::Instant::now();
    let zone = match Zone::parse(&text, &origin) {
        Ok(z) => z,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("loaded {} records in {:.1} ms", zone.len(), t.elapsed().as_secs_f64() * 1e3);
    for w in &zone.warnings {
        eprintln!("warning: {w}");
    }
    let mut out = String::new();
    for r in zone.records() {
        let mut w = Writer::uncompressed();
        r.data.encode(&mut w);
        let hex: String = w.finish().iter().map(|b| format!("{b:02x}")).collect();
        out.push_str(&format!("{}|{}|{}|{hex}\n", r.name.to_lowercase(), r.rtype(), r.ttl));
    }
    print!("{out}");
}
