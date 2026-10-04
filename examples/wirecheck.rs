//! Reads messages as hex, one per line, and writes each back as hex after decoding and encoding
//! it again (or `ERR reason`). `scripts/check_wire.py` feeds it messages made by dnspython.

use std::io::{self, BufRead, Write};

use dnscore::wire::Message;

fn main() {
    let out = io::stdout();
    let mut out = out.lock();
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let bytes: Vec<u8> = (0..line.len()).step_by(2).map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap()).collect();
        match Message::decode(&bytes) {
            Ok(m) => {
                let hex: String = m.encode().iter().map(|b| format!("{b:02x}")).collect();
                writeln!(out, "{hex}").unwrap();
            }
            Err(e) => writeln!(out, "ERR {e}").unwrap(),
        }
    }
}
