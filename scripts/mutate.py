"""Breaks one check at a time and runs the tests, to see that each check is actually tested.

    python scripts/mutate.py

Each mutation is applied to the source, `cargo test --release` runs (with a time limit, since a
broken loop check can hang), and the source is restored, with its time bumped so cargo rebuilds.
Do not build or run anything else in this folder while it runs.
"""
import os
import subprocess
import time

ROOT = os.path.join(os.path.dirname(__file__), "..")

MUTATIONS = [
    ("src/wire.rs", "if target >= limit {", "if false {", "compression pointers may point anywhere (loops)"),
    ("src/wire.rs", "                    if s < 2 {\n                        tc = true;", "                    if false {\n                        tc = true;", "truncation does not set TC"),
    ("src/wire.rs", "if r.pos() != buf.len() {", "if false {", "trailing bytes after the last record accepted"),
    ("src/wire.rs", "if total > MAX_WIRE {", "if false {", "decoded names may exceed 255 bytes"),
    ("src/transport.rs", "if r.header.qr && r.header.id == q.header.id && r.questions == q.questions {", "if r.header.qr {", "UDP answers are not matched to the query"),
    ("src/transport.rs", "if r.header.tc {\n                    tcp_exchange", "if false {\n                    tcp_exchange", "no TCP retry after truncation"),
    ("src/resolver.rs", ".filter(|r| r.name.is_subdomain_of(&zone)).cloned().collect();", ".cloned().collect();", "answers outside the server's zone are believed"),
    ("src/resolver.rs", "a.rtype() == t && a.name.is_subdomain_of(&zone)", "a.rtype() == t", "out-of-bailiwick glue is believed"),
    ("src/resolver.rs", "if seen.contains(&next) || seen.len() > MAX_CHAIN {", "if seen.len() > 1000 {", "CNAME loops are not detected"),
    ("src/resolver.rs", "s.ttl = s.ttl.min(minimum);", "s.ttl = s.ttl;", "negative TTL ignores the SOA minimum"),
    ("src/cache.rs", "if age >= e.ttl as u64 || e.rank < min_rank {", "if e.rank < min_rank {", "expired cache entries are served"),
    ("src/cache.rs", "if alive && old.rank > e.rank {", "if false {", "glue may replace answers in the cache"),
    ("src/auth.rs", "if zone.get(&anc, rtype::NS).is_some() {", "if false {", "no referrals at zone cuts"),
    ("src/auth.rs", "None if zone.has_descendants(&name) => {", "None if false => {", "empty non-terminals are NXDOMAIN"),
    ("src/auth.rs", "RData::Soa { minimum, .. } => set.ttl.min(*minimum),", "RData::Soa { .. } => set.ttl,", "negative answers use the SOA TTL"),
    ("src/auth.rs", "if anc == *name && qtype == rtype::DS {", "if false {", "DS queries are referred to the child"),
    ("src/zone.rs", "return Err(format!(\"{owner} has a CNAME and other data\"));", "return Ok(());", "CNAME next to other data is accepted"),
    ("src/server.rs", "if !tcp || qn.qtype == rtype::IXFR", "if qn.qtype == rtype::IXFR", "zone transfers over UDP"),
    ("src/server.rs", "|| !self.allow_transfer.iter().any(|n| n.contains(client))", "", "anyone may transfer zones"),
    ("src/server.rs", "if q.header.qr {\n            return Vec::new();", "if false {\n            return Vec::new();", "responses are answered"),
]


def run_tests():
    try:
        r = subprocess.run(["cargo", "test", "--release", "-q"], cwd=ROOT, capture_output=True, text=True, timeout=600)
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        subprocess.run(["taskkill", "/F", "/IM", "server-*", "/IM", "resolver-*", "/IM", "wire-*"], capture_output=True)
        return False


caught = 0
for path, old, new, what in MUTATIONS:
    full = os.path.join(ROOT, path)
    src = open(full, encoding="utf-8", newline="").read()
    if src.count(old) != 1:
        print(f"SKIP (pattern found {src.count(old)} times): {what}")
        continue
    try:
        open(full, "w", encoding="utf-8", newline="").write(src.replace(old, new))
        passed = run_tests()
    finally:
        open(full, "w", encoding="utf-8", newline="").write(src)
        now = time.time()
        os.utime(full, (now, now))
    caught += not passed
    print(f"{'caught  ' if not passed else 'MISSED  '} {what}", flush=True)
print(f"{caught} of {len(MUTATIONS)} caught")
