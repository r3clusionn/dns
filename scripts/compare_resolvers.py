"""Runs `dnsr serve --recursive` and asks it and a public resolver the same questions, then
compares the answers.

    cargo build --release
    python scripts/compare_resolvers.py [scripts/domains.txt] [--type A] [--reference 1.1.1.1]

For each name: the response codes must match; for NOERROR both must have addresses (or both
none). Address sets are also compared exactly, but big sites hand out different addresses per
query or location, so that count is reported, not required. Needs dnspython.
"""
import argparse
import subprocess
import sys
import time

import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

ap = argparse.ArgumentParser()
ap.add_argument("names", nargs="?", default=__file__.rsplit("scripts", 1)[0] + "scripts/domains.txt")
ap.add_argument("--type", default="A")
ap.add_argument("--reference", default="1.1.1.1")
ap.add_argument("--port", type=int, default=5399)
a = ap.parse_args()

exe = __file__.rsplit("scripts", 1)[0] + "target/release/dnsr"
server = subprocess.Popen([exe, "serve", "--recursive", "--listen", f"127.0.0.1:{a.port}"], stderr=subprocess.DEVNULL)
time.sleep(0.5)
names = [l.strip() for l in open(a.names) if l.strip()]
qtype = dns.rdatatype.from_text(a.type)


def ask(where, port, name):
    q = dns.message.make_query(name, qtype)
    t = time.perf_counter()
    try:
        r = dns.query.udp(q, where, port=port, timeout=8)
        if r.flags & dns.flags.TC:
            r = dns.query.tcp(q, where, port=port, timeout=8)
    except Exception as e:
        return None, str(e), time.perf_counter() - t
    addrs = {rd.to_text() for rr in r.answer if rr.rdtype == qtype for rd in rr}
    return r.rcode(), addrs, time.perf_counter() - t


import dns.flags  # noqa: E402

same_rcode = same_shape = same_set = 0
times = []
mismatches = []
try:
    for name in names:
        rc1, ours, t1 = ask("127.0.0.1", a.port, name)
        rc2, ref, _ = ask(a.reference, 53, name)
        times.append(t1)
        if rc1 == rc2:
            same_rcode += 1
            if rc1 != dns.rcode.NOERROR or bool(ours) == bool(ref):
                same_shape += 1
            else:
                mismatches.append((name, "addresses on one side only", ours, ref))
            if ours == ref:
                same_set += 1
        else:
            mismatches.append((name, f"rcode {dns.rcode.to_text(rc1) if rc1 is not None else ours} vs {dns.rcode.to_text(rc2) if rc2 is not None else ref}", ours, ref))
    # Second pass: everything should now come from dnsr's cache.
    cached = [ask("127.0.0.1", a.port, n)[2] for n in names]
finally:
    server.kill()

n = len(names)
times.sort()
cached.sort()
print(f"{n} names, type {a.type}, reference {a.reference}")
print(f"  same response code: {same_rcode}")
print(f"  same response code and both with or both without addresses: {same_shape}")
print(f"  identical address sets: {same_set}")
print(f"  dnsr, cold cache: median {times[n // 2] * 1e3:.0f} ms, 90th percentile {times[n * 9 // 10] * 1e3:.0f} ms")
print(f"  dnsr, second pass from its cache: median {cached[n // 2] * 1e3:.2f} ms")
for m in mismatches:
    print("  differs:", m)
sys.exit(1 if same_shape != n else 0)
