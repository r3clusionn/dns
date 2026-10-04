"""Throughput of dnsr against CoreDNS on the same machine, in rotated rounds.

    cargo build --release --examples
    python scripts/bench.py PATH_TO_COREDNS_EXE [ROUNDS] [SECONDS]

Two cases, each with the load generator in examples/loadgen.rs (8 sockets, 32 queries in flight
each) asking for 10,000 different names:
  authoritative  both serve the zone bench.test from a zone file;
  cached         both forward to dnsr's authoritative server and answer from their cache (the
                 cache is warmed first, so every measured query is a cache hit).
"""
import os
import statistics
import subprocess
import sys
import tempfile
import time

import psutil

coredns = sys.argv[1]
rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 3
secs = sys.argv[3] if len(sys.argv) > 3 else "10"
root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
dnsr = os.path.join(root, "target", "release", "dnsr.exe")
loadgen = os.path.join(root, "target", "release", "examples", "loadgen.exe")

work = tempfile.mkdtemp(prefix="dnsr-bench-")
zone = os.path.join(work, "bench.test.zone")
with open(zone, "w") as f:
    f.write("$TTL 3600\n@ SOA ns admin 1 3600 600 86400 300\n@ NS ns\nns A 192.0.2.1\n")
    for i in range(10_000):
        f.write(f"h{i} A 10.{i // 65536}.{i // 256 % 256}.{i % 256}\n")
corefile = os.path.join(work, "Corefile")
with open(corefile, "w") as f:
    f.write(f"bench.test:5401 {{\n    bind 127.0.0.1\n    file {zone.replace(os.sep, '/')}\n}}\n")
    f.write(".:5403 {\n    bind 127.0.0.1\n    forward . 127.0.0.1:5400\n    cache 3600\n}\n")

# dnsr's authoritative server (the upstream for both caches) runs throughout.
auth = subprocess.Popen([dnsr, "serve", "--listen", "127.0.0.1:5400", "--zone", f"bench.test={zone}", "--threads", "8"], stderr=subprocess.DEVNULL)
time.sleep(0.5)


def load(port, seconds=secs):
    out = subprocess.run([loadgen, f"127.0.0.1:{port}", "bench.test", "10000", "8", "32", seconds], capture_output=True, text=True).stdout.strip()
    return float(out.split()[0]), out


def start(kind):
    if kind == "dnsr auth":
        return subprocess.Popen([dnsr, "serve", "--listen", "127.0.0.1:5402", "--zone", f"bench.test={zone}", "--threads", "8"], stderr=subprocess.DEVNULL), 5402
    if kind == "dnsr cache":
        return subprocess.Popen([dnsr, "serve", "--listen", "127.0.0.1:5404", "--forward", "udp://127.0.0.1:5400", "--threads", "8"], stderr=subprocess.DEVNULL), 5404
    p = subprocess.Popen([coredns, "-conf", corefile], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return p, 5401 if kind == "coredns auth" else 5403


results = {}
cpus = {}
try:
    for r in range(rounds):
        kinds = ["dnsr auth", "coredns auth", "dnsr cache", "coredns cache"]
        kinds = kinds[r % 4:] + kinds[: r % 4]
        for k in kinds:
            p, port = start(k)
            time.sleep(1.0)
            if "cache" in k:
                load(port, "2")  # warm the cache with every name
            proc = psutil.Process(p.pid)
            c0 = proc.cpu_times()
            qps, line = load(port)
            c1 = proc.cpu_times()
            # CPU time the server used per 100,000 answers (user + system, all threads).
            cpu = (c1.user + c1.system - c0.user - c0.system) / (qps * float(secs)) * 100_000
            p.kill()
            p.wait()
            results.setdefault(k, []).append(qps)
            cpus.setdefault(k, []).append(cpu)
            print(f"round {r + 1} {k:14} {line}; server CPU {cpu:.2f} s per 100k answers", flush=True)
finally:
    auth.kill()

print()
for k, v in results.items():
    print(f"{k:14} median {statistics.median(v):,.0f} answers/s, {statistics.median(cpus[k]):.2f} CPU s per 100k  (runs: {', '.join(f'{x:,.0f}' for x in v)})")
