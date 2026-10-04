"""Compares dnsr's reading of a zone file with dnspython's, record by record, in wire format.

    cargo build --release --examples
    python scripts/check_zone.py ZONEFILE ORIGIN

Needs dnspython. Prints the records that only one side has, and exits 1 if there are any.
"""
import collections
import subprocess
import sys

import dns.name
import dns.zone

path, origin = sys.argv[1], sys.argv[2]
exe = __file__.rsplit("scripts", 1)[0] + "target/release/examples/zonedump"
ours = subprocess.run([exe, path, origin], capture_output=True, text=True)
if ours.returncode != 0:
    print("dnsr failed:", ours.stderr)
    sys.exit(1)
print("dnsr:", ours.stderr.strip())
mine = collections.Counter(ours.stdout.split("\n")[:-1])

z = dns.zone.from_file(path, origin=origin, relativize=False, check_origin=True)
theirs = collections.Counter()
for name, node in z.nodes.items():
    for rds in node.rdatasets:
        for rd in rds:
            # Names inside the data are written uncompressed and as written (not lowercased).
            wire = rd.to_wire(None, None, None, False) if hasattr(rd, "to_wire") else b""
            theirs[f"{name.to_text().lower()}|{rds.rdtype}|{rds.ttl}|{wire.hex()}"] += 1

only_mine = mine - theirs
only_theirs = theirs - mine
print(f"records: dnsr {sum(mine.values())}, dnspython {sum(theirs.values())}, only dnsr {sum(only_mine.values())}, only dnspython {sum(only_theirs.values())}")
for k in list(only_mine)[:10]:
    print("  only dnsr:     ", k[:160])
for k in list(only_theirs)[:10]:
    print("  only dnspython:", k[:160])
sys.exit(1 if only_mine or only_theirs else 0)
