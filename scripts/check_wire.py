"""Makes random DNS messages with dnspython, has dnsr decode and re-encode each one, and checks
that dnspython reads dnsr's encoding back as the same message.

    cargo build --release --examples
    python scripts/check_wire.py [COUNT]

Names are drawn from a few labels in mixed case so that compression finds many shared suffixes.
"""
import random
import subprocess
import sys

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

count = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
rnd = random.Random(25)
EXE = __file__.rsplit("scripts", 1)[0] + "target/release/examples/wirecheck"
LABELS = ["www", "WWW", "mail", "a", "b-c", "x1", "example", "Example", "com", "net", "org", "test", "_tcp", "_sip", "*"]


def name():
    return ".".join(rnd.choice(LABELS) for _ in range(rnd.randint(0, 5))) + "."


def text_for(t):
    if t == "A":
        return ".".join(str(rnd.randint(0, 255)) for _ in range(4))
    if t == "AAAA":
        return ":".join(f"{rnd.randint(0, 65535):x}" for _ in range(8))
    if t in ("NS", "CNAME", "PTR"):
        return name()
    if t == "MX":
        return f"{rnd.randint(0, 65535)} {name()}"
    if t == "SOA":
        return f"{name()} {name()} " + " ".join(str(rnd.randint(0, 2**32 - 1)) for _ in range(5))
    if t == "TXT":
        return " ".join('"' + "".join(rnd.choice('ab c;"\\\x01\xff') for _ in range(rnd.randint(0, 40))).replace("\\", "\\\\").replace('"', '\\"') + '"' for _ in range(rnd.randint(1, 4)))
    if t == "SRV":
        return f"{rnd.randint(0, 9)} {rnd.randint(0, 9)} {rnd.randint(1, 65535)} {name()}"
    if t == "CAA":
        return f'{rnd.choice([0, 128])} {rnd.choice(["issue", "iodef", "tbs"])} "{rnd.choice(["ca.example", "", "x;y"])}"'
    if t == "DS":
        return f"{rnd.randint(0, 65535)} 8 2 " + "".join(rnd.choice("0123456789ABCDEF") for _ in range(64))
    if t == "DNSKEY":
        return f"257 3 8 " + "AwEAAa" + "".join(rnd.choice("ABCDEFGHabcdefgh0123456789+/") for _ in range(42)) + "=="
    if t == "NSEC":
        return f"{name()} " + " ".join(rnd.sample(["A", "NS", "SOA", "MX", "TXT", "AAAA", "RRSIG", "NSEC", "CAA", "TYPE1234"], rnd.randint(1, 5)))
    if t == "HINFO":
        return '"cpu" "os"'
    if t == "TYPE65280":
        n = rnd.randint(0, 20)
        return f"\\# {n} " + "".join(f"{rnd.randint(0, 255):02x}" for _ in range(n))
    raise ValueError(t)


TYPES = ["A", "AAAA", "NS", "CNAME", "PTR", "MX", "SOA", "TXT", "SRV", "CAA", "DS", "DNSKEY", "NSEC", "HINFO", "TYPE65280"]


def message():
    q = dns.message.make_query(name(), rnd.choice(TYPES[:-1]), use_edns=rnd.choice([None, 0]), want_dnssec=rnd.random() < 0.3)
    m = dns.message.make_response(q)
    m.id = rnd.randint(0, 65535)
    if rnd.random() < 0.3:
        m.flags |= dns.flags.AA
    if rnd.random() < 0.2:
        m.set_rcode(rnd.choice([dns.rcode.NXDOMAIN, dns.rcode.SERVFAIL, dns.rcode.REFUSED]))
    for section in (m.answer, m.authority, m.additional):
        for _ in range(rnd.randint(0, 4)):
            t = rnd.choice(TYPES)
            rr = dns.rrset.from_text(name(), rnd.randint(0, 2**31 - 1), "IN", t, *[text_for(t) for _ in range(rnd.randint(1, 3))])
            section.append(rr)
    return m


msgs, wires = [], []
while len(msgs) < count:
    m = message()
    try:
        wires.append(m.to_wire())
        msgs.append(m)
    except dns.exception.TooBig:
        pass  # dnspython will not encode it; make another
out = subprocess.run([EXE], input="\n".join(w.hex() for w in wires), capture_output=True, text=True).stdout.split("\n")
bad = errors = 0
smaller = 0
larger_without_srv = 0
for m, w, line in zip(msgs, wires, out):
    if line.startswith("ERR"):
        errors += 1
        if errors <= 5:
            print("dnsr refused a dnspython message:", line, w.hex()[:120])
        continue
    ours = bytes.fromhex(line)
    back = dns.message.from_wire(ours)
    # Compare with dnspython's own reading of its encoding (reading merges records of one name
    # and type that were added as separate sets).
    ref = dns.message.from_wire(w)
    if back != ref or back.rcode() != ref.rcode() or back.flags != ref.flags or back.edns != ref.edns or back.ednsflags != ref.ednsflags:
        bad += 1
        if bad <= 5:
            print("MISMATCH\n", m.to_text()[:600], "\n---\n", back.to_text()[:600])
    if len(ours) <= len(w):
        smaller += 1
    elif not any(rr.rdtype == dns.rdatatype.SRV for sec in (ref.answer, ref.authority, ref.additional) for rr in sec):
        # dnspython compresses SRV targets, which RFC 2782 says not to do; anything else is a surprise.
        larger_without_srv += 1
print(f"{count} messages: {errors} refused, {bad} different after a round trip; dnsr's encoding was the same size or smaller than dnspython's for {smaller}, larger for {count - smaller} (of those, {larger_without_srv} without an SRV record)")
sys.exit(1 if bad or errors else 0)
