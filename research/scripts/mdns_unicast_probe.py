"""Ask one device directly (unicast to its port 5353) which DNS-SD services it exposes,
then resolve each instance (SRV/TXT/A). Unicast gets past routers that drop multicast.
usage: mdns_unicast_probe.py <device-ip> [extra service types...]"""
import socket, struct, sys, time

TARGET = sys.argv[1]
EXTRA = sys.argv[2:]

def qname(n):
    return b"".join(bytes([len(p)]) + p.encode() for p in n.rstrip(".").split(".")) + b"\0"

def query(names_types, qid):
    hdr = struct.pack("!HHHHHH", qid, 0, len(names_types), 0, 0, 0)
    return hdr + b"".join(qname(n) + struct.pack("!HH", t, 1) for n, t in names_types)

def read_name(buf, off):
    labels, jumped, end = [], False, None
    for _ in range(128):
        l = buf[off]
        if l == 0:
            off += 1; break
        if l & 0xC0 == 0xC0:
            if not jumped: end = off + 2
            off = ((l & 0x3F) << 8) | buf[off + 1]; jumped = True; continue
        labels.append(buf[off + 1:off + 1 + l].decode("utf-8", "replace")); off += 1 + l
    return ".".join(labels), (end if jumped else off)

def parse(buf):
    recs = []
    _, _, qd, an, ns, ar = struct.unpack("!HHHHHH", buf[:12]); off = 12
    for _ in range(qd):
        _, off = read_name(buf, off); off += 4
    for _ in range(an + ns + ar):
        name, off = read_name(buf, off)
        t, _, ttl, rdl = struct.unpack("!HHIH", buf[off:off + 10]); off += 10
        rd = buf[off:off + rdl]
        if t == 12: recs.append(("PTR", name, read_name(buf, off)[0]))
        elif t == 1: recs.append(("A", name, socket.inet_ntoa(rd)))
        elif t == 28: recs.append(("AAAA", name, socket.inet_ntop(socket.AF_INET6, rd)))
        elif t == 33:
            port = struct.unpack("!H", rd[4:6])[0]
            recs.append(("SRV", name, f"{read_name(buf, off + 6)[0]}:{port}"))
        elif t == 16:
            items, i = [], 0
            while i < len(rd):
                l = rd[i]; items.append(rd[i + 1:i + 1 + l].decode("utf-8", "replace")); i += 1 + l
            recs.append(("TXT", name, items))
        off += rdl
    return recs

def ask(sock, names_types, wait=1.5, tries=3):
    out = []
    for attempt in range(tries):
        sock.sendto(query(names_types, 0x1000 + attempt), (TARGET, 5353))
        end = time.time() + wait
        while time.time() < end:
            try:
                data, src = sock.recvfrom(9000)
            except socket.timeout:
                break
            if src[0] == TARGET:
                out += parse(data)
        if out:
            break
    return out

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 0))  # ephemeral source port => device answers by unicast (legacy query)
s.settimeout(0.5)

print(f"== service types exposed by {TARGET}")
types = sorted({r[2] for r in ask(s, [("_services._dns-sd._udp.local", 12)]) if r[0] == "PTR"})
for t in types: print("  ", t)
if not types: print("   (no answer to service enumeration)")

for t in sorted(set(types) | {f"{e}.local" if not e.endswith(".local") else e for e in EXTRA}
                | {"_companion-link._tcp.local", "_apple-mobdev2._tcp.local"}):
    recs = ask(s, [(t, 12)])
    inst = [r[2] for r in recs if r[0] == "PTR" and r[1] == t]
    print(f"\n== {t}: {len(inst)} instance(s)")
    for i in inst:
        det = ask(s, [(i, 33), (i, 16)])
        for kind, name, val in det:
            if name != i: continue
            if kind == "TXT":
                for item in val: print(f"     TXT {item}")
            else:
                print(f"     {kind} {val}")
