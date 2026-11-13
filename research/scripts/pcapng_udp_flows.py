import sys, collections, math
from scapy.all import rdpcap, IPv6, IP, UDP, Raw

pkts = rdpcap(sys.argv[1])
flows = collections.defaultdict(list)
for pk in pkts:
    ipl = pk[IPv6] if pk.haslayer(IPv6) else (pk[IP] if pk.haslayer(IP) else None)
    if ipl is None or not ipl.haslayer(UDP): continue
    u = ipl[UDP]
    d = bytes(u[Raw].load) if u.haslayer(Raw) else b''
    src = ipl.src; dst = ipl.dst
    flows[(src, u.sport, dst, u.dport)].append(d)

def ent(b):
    if not b: return 0
    c = collections.Counter(b); n = len(b)
    return -sum(v/n*math.log2(v/n) for v in c.values())

print('top UDP flows by packet count:')
for key, ds in sorted(flows.items(), key=lambda x: -len(x[1]))[:8]:
    src, sp, dst, dp = key
    big = b''.join(d for d in ds if len(d) > 200)
    rtp = sum(1 for d in ds if len(d) >= 12 and (d[0] >> 6) == 2)
    sizes = collections.Counter(len(d) for d in ds)
    print(f'\n{src}.{sp} -> {dst}.{dp}')
    print(f'  packets={len(ds)}  rtp_v2_hdr={rtp}  entropy(>200B payloads)={ent(big):.3f}')
    print(f'  top sizes: {dict(sizes.most_common(5))}')
    nonempty = [d for d in ds if d]
    if nonempty:
        d0 = nonempty[0]
        print(f'  first payload: {d0[:24].hex(" ")}')
        if len(d0) >= 12 and (d0[0] >> 6) == 2:
            pt = d0[1] & 0x7f; ssrc = d0[8:12].hex()
            print(f'  RTP? ver=2 pt={pt} ssrc={ssrc}')
