import sys, collections
from scapy.all import rdpcap, IPv6, IP, TCP, UDP, Raw

pkts = rdpcap(sys.argv[1])
print('total frames:', len(pkts))
linktypes = collections.Counter()
proto = collections.Counter()
tcp_class = collections.Counter()
tcp_sample = {}
udp_flows = collections.Counter()

def cls(p):
    if len(p) >= 2 and p[0] == 0x16 and p[1] == 0x03: return 'TLS-handshake(0x16 03)'
    if len(p) >= 2 and p[0] == 0x17 and p[1] == 0x03: return 'TLS-appdata(0x17 03)'
    if len(p) >= 2 and p[0] in (0x14, 0x15) and p[1] == 0x03: return 'TLS-ccs/alert'
    return f'other(first={p[0]:#04x})'

for pk in pkts:
    L = pk
    ipl = None
    if L.haslayer(IPv6): ipl = L[IPv6]
    elif L.haslayer(IP): ipl = L[IP]
    if ipl is None:
        proto['non-ip'] += 1; continue
    if ipl.haslayer(TCP):
        t = ipl[TCP]
        proto['tcp'] += 1
        if t.haslayer(Raw):
            d = bytes(t[Raw].load)
            c = cls(d)
            tcp_class[c] += 1
            tcp_sample.setdefault(c, d[:40].hex(' '))
    elif ipl.haslayer(UDP):
        u = ipl[UDP]
        proto['udp'] += 1
        udp_flows[(u.sport, u.dport)] += 1

print('proto:', dict(proto))
print('\nTCP payload classes:')
for c, n in tcp_class.most_common():
    print(f'  {n:5}  {c}')
    print(f'         e.g. {tcp_sample[c]}')
print('\nUDP flows (sport->dport) top:')
for f, n in udp_flows.most_common(8):
    print(f'  {n:5}  {f[0]} -> {f[1]}')
