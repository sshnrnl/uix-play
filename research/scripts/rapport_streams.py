import sys, collections
from scapy.all import rdpcap, IPv6, IP, TCP, Raw

pkts = rdpcap(sys.argv[1])
# group TCP segments by stream (unordered 4-tuple), keep per-direction ordered by seq
streams = collections.defaultdict(lambda: {'dirs': collections.defaultdict(dict), 'first_ts': None})
for pk in pkts:
    ipl = pk[IPv6] if pk.haslayer(IPv6) else (pk[IP] if pk.haslayer(IP) else None)
    if ipl is None or not ipl.haslayer(TCP): continue
    t = ipl[TCP]
    if not t.haslayer(Raw): continue
    d = bytes(t[Raw].load)
    if not d: continue
    a = (ipl.src, t.sport); b = (ipl.dst, t.dport)
    key = tuple(sorted([a, b]))
    st = streams[key]
    if st['first_ts'] is None: st['first_ts'] = float(pk.time)
    st['dirs'][(a, b)][t.seq] = d

# order streams by first activity; show the earliest few (the control handshakes start first)
ordered = sorted(streams.items(), key=lambda x: x[1]['first_ts'])

def looks_tlv(d):
    # HAP TLV8: sequence of type(1) len(1) value(len). Walk and see if it consumes cleanly.
    i = 0; types = []
    while i + 2 <= len(d):
        t = d[i]; l = d[i+1];
        if i + 2 + l > len(d): return None
        types.append((t, l)); i += 2 + l
        if len(types) > 12: break
    return types if i == len(d) or len(types) >= 2 else None

shown = 0
for key, st in ordered:
    # skip big data streams (video/rtcp are UDP so already excluded); show small control streams
    total = sum(len(v) for dd in st['dirs'].values() for v in dd.values())
    if total > 20000: continue  # skip bulk
    print(f'\n===== stream {key[0]} <-> {key[1]}  (bytes={total})')
    for (a, b), segs in st['dirs'].items():
        payload = b''.join(segs[s] for s in sorted(segs))
        print(f'  --- {a} -> {b}: {len(payload)} bytes')
        head = payload[:96]
        print(f'      head: {head[:48].hex(" ")}')
        if len(head) > 48: print(f'            {head[48:96].hex(" ")}')
        tlv = looks_tlv(payload[:64])
        if tlv: print(f'      TLV8? types(len): {tlv[:8]}')
        # scan for a 32-byte stretch that could be a curve25519 key (heuristic: printable? no—just note offsets of 0x20-len TLV)
        for i in range(min(len(payload)-2, 60)):
            if payload[i+1] == 0x20 and payload[i] in (0x01,0x03,0x04,0x05):  # TLV type with len=32
                print(f'      possible 32B key at TLV off {i}: type={payload[i]:#04x} val={payload[i+2:i+34].hex()}')
                break
    shown += 1
    if shown >= 6: break
print(f'\n(total control-ish streams shown: {shown}; total streams: {len(streams)})')
