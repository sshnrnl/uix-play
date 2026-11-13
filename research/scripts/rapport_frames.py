import sys, collections
from scapy.all import rdpcap, IPv6, TCP, Raw

pkts = rdpcap(sys.argv[1])
streams = collections.defaultdict(lambda: collections.defaultdict(dict))
for pk in pkts:
    if not pk.haslayer(IPv6) or not pk.haslayer(TCP): continue
    ipl = pk[IPv6]; t = pk[TCP]
    if not t.haslayer(Raw): continue
    d = bytes(t[Raw].load)
    if not d: continue
    a=(ipl.src,t.sport); b=(ipl.dst,t.dport); key=tuple(sorted([a,b]))
    streams[key][(a,b)][t.seq]=d

def walk(payload, label):
    i=0; frames=[]
    while i+4 <= len(payload):
        typ=payload[i]; ln=(payload[i+1]<<16)|(payload[i+2]<<8)|payload[i+3]
        if i+4+ln > len(payload):
            frames.append(('TRUNC', typ, ln, len(payload)-i-4)); break
        frames.append((typ, ln)); i+=4+ln
    clean = (i==len(payload))
    print(f'  {label}: {len(payload)}B -> {len(frames)} frames, clean_end={clean}')
    print('     frames (type,len):', frames[:12])

for key, dirs in streams.items():
    if not (isinstance(key[0][0],str) and key[0][0].startswith('fe80')): continue
    tot=sum(len(v) for dd in dirs.values() for v in dd.values())
    if tot>60000: continue
    print(f'\n== {key[0]} <-> {key[1]}')
    for (a,b),segs in dirs.items():
        payload=b''.join(segs[s] for s in sorted(segs))
        walk(payload, f'{a[1]}->{b[1]}')
