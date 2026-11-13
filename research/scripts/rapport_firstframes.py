import sys, collections, math
from scapy.all import rdpcap, IPv6, TCP, Raw

pkts = rdpcap(sys.argv[1])
streams = collections.defaultdict(lambda: collections.defaultdict(dict))
syns = {}
for pk in pkts:
    if not pk.haslayer(IPv6) or not pk.haslayer(TCP): continue
    ipl=pk[IPv6]; t=pk[TCP]
    a=(ipl.src,t.sport); b=(ipl.dst,t.dport); key=tuple(sorted([a,b]))
    if t.flags & 0x02:  # SYN
        syns[key]=syns.get(key,0)+1
    if t.haslayer(Raw):
        d=bytes(t[Raw].load)
        if d: streams[key][(a,b)][t.seq]=d

def ent(b):
    if not b: return 0
    c=collections.Counter(b); n=len(b)
    return -sum(v/n*math.log2(v/n) for v in c.values())

def frames(payload):
    i=0; out=[]
    while i+4<=len(payload):
        typ=payload[i]; ln=(payload[i+1]<<16)|(payload[i+2]<<8)|payload[i+3]
        if i+4+ln>len(payload): break
        out.append((typ,ln,payload[i+4:i+4+ln])); i+=4+ln
    return out

for key, dirs in streams.items():
    if not (isinstance(key[0][0],str) and key[0][0].startswith('fe80')): continue
    tot=sum(len(v) for dd in dirs.values() for v in dd.values())
    if tot>60000: continue
    print(f'\n===== {key[0]} <-> {key[1]}  had_SYN={syns.get(key,0)>0}')
    for (a,b),segs in dirs.items():
        payload=b''.join(segs[s] for s in sorted(segs))
        fr=frames(payload)
        print(f'  --- {a[1]}->{b[1]}: {len(fr)} frames')
        for idx,(typ,ln,body) in enumerate(fr[:2]):
            print(f'    frame[{idx}] type={typ:#04x} len={ln} entropy={ent(body):.3f}')
            print(f'      {body[:64].hex(" ")}')
            # look for 32-byte-value TLV (HAP pubkey) or OPACK dict markers
            marks=[f'{body[j]:#04x}@{j}' for j in range(min(8,len(body)))]
            print(f'      first bytes: {marks}')
