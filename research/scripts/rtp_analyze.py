import struct, sys, math, collections
f = open(sys.argv[1], 'rb'); gh = f.read(24)
magic = struct.unpack('<I', gh[:4])[0]; end = '<' if magic in (0xa1b2c3d4, 0xa1b23c4d) else '>'
linktype = struct.unpack(end + 'I', gh[20:24])[0]
flows = collections.defaultdict(list)
while True:
    h = f.read(16)
    if len(h) < 16: break
    ts, tu, incl, orig = struct.unpack(end + 'IIII', h); d = f.read(incl)
    off = {1: 14, 0: 4, 12: 0, 101: 0}.get(linktype, 14)
    if linktype == 1:
        et = struct.unpack('>H', d[12:14])[0]
        if et != 0x86dd: continue
    ip = d[off:]
    if (ip[0] >> 4) != 6 or ip[6] != 17: continue
    src, dst = ip[8:24].hex(), ip[24:40].hex(); udp = ip[40:]
    sp, dp = struct.unpack('>HH', udp[:4]); pl = udp[8:]
    flows[(sp, dp)].append((ts + tu / 1e6, pl))
print('linktype', linktype)
def entropy(b):
    if not b: return 0
    c = collections.Counter(b); n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())
for (sp, dp), pk in sorted(flows.items(), key=lambda x: -len(x[1])):
    dur = pk[-1][0] - pk[0][0] or 1
    tot = sum(len(p) for _, p in pk)
    print(f'\n=== UDP {sp} -> {dp}: {len(pk)} pkts, {dur:.2f}s, {tot/dur/1024:.0f} KB/s')
    b0 = collections.Counter(p[0] for _, p in pk if p)
    print('  first byte:', ', '.join(f'0x{k:02x}x{v}' for k, v in b0.most_common(5)))
    rtp = [p for _, p in pk if len(p) >= 12 and (p[0] >> 6) == 2]
    print(f'  RTP v2 header candidates: {len(rtp)}/{len(pk)}')
    if rtp:
        pts = collections.Counter(p[1] & 0x7f for p in rtp); ssrc = collections.Counter(p[8:12].hex() for p in rtp)
        print('  payload types:', dict(pts.most_common(4)), ' SSRCs:', dict(ssrc.most_common(3)))
        seqs = [struct.unpack('>H', p[2:4])[0] for p in rtp[:12]]
        tss = [struct.unpack('>I', p[4:8])[0] for p in rtp[:12]]
        print('  seq:', seqs); print('  ts :', tss)
        ext = sum(1 for p in rtp if p[0] & 0x10); print(f'  with header extension: {ext}')
        bodies = []
        for p in rtp:
            cc = p[0] & 0x0f; o = 12 + 4 * cc
            if p[0] & 0x10 and len(p) > o + 4: o += 4 + 4 * struct.unpack('>H', p[o + 2:o + 4])[0]
            bodies.append(p[o:])
        big = b''.join(b for b in bodies if len(b) > 200)
        print(f'  payload entropy (bits/byte, 8=random): {entropy(big):.3f} over {len(big)} bytes')
        nal = collections.Counter(b[0] for b in bodies if b)
        print('  payload first byte (would be NAL header if clear):', ', '.join(f'0x{k:02x}x{v}' for k, v in nal.most_common(6)))
        print('  sample payload start:', bodies[0][:24].hex(' ') if bodies else '')
        print('  sample packet start :', pk[0][1][:32].hex(' '))
    else:
        print('  sample:', pk[0][1][:32].hex(' '))
        print(f'  entropy: {entropy(b"".join(p for _, p in pk)):.3f}')
