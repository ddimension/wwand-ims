#!/usr/bin/env python3
"""rtp-amrwb2wav.py CAPTURE.pcap OUT.wav [--pt 97] [--port 40000] [--src ADDR]

Extract an AMR-WB RTP stream (RFC 4867, bandwidth-efficient mode, the
default when the SDP has no octet-align=1) from a pcap and write it as a
16 kHz WAV via the AMR-WB storage format (.awb) and ffmpeg.

Needs tshark and ffmpeg. RTP on an IMS call is not inside the IPsec SAs
(only SIP is), so a plain `tcpdump -i wwims -w x.pcap udp` has it.
Gaps (lost RTP, by sequence number) are filled with NO_DATA frames so the
timing stays right.
"""
import argparse
import os
import subprocess
import sys
import tempfile

# speech bits per frame type (TS 26.201 table 2); 9 = SID, 14/15 = none
FT_BITS = {0: 132, 1: 177, 2: 253, 3: 285, 4: 317, 5: 365, 6: 397,
           7: 461, 8: 477, 9: 40, 14: 0, 15: 0}


class Bits:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def left(self):
        return len(self.data) * 8 - self.pos

    def get(self, n):
        v = 0
        for _ in range(n):
            byte = self.data[self.pos >> 3]
            v = (v << 1) | ((byte >> (7 - (self.pos & 7))) & 1)
            self.pos += 1
        return v

    def take(self, n):
        """n bits as bytes, MSB first, zero-padded to a byte boundary"""
        out = bytearray((n + 7) // 8)
        for i in range(n):
            if self.get(1):
                out[i >> 3] |= 0x80 >> (i & 7)
        return bytes(out)


def frames_be(payload):
    """RFC 4867 4.3: CMR(4), TOC entries F(1) FT(4) Q(1), then speech bits"""
    b = Bits(payload)
    b.get(4)                                   # CMR
    toc = []
    while True:
        if b.left() < 6:
            return []
        f, ft, q = b.get(1), b.get(4), b.get(1)
        toc.append((ft, q))
        if not f:
            break
    out = []
    for ft, q in toc:
        n = FT_BITS.get(ft)
        if n is None or b.left() < n:
            return out
        out.append((ft, q, b.take(n)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('pcap')
    ap.add_argument('wav')
    ap.add_argument('--pt', type=int, default=97)
    ap.add_argument('--port', type=int, default=40000)
    ap.add_argument('--src', help='only packets from this IP')
    a = ap.parse_args()

    flt = 'rtp.p_type == %d' % a.pt
    if a.src:
        flt += ' && %s.src == %s' % ('ipv6' if ':' in a.src else 'ip', a.src)
    rows = subprocess.run(
        ['tshark', '-r', a.pcap, '-d', 'udp.port==%d,rtp' % a.port,
         '-Y', flt, '-T', 'fields', '-e', 'rtp.seq', '-e', 'rtp.payload'],
        check=True, capture_output=True, text=True).stdout.split('\n')

    awb = bytearray(b'#!AMR-WB\n')
    last, nframes, lost = None, 0, 0
    for row in rows:
        if '\t' not in row:
            continue
        seq, hexp = row.split('\t', 1)
        seq = int(seq)
        if last is not None:
            gap = (seq - last - 1) & 0xFFFF
            if 0 < gap < 1000:                 # lost packets -> NO_DATA
                awb += bytes([15 << 3]) * gap
                lost += gap
        last = seq
        for ft, q, speech in frames_be(bytes.fromhex(hexp.replace(':', ''))):
            awb += bytes([(ft << 3) | (q << 2)]) + speech
            nframes += 1

    if nframes == 0:
        sys.exit('no AMR-WB frames for pt %d on port %d' % (a.pt, a.port))
    with tempfile.NamedTemporaryFile(suffix='.awb', delete=False) as t:
        t.write(awb)
    try:
        subprocess.run(['ffmpeg', '-hide_banner', '-loglevel', 'error', '-y',
                        '-f', 'amr', '-i', t.name, '-ar', '16000', a.wav],
                       check=True)
    finally:
        os.unlink(t.name)
    print('%d frames (%.1f s), %d lost packets filled -> %s'
          % (nframes, nframes * 0.02, lost, a.wav))


if __name__ == '__main__':
    main()
