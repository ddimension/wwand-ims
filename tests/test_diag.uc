// Host tests for ctl/diag.uc: HDLC framing and an EFS read against a
// simulated modem on the DIAG port (subsystem 0x13 only, as some answer;
// the 0x3E probe is refused). Made-up file content.
'use strict';

import { eq, ok, done } from './lib/check.uc';

import * as D from 'ims_diag';

// CRC-16/X.25 check value of "123456789"
eq(sprintf('%04X', D.crc16('123456789')), '906E', 'crc16: the X.25 check value');
let f = D.frame(chr(0x4B, 0x13, 0x7E, 0x7D));
ok(index(substr(f, 0, length(f) - 1), chr(0x7E)) < 0 && ord(f, length(f) - 1) == 0x7E, 'frame: 7E/7D escaped, 7E at the end');
let df = D.deframe(f + substr(D.frame('xyz'), 0, 3));
eq([ df.packets, df.bad, length(df.rest) ], [ [ chr(0x4B, 0x13, 0x7E, 0x7D) ], 0, 3 ], 'deframe: one packet back, the half one kept');
let broken = D.frame('abcd');
broken = substr(broken, 0, 1) + 'X' + substr(broken, 2);
eq(D.deframe(broken).bad, 1, 'deframe: a bad CRC is dropped');

let le32 = (v) => chr(v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF);
let u32 = (s, o) => ord(s, o) | (ord(s, o + 1) << 8) | (ord(s, o + 2) << 16) | (ord(s, o + 3) << 24);

function modem(content)
{
	let m = { out: '', seen: [], inbuf: '', closed: false };
	let answer = (p) => {
		let ss = ord(p, 1), cmd = ord(p, 2) | (ord(p, 3) << 8);
		push(m.seen, sprintf('%02X/%d', ss, cmd));
		if (ord(p, 0) != 0x4B || ss != 0x13)
			return chr(0x13) + p;		// DIAG_BAD_CMD_F + the request
		let h = substr(p, 0, 4);
		if (cmd == 0)
			return h + substr(p, 4);
		if (cmd == 15)
			return h + le32(0) + le32(0o100444) + le32(length(content)) + le32(1) + le32(0) + le32(0) + le32(0);
		if (cmd == 2)
			return h + le32(7) + le32(0);
		if (cmd == 4) {
			let n = u32(p, 8), off = u32(p, 12);
			let d = substr(content, off, n);
			return h + le32(7) + le32(off) + le32(length(d)) + le32(0) + d;
		}
		if (cmd == 3)
			return h + le32(0);
		return chr(0x13) + p;
	};
	m.port = {
		write: (b) => {
			m.inbuf += b;
			let df = D.deframe(m.inbuf);
			m.inbuf = df.rest;
			for (let p in df.packets) {
				// an unsolicited log packet before each answer: not ours
				m.out += D.frame(chr(0x10, 0, 0, 0)) + D.frame(answer(p));
			}
			return true;
		},
		// as wwand_io on a raw tty: false when nothing is there
		read: () => { let d = m.out; m.out = ''; return length(d) ? d : false; },
		close: () => { m.closed = true; },
	};
	m.io = { open_tty: (path, baud) => (path == '/dev/ttyUSB0') ? m.port : null };
	return m;
}

let XML = '<?xml version="1.0" ?>\n<IWLAN_S2B_CONFIG>' + join('', map(split(sprintf('%2500s', ''), ''), () => ' ')) + '</IWLAN_S2B_CONFIG>\n';
let m = modem(XML);
let r = D.efs_read(m.io, '/dev/ttyUSB0', '/data/iwlan_s2b_config.xml');
eq([ r.error, length(r.data), r.data == XML ], [ null, length(XML), true ], 'efs_read: the whole file, over three READs');
ok(m.closed, 'efs_read: the port closed again');
eq(filter(m.seen, (x) => x != '3E/0'), [ '13/0', '13/15', '13/2', '13/4', '13/4', '13/4', '13/3' ],
	'efs_read: 0x3E refused, then HELLO, STAT, OPEN, READ x3, CLOSE on 0x13 — nothing else');
ok(!length(filter(m.seen, (x) => !match(x, /\/(0|2|3|4|15)$/))), 'efs_read: no other EFS command, no WRITE (5)');
eq(D.efs_read(m.io, '/dev/ttyUSB9', '/x').error, 'open', 'efs_read: a port that does not open');

done();
