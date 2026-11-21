// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// Read a file from a Qualcomm modem's EFS over its DIAG port — read-only,
// any Qualcomm modem (not only Quectel's AT+QNVFR). Used by `wwandctl ims
// setup` for the carrier config's /data/iwlan_s2b_config.xml.
//
// DIAG is HDLC-framed: the packet, its CRC-16/X.25 (init 0xFFFF, inverted,
// little-endian), 0x7D/0x7E escaped as 0x7D (byte ^ 0x20), a 0x7E at the
// end. EFS2 is DIAG subsystem 0x13 (or 0x3E, the "alternate EFS" a modem
// with several file systems answers on), commands in a subsystem packet
// 4B <subsys> <cmd u16 LE>:
//   HELLO 0, OPEN 2, CLOSE 3, READ 4, STAT 15 — and nothing that writes.
// The packet layouts follow Qualcomm's fs_diag (as bkerler/edl's qc_diag
// sends them). Note: edl 2026.08's efs_read() sends EFS2_DIAG_WRITE (5),
// not READ (4) — a write request with the read's arguments; this module
// has no WRITE at all.
//
//   import * as D from 'ims_diag';
//   let r = D.efs_read(io, '/dev/ttyUSB0', '/data/iwlan_s2b_config.xml');
//   r: { data } or { error, detail }
//
// `io` is wwand_io (open_tty: raw mode, non-blocking read). The DIAG port has
// one user at a time: a running QLog capture (wwand-qlog) owns it.
// An ES module (bytecode in the package): installed as
// /usr/share/wwand-ims/ims_diag.uc.

'use strict';

const EFS_HELLO = 0, EFS_OPEN = 2, EFS_CLOSE = 3, EFS_READ = 4, EFS_STAT = 15;
const MAX_READ = 1024;		// fs_diag's FS_DIAG_MAX_READ_REQ
const O_RDONLY = 0;

export function crc16(s)
{
	let crc = 0xFFFF;
	for (let i = 0; i < length(s); i++) {
		crc ^= ord(s, i);
		for (let b = 0; b < 8; b++)
			crc = (crc & 1) ? ((crc >> 1) ^ 0x8408) : (crc >> 1);
	}
	return (~crc) & 0xFFFF;
}

function escape(s)
{
	let out = '';
	for (let i = 0; i < length(s); i++) {
		let c = ord(s, i);
		out += (c == 0x7E || c == 0x7D) ? chr(0x7D, c ^ 0x20) : chr(c);
	}
	return out;
}

// one packet -> its HDLC frame
export function frame(pkt)
{
	let c = crc16(pkt);
	return escape(pkt + chr(c & 0xFF, c >> 8)) + chr(0x7E);
}

// the frames in a buffer: { packets: [ packet without CRC ], rest, bad }
export function deframe(buf)
{
	let packets = [], bad = 0, start = 0;
	for (let i = 0; i < length(buf); i++) {
		if (ord(buf, i) != 0x7E)
			continue;
		let raw = substr(buf, start, i - start), p = '';
		start = i + 1;
		for (let j = 0; j < length(raw); j++) {
			let c = ord(raw, j);
			if (c == 0x7D && j + 1 < length(raw))
				c = ord(raw, ++j) ^ 0x20;
			p += chr(c);
		}
		if (length(p) < 3)
			continue;
		let body = substr(p, 0, length(p) - 2);
		let got = ord(p, length(p) - 2) | (ord(p, length(p) - 1) << 8);
		if (crc16(body) != got) {
			bad++;
			continue;
		}
		push(packets, body);
	}
	return { packets: packets, rest: substr(buf, start), bad: bad };
}

function u32(s, o)
{
	return ord(s, o) | (ord(s, o + 1) << 8) | (ord(s, o + 2) << 16) | (ord(s, o + 3) << 24);
}

function le32(v)
{
	return chr(v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF);
}

function hdr(subsys, cmd)
{
	return chr(0x4B, subsys, cmd & 0xFF, cmd >> 8);
}

// the DIAG answers that refuse a command: bad command, parameters, length,
// security mode
const REFUSED = { '19': 'bad command', '20': 'bad parameters', '21': 'bad length', '71': 'bad security mode' };

// a session on an open port: request(pkt) -> answer packet or { error }
export function session(port, timeout_ms)
{
	let rest = '';
	return {
		request: (pkt) => {
			let want = substr(pkt, 0, 4);
			port.write(frame(pkt));
			let t = 0;
			while (t < (timeout_ms ?? 3000)) {
				// a raw tty (VMIN 0) reads 0 bytes when nothing is there, which
				// wwand_io returns as false: nothing yet, the timeout decides
				let d = port.read();
				if (d == null || d === false || d == '') {
					sleep(10);
					t += 10;
					continue;
				}
				let f = deframe(rest + d);
				rest = f.rest;
				for (let p in f.packets) {
					if (substr(p, 0, 4) == want)
						return p;
					// a refusal quotes the request after its code; log and event
					// packets (a mask someone else set), and a late answer to an
					// earlier request, are not ours
					if (REFUSED[sprintf('%d', ord(p, 0))] && substr(p, 1, 4) == want)
						return { error: 'refused', detail: REFUSED[sprintf('%d', ord(p, 0))] };
				}
			}
			return { error: 'timeout', detail: 'no answer on the DIAG port' };
		},
	};
}

// EFS2 answers: the error word after the 4-byte header (and the fd)
function efs_err(code)
{
	return code ? sprintf('EFS errno %d', code) : null;
}

// read one EFS file: { data } or { error, detail }
export function efs_read(io, path, file, opts)
{
	let port = io.open_tty(path, 115200);
	if (!port)
		return { error: 'open', detail: sprintf('cannot open %s', path) };
	let s = session(port, opts?.timeout_ms);
	let out = null;

	// the EFS subsystem this modem answers on
	let subsys = null;
	for (let ss in [ 0x3E, 0x13 ]) {
		// HELLO with all its 10 parameters zero (the probe edl uses)
		let r = s.request(hdr(ss, EFS_HELLO) + join('', map([ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ], () => le32(0))));
		if (type(r) == 'string') {
			subsys = ss;
			break;
		}
	}
	if (subsys == null) {
		port.close();
		return { error: 'no_efs', detail: 'the modem answers no EFS2 subsystem (0x3E, 0x13) on DIAG' };
	}

	let st = s.request(hdr(subsys, EFS_STAT) + file + chr(0));
	if (type(st) != 'string' || length(st) < 16) {
		port.close();
		return st?.error ? st : { error: 'stat', detail: 'short STAT answer' };
	}
	if (efs_err(u32(st, 4))) {
		port.close();
		return { error: 'stat', detail: sprintf('%s: %s', file, efs_err(u32(st, 4))) };
	}
	let size = u32(st, 12);

	let op = s.request(hdr(subsys, EFS_OPEN) + le32(O_RDONLY) + le32(0) + file + chr(0));
	if (type(op) != 'string' || length(op) < 12 || efs_err(u32(op, 8))) {
		port.close();
		return (type(op) == 'object') ? op : { error: 'open', detail: sprintf('%s: %s', file, efs_err(u32(op, 8)) ?? 'short OPEN answer') };
	}
	let fd = u32(op, 4);

	let data = '';
	for (let off = 0; off < size;) {
		let r = s.request(hdr(subsys, EFS_READ) + le32(fd) + le32(min(MAX_READ, size - off)) + le32(off));
		if (type(r) != 'string' || length(r) < 20) {
			out = (type(r) == 'object') ? r : { error: 'read', detail: 'short READ answer' };
			break;
		}
		if (efs_err(u32(r, 16))) {
			out = { error: 'read', detail: efs_err(u32(r, 16)) };
			break;
		}
		let n = u32(r, 12);
		if (n == 0)
			break;
		data += substr(r, 20, n);
		off += n;
	}
	s.request(hdr(subsys, EFS_CLOSE) + le32(fd));
	port.close();
	return out ?? { data: data };
}
