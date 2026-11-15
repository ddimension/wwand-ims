// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// The MCFG carrier configuration in a Qualcomm MBN file: read its items, set
// one, and pack it again. Used by `wwandctl ims mbn` (ctl/ims.uc); installed
// at /usr/share/ucode/wwand/ims_mcfg.uc. A plain script: no imports, the
// digests are handed in ({ sha256, sha384 }: hex digest of a string).
//
// The format (research/rg650e-245/NOTES.md, 2026-11-15; layout after
// sbaresearch/mbn-mcfg-tools FORMAT.md, checked against 41 MBNs of the
// RG650E and the OnePlus 8T, all of which this code rebuilds bit for bit):
//
//   ELF32, three program headers: 0 the ELF and program headers, 1 the hash
//   segment (hash table header, one digest per segment, the segment's own
//   slot zero, then signature and certificate chain), 2 the MCFG segment.
//
//   MCFG: "MCFG", u16 format, u16 config type, u32 item count (the trailer
//   included), u16 carrier index, u16 reserved, u16 version id, u16 version
//   size, version, items, trailer. An item: u32 length (all of it), u8 type,
//   u8 attributes, u16 reserved, data. A file item (type 2 NV file, 4 file):
//   u16 1, u16 path length (with its NUL), path, u16 2, u16 data length,
//   data. The trailer (type 0x0a) carries the name, MCC/MNC and ICCIDs; its
//   last 4 bytes are a placeholder for the end mark: the segment is padded
//   with 1-4 bytes to a multiple of 4, and its last u32 is the trailer
//   length plus that padding.
//
// What is changed here is the MCFG segment, its size in program header 2,
// and the digests of segments 0 and 2 in the hash table. The signature over
// the hash table is NOT renewed (no key): the RG650E A05 loads and applies
// such a file (HW, 2026-11-15); a modem that enforces MBN signatures would
// refuse it.

'use strict';

let struct = require('struct');

const ITEM_NV = 1, ITEM_NVFILE = 2, ITEM_FILE = 4, ITEM_TRAILER = 0x0a;

function u16(b, o) { return struct.unpack('<H', b, o)[0]; }
function u32(b, o) { return struct.unpack('<I', b, o)[0]; }

function hex2bin(h)
{
	let out = '';
	for (let i = 0; i + 1 < length(h); i += 2)
		out += chr(hex(substr(h, i, 2)));
	return out;
}

function bin2hex(s)
{
	return join('', map(split(s, ''), (c) => sprintf('%02x', ord(c))));
}

// replace a run of bytes of the same length at an offset
function splice(buf, off, repl)
{
	return substr(buf, 0, off) + repl + substr(buf, off + length(repl));
}

// one item's fields; a file item with its path and data
function item_of(raw)
{
	let it = { raw: raw, len: u32(raw, 0), type: ord(raw, 4), attr: ord(raw, 5) };
	if ((it.type == ITEM_NVFILE || it.type == ITEM_FILE) && length(raw) >= 12 && u16(raw, 8) == 1) {
		let pl = u16(raw, 10);
		it.path = trim(substr(raw, 12, pl), '\0');
		if (12 + pl + 4 <= length(raw) && u16(raw, 12 + pl) == 2) {
			let dl = u16(raw, 14 + pl);
			it.data = substr(raw, 16 + pl, dl);
		}
	}
	else if (it.type == ITEM_NV && length(raw) >= 12) {
		it.nv = u16(raw, 8);
		it.data = substr(raw, 12, u16(raw, 10));
	}
	return it;
}

// the trailer's fields: type u8, length u16, value
function trailer_fields(raw)
{
	let out = {};
	if (length(raw) < 20 || substr(raw, 12, 8) != 'MCFG_TRL')
		return out;
	let end = 12 + u16(raw, 10);
	for (let p = 20; p + 3 <= end;) {
		let t = ord(raw, p), l = u16(raw, p + 1);
		out[sprintf('%d', t)] = substr(raw, p + 3, l);
		p += 3 + l;
	}
	return out;
}

// parse an MBN file (a string of bytes). die() on anything not understood.
function parse(buf)
{
	if (substr(buf, 0, 4) != '\x7fELF' || ord(buf, 4) != 1)
		die('not an ELF32 file');
	let phoff = u32(buf, 0x1c), phnum = u16(buf, 0x2c), phsz = u16(buf, 0x2a);
	if (phnum != 3 || phsz != 32)
		die(sprintf('expected 3 program headers of 32 bytes, found %d of %d', phnum, phsz));
	let segs = [];
	for (let i = 0; i < 3; i++) {
		let o = phoff + 32 * i;
		push(segs, { ph: o, offset: u32(buf, o + 4), filesz: u32(buf, o + 16), flags: u32(buf, o + 24) });
	}
	let m = segs[2].offset;
	if (substr(buf, m, 4) != 'MCFG')
		die('segment 2 is not an MCFG segment');
	if (m + segs[2].filesz != length(buf))
		die('the MCFG segment is not the end of the file');
	let n = u32(buf, m + 8), vsz = u16(buf, m + 18);
	let p = m + 20 + vsz, items = [];
	for (let i = 0; i < n; i++) {
		let l = u32(buf, p);
		if (l < 8 || p + l > m + segs[2].filesz)
			die(sprintf('item %d: length %d runs past the segment', i, l));
		push(items, item_of(substr(buf, p, l)));
		p += l;
	}
	let tr = items[length(items) - 1];
	if (tr?.type != ITEM_TRAILER)
		die('the last item is not the MCFG trailer');
	let pad = m + segs[2].filesz - p;
	if (pad < 1 || pad > 4 || u32(buf, m + segs[2].filesz - 4) != tr.len + pad)
		die('the MCFG end mark does not match the trailer');
	pop(items);
	let tf = trailer_fields(tr.raw);
	return {
		buf: buf, segs: segs, header: substr(buf, m, 20 + vsz),
		items: items, trailer: tr.raw,
		name: tf['3'], version: (tf['1'] != null && length(tf['1']) == 4) ? u32(tf['1'], 0) : null,
	};
}

function find(p, path)
{
	for (let i = 0; i < length(p.items); i++)
		if (p.items[i].path == path)
			return i;
	return -1;
}

// a file item as the MBNs carry them
function file_item(path, data, typ, attr)
{
	let pb = path + '\0';
	let body = struct.pack('<HH', 1, length(pb)) + pb + struct.pack('<HH', 2, length(data)) + data;
	return item_of(struct.pack('<IBBH', 8 + length(body), typ ?? ITEM_NVFILE, attr ?? 0x19, 0) + body);
}

// set a file item: replaced in place where the path exists, else appended
// with the type and attributes of a sibling in the same directory
function set_item(p, path, data)
{
	let i = find(p, path);
	if (i >= 0) {
		let old = p.items[i];
		if (old.data == data)
			return 'unchanged';
		p.items[i] = file_item(path, data, old.type, old.attr);
		return 'replaced';
	}
	let dir = substr(path, 0, rindex(path, '/') + 1), sib = null;
	for (let it in p.items)
		if (it.path != null && substr(it.path, 0, length(dir)) == dir)
			sib = it;
	push(p.items, file_item(path, data, sib?.type, sib?.attr));
	return 'added';
}

// the segment digests in the hash table: the algorithm is the one whose
// digest of segment 0 is there
function hash_algo(p, dig)
{
	let h = p.segs[1];
	let table = substr(p.buf, h.offset, h.filesz);
	for (let a in [ 'sha384', 'sha256' ]) {
		if (!dig?.[a])
			continue;
		let d0 = hex2bin(dig[a](substr(p.buf, 0, p.segs[0].filesz)));
		if (index(table, d0) >= 0)
			return a;
	}
	return null;
}

// pack: a new file from the parsed one and its (changed) items
function build(p, dig)
{
	let a = hash_algo(p, dig);
	if (!a)
		die('no known digest of segment 0 in the hash segment (not a SHA-256/384 MBN?)');
	let buf = p.buf, segs = p.segs;
	let old0 = hex2bin(dig[a](substr(buf, 0, segs[0].filesz)));
	let old2 = hex2bin(dig[a](substr(buf, segs[2].offset, segs[2].filesz)));

	let hdr = splice(p.header, 8, struct.pack('<I', length(p.items) + 1));
	let mc = hdr + join('', map(p.items, (it) => it.raw)) +
		substr(p.trailer, 0, length(p.trailer) - 4) + '\0\0\0\0';
	let pad = 4 - length(mc) % 4;
	mc += substr('\0\0\0\0', 0, pad);
	mc = splice(mc, length(mc) - 4, struct.pack('<I', length(p.trailer) + pad));

	let out = substr(buf, 0, segs[2].offset) + mc;
	out = splice(out, segs[2].ph + 16, struct.pack('<II', length(mc), length(mc)));

	let new0 = hex2bin(dig[a](substr(out, 0, segs[0].filesz)));
	let new2 = hex2bin(dig[a](mc));
	let table = substr(out, segs[1].offset, segs[1].filesz);
	for (let pair in [ [ old0, new0 ], [ old2, new2 ] ]) {
		let i = index(table, pair[0]);
		if (i < 0 || index(substr(table, i + 1), pair[0]) >= 0)
			die('a segment digest is not exactly once in the hash table');
		table = splice(table, i, pair[1]);
	}
	return { buf: splice(out, segs[1].offset, table), algo: a };
}

// ---- LTE FGI: /nv/item_files/modem/lte/rrc/efs/lte_fgi_r8 -----------------------------
// What AT+QNWCFG="lte_fgi_fdd" writes on the RG650E, and what 20 Qualcomm
// carrier MBNs on the OnePlus 8T carry: a leading byte (0x07 in every MBN
// seen), then a little-endian u32 whose bit n-1 is FGI n (FGIs 1-32).

const FGI_R8 = '/nv/item_files/modem/lte/rrc/efs/lte_fgi_r8';

function fgi_word(list)
{
	let w = 0;
	for (let f in list ?? [])
		if (f >= 1 && f <= 32)
			w |= (1 << (f - 1));
	return w & 0xffffffff;
}

function fgi_list(w)
{
	let out = [];
	for (let i = 0; i < 32; i++)
		if ((w >> i) & 1)
			push(out, i + 1);
	return out;
}

// the item's FGIs, or null without one
function fgi_of(p)
{
	let i = find(p, FGI_R8);
	let d = (i >= 0) ? p.items[i].data : null;
	return (d != null && length(d) == 5) ? { prefix: ord(d, 0), list: fgi_list(u32(d, 1)) } : null;
}

// the prefix byte the MBN's own LTE RRC items use (0x07 where none)
function rrc_prefix(p)
{
	for (let it in p.items)
		if (index(it.path ?? '', '/nv/item_files/modem/lte/rrc/efs/') == 0 && length(it.data ?? '') > 1)
			return ord(it.data, 0);
	return 0x07;
}

function fgi_data(prefix, list)
{
	return chr(prefix) + struct.pack('<I', fgi_word(list));
}

return {
	parse: parse, find: find, set_item: set_item, build: build, file_item: file_item,
	trailer_fields: trailer_fields, bin2hex: bin2hex, hex2bin: hex2bin,
	FGI_R8: FGI_R8, fgi_word: fgi_word, fgi_list: fgi_list, fgi_of: fgi_of,
	rrc_prefix: rrc_prefix, fgi_data: fgi_data,
};
