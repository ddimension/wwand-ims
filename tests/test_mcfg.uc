// Host tests for ctl/mcfg.uc: an MBN built here with the layout of the
// RG650E's and the OnePlus 8T's (three segments, a hash table holding the
// digests of segments 0 and 2, MCFG items, the trailer and its end mark) is
// parsed, rebuilt unchanged byte for byte, and patched with lte_fgi_r8. The
// host ucode has no digest module: a stand-in "sha384" is enough for the
// structure; the real digests were checked on the router, where the patched
// file is the one the RG650E applied (ef86d496…, 2026-11-15).
'use strict';

import { eq, ok, done } from './lib/check.uc';

let struct = require('struct');
let M = require('ims_mcfg');

// 48 bytes that depend on the whole input
let fake = (s) => {
	let a = 0x12345, b = length(s);
	for (let i = 0; i < length(s); i++) {
		a = (a * 31 + ord(s, i)) & 0x7fffffff;
		b = (b ^ (a << 3)) & 0x7fffffff;
	}
	let h = '';
	for (let i = 0; i < 12; i++) {
		a = (a * 1103515245 + 12345 + b) & 0x7fffffff;
		h += sprintf('%08x', a);
	}
	return h;
};
let DIG = { sha384: fake };

let zeros = (n) => { let z = ''; for (let i = 0; i < n; i++) z += '\0'; return z; };
let item = (path, data) => M.file_item(path, data, 2, 0x19).raw;

// the trailer: header, "MCFG_TRL", fields (type u8, length u16), 4-byte placeholder
let trailer = (name) => {
	let f = chr(1) + struct.pack('<H', 4) + struct.pack('<I', 0x0a010449) +
	        chr(3) + struct.pack('<H', length(name)) + name;
	let content = 'MCFG_TRL' + f;
	let body = struct.pack('<I', 0x0a) + chr(0xa1) + chr(0) + struct.pack('<H', length(content)) + content;
	return struct.pack('<I', 4 + length(body) + 4) + body + '\0\0\0\0';
};

let mbn = (items, name) => {
	let tr = trailer(name);
	let mc = 'MCFG' + struct.pack('<HHIHHHH', 4, 1, length(items) + 1, 4, 0, 0x1383, 4) +
	         struct.pack('<I', 0x0a010449) + join('', items) + substr(tr, 0, length(tr) - 4) + '\0\0\0\0';
	let pad = 4 - length(mc) % 4;
	mc += substr('\0\0\0\0', 0, pad);
	mc = substr(mc, 0, length(mc) - 4) + struct.pack('<I', length(tr) + pad);
	// ELF32 header + three program headers = 0x94 bytes
	let eh = '\x7fELF' + chr(1) + chr(1) + chr(1) + '\0\0\0\0\0\0\0\0\0' +
	         struct.pack('<HHIIIIIHHHHHH', 2, 0, 1, 0, 0x34, 0, 0, 0x34, 32, 3, 40, 0, 0);
	let ph = (t, off, sz, fl) => struct.pack('<IIIIIIII', t, off, 0, 0, sz, sz, fl, 4);
	let hs_size = 0x100;
	let elf = eh + ph(0, 0, 0x94, 0x07000000) + ph(0, 0x1000, hs_size, 0x02000000) + ph(1, 0x2000, length(mc), 6);
	// hash segment: a header, then digests of segment 0, 1 (zero), 2
	let d0 = M.hex2bin(fake(elf)), d2 = M.hex2bin(fake(mc));
	let hs = struct.pack('<IIII', 0, 7, 0x18, 0) + d0 + zeros(48) + d2;
	hs += zeros(hs_size - length(hs));
	let gap1 = zeros(0x1000 - length(elf)), gap2 = zeros(0x1000 - hs_size);
	return elf + gap1 + hs + gap2 + mc;
};

let R10 = '/nv/item_files/modem/lte/rrc/efs/lte_fgi_r10';
let base = mbn([ item('/nv/item_files/modem/ims/ims_operator_mode', '\x07\x01'), item(R10, '\x07\x36\x3f\x00\x00') ],
               'Germany-VoLTE-Vodafone');

// ---- parse and rebuild --------------------------------------------------------------

let p = M.parse(base);
eq(length(p.items), 2, 'parse: two items, the trailer apart');
eq(p.name, 'Germany-VoLTE-Vodafone', 'parse: the name from the trailer');
eq(p.items[1].path, R10, 'parse: the file item path');
eq(M.bin2hex(p.items[1].data), '07363f0000', 'parse: the file item data');
eq(M.fgi_of(p), null, 'fgi_of: no lte_fgi_r8 in the base');
eq(M.rrc_prefix(p), 7, 'rrc_prefix: the 0x07 the LTE RRC items carry');

let rt = M.build(p, DIG);
ok(rt.buf == base, 'build: an unchanged MBN is rebuilt byte for byte');
eq(rt.algo, 'sha384', 'build: the digest found in the hash table');

// ---- the FGI word ------------------------------------------------------------------------

// the RG650E's list before the fix and the word AT+QNWCFG left in EFS
let before = [ 2, 4, 5, 6, 8, 9, 10, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 25, 30, 31 ];
eq(M.bin2hex(M.fgi_data(7, before)), '07baf37f61', 'fgi_data: the RG650E original = EFS baf37f61');
let after = sort([ ...before, 3, 7 ], (a, b) => a - b);
eq(M.bin2hex(M.fgi_data(7, after)), '07fef37f61', 'fgi_data: with 3 and 7 = EFS fef37f61 (HW 2026-11-14)');
eq(M.fgi_list(M.fgi_word(after)), after, 'fgi_list: the word back to the list');
// a Qualcomm carrier MBN (DT VoLTE Commercial on the 8T): 07 fff37f7d
let dt = M.fgi_list(struct.unpack('<I', M.hex2bin('fff37f7d'))[0]);
ok(index(dt, 3) >= 0 && index(dt, 7) >= 0, 'fgi_list: the carrier MBN has FGI 3 and 7');

// ---- patch -------------------------------------------------------------------------------

eq(M.set_item(p, M.FGI_R8, M.fgi_data(7, after)), 'added', 'set_item: lte_fgi_r8 added');
let it = p.items[2];
eq([ it.type, it.attr, it.len ], [ 2, 0x19, 65 ], 'set_item: type and attributes of its sibling, 65 bytes as in the 8T MBNs');
let out = M.build(p, DIG);
let q = M.parse(out.buf);
eq(length(q.items), 3, 'patched: three items');
eq(M.fgi_of(q)?.list, after, 'patched: the FGIs read back');
eq(q.name, 'Germany-VoLTE-Vodafone', 'patched: the trailer is kept');
eq(struct.unpack('<I', out.buf, 0x34 + 64 + 16)[0], length(out.buf) - 0x2000, 'patched: segment 2 size in its program header');
let hs = substr(out.buf, 0x1000, 0x100);
ok(index(hs, M.hex2bin(fake(substr(out.buf, 0, 0x94)))) >= 0, 'patched: the digest of segment 0 renewed');
ok(index(hs, M.hex2bin(fake(substr(out.buf, 0x2000)))) >= 0, 'patched: the digest of segment 2 renewed');
ok(index(hs, M.hex2bin(fake(substr(base, 0x2000)))) < 0, 'patched: the old digest of segment 2 is gone');

eq(M.set_item(q, M.FGI_R8, M.fgi_data(7, after)), 'unchanged', 'set_item: the same value again is no change');
eq(M.set_item(q, M.FGI_R8, M.fgi_data(7, before)), 'replaced', 'set_item: another value replaces the item');
eq(length(q.items), 3, 'set_item: replaced in place, not appended');

// a broken file
let bad = substr(out.buf, 0, length(out.buf) - 4) + struct.pack('<I', 9);
let e = null;
try { M.parse(bad); } catch (x) { e = x.message; }
ok(e != null && index(e, 'end mark') >= 0, 'parse: a wrong end mark is refused');

// ---- the ctl helpers -----------------------------------------------------------------------

let T = require('ctl_ims')._t;
eq(T.num_list('3,7'), [ 3, 7 ], 'num_list: 3,7');
eq(T.fgi_merge([ 2, 4, 102 ], [ 3, 7 ]), [ 2, 3, 4, 7 ], 'fgi_merge: union, FGIs 1-32 only');

done();
