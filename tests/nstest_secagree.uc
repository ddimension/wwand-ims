// ue/secagree.uc against the real kernel, through wwand_io.xfrm,
// in a user + network namespace of its own (run.sh starts it under
// `unshare -rn`). Two netns-local addresses on lo stand in for UE and
// P-CSCF; the SAs and policies are read back with `ip -j xfrm` (the test may
// use the CLI, the code under test does not).
'use strict';

import { eq, ok, done } from './lib/check.uc';
import * as SA from 'ue_secagree';
import { xfrm } from 'wwand_io';	// NETLINK_XFRM binding, now in wwand_io.so
import * as fs from 'fs';

let CK = hexdec('b40ba9a3c58b2a05bbf0d987b21bf8cb');
let IK = hexdec('f769bcd751044604127672711c6d3441');

function sh(cmd)
{
	let p = fs.popen(cmd);
	let out = p.read('all');
	p.close();
	return out ?? '';
}

// `ip xfrm` has no JSON output for xfrm (iproute2 6.15), so the text is read:
// an SA starts with "src A dst B", its second line has "spi 0x.. reqid N mode M"
function states()
{
	let out = [], cur = null;
	for (let l in split(sh('ip xfrm state 2>/dev/null'), '\n')) {
		let m = match(l, /^src (\S+) dst (\S+)/);
		if (m) {
			cur = { src: m[1], dst: m[2] };
			push(out, cur);
			continue;
		}
		m = cur && match(l, /proto esp spi (0x[0-9a-f]+)( reqid ([0-9]+))?( mode ([a-z]+))?/);
		if (m) {
			cur.spi = +m[1];
			cur.reqid = m[3] != null ? +m[3] : null;
			cur.mode = m[5];
		}
	}
	return out;
}

// a policy is "src A/n dst B/n ..." followed by "\tdir D priority P"
function policies()
{
	let out = [];
	for (let m in match(sh('ip xfrm policy 2>/dev/null'), /\n?src \S+ dst \S+[^\n]*\n\s+dir (\S+)/g))
		push(out, { dir: m[1] });
	return out;
}

for (let fam in [ 'v6', 'v4' ]) {
	let U = fam == 'v6' ? '2001:db8::1' : '192.0.2.1';
	let P = fam == 'v6' ? '2001:db8::2' : '192.0.2.2';

	// reserve two inbound SPIs: larval SAs, P-CSCF -> UE
	let res = SA.reserve(xfrm, U, P);
	ok(res.spi_c && res.spi_s && res.spi_c != res.spi_s, fam + ': reserve gives two distinct SPIs');
	eq(length(states()), 2, fam + ': two larval SAs');

	let ue = { addr: U, port_c: 5062, port_s: 5064, spi_c: res.spi_c, spi_s: res.spi_s };
	let pc = { addr: P, port_c: 7000, port_s: 7001, spi_c: 0x5555, spi_s: 0x6666 };

	for (let combo in [ [ 'hmac-sha-1-96', 'null' ], [ 'hmac-md5-96', 'aes-cbc' ], [ 'hmac-sha-1-96', 'des-ede3-cbc' ] ]) {
		let tag = sprintf('%s %s/%s', fam, combo[0], combo[1]);
		let plan = SA.plan(ue, pc, combo[0], combo[1], CK, IK, 10);
		let err = SA.apply(xfrm, plan, [ res.spi_c, res.spi_s ]);

		eq(err, null, tag + ': apply');

		let st = states();
		eq(length(st), 4, tag + ': four SAs in the kernel');
		let by_spi = {};
		for (let s in st)
			by_spi[sprintf('%d', +s.spi)] = s;

		let out1 = by_spi[sprintf('%d', 0x6666)];
		eq([ out1?.src, out1?.dst, out1?.mode, out1?.reqid ], [ U, P, 'transport', 10 ],
			tag + ': UE client -> P-CSCF server SA');
		let in2 = by_spi[sprintf('%d', res.spi_s)];
		eq([ in2?.src, in2?.dst, in2?.reqid ], [ P, U, 11 ], tag + ': reserved inbound SA filled in');

		let pol = policies();
		eq(length(pol), 4, tag + ': four policies');
		eq(sort(map(pol, (q) => q.dir)), [ 'in', 'in', 'out', 'out' ], tag + ': two in, two out');

		SA.remove(xfrm, plan);
		eq([ length(states()), length(policies()) ], [ 0, 0 ], tag + ': remove leaves nothing');
	}

	// a set that collides with an existing SA is rolled back completely
	let plan = SA.plan(ue, pc, 'hmac-md5-96', 'null', CK, IK, 20);
	xfrm.sa_add({ src: P, dst: U, spi: res.spi_c, auth: { name: 'hmac(md5)', key: IK } });
	let err = SA.apply(xfrm, plan, []);
	ok(err?.error && index(err.error, 'exists') >= 0, fam + ': collision reported (' + err?.error + ')');
	eq(length(states()), 1, fam + ': rollback leaves only the pre-existing SA');
	xfrm.sa_del({ src: P, dst: U, spi: res.spi_c });
	eq(length(states()), 0, fam + ': clean');
}

// bad input is refused before the kernel
eq(xfrm.sa_add({ src: '2001:db8::1', dst: '192.0.2.2', spi: 4096, auth: { name: 'hmac(md5)', key: IK } }), null,
	'mixed families refused');
ok(index(xfrm.error(), 'mixed') >= 0, 'error names the problem');
eq(xfrm.sa_add({ src: '192.0.2.1', dst: '192.0.2.2', spi: 12, auth: { name: 'hmac(md5)', key: IK } }), null,
	'reserved SPI refused');
eq(xfrm.policy_add({ dir: 'up', sel: { src: '192.0.2.1', dst: '192.0.2.2' }, tmpl: {} }), null, 'bad dir refused');

done();
