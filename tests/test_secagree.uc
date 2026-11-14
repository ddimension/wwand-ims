// Host tests for ue/secagree.uc without a kernel: headers, the choice of the
// server's offer, the key derivation and the SA plan. The kernel side is in
// nstest_secagree.uc.
'use strict';

import { eq, ok, done } from './lib/check.uc';
import * as SA from 'ue_secagree';

let CK = hexdec('b40ba9a3c58b2a05bbf0d987b21bf8cb');
let IK = hexdec('f769bcd751044604127672711c6d3441');

// ---- Security-Client -------------------------------------------------------------

eq(SA.client_header(1111, 2222, 5062, 5064, [ 'hmac-sha-1-96' ], [ 'null' ]),
	'ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;prot=esp;spi-c=1111;spi-s=2222;port-c=5062;port-s=5064',
	'client_header: one combination');
let all = SA.parse(SA.client_header(1, 2, 3, 4));
eq(length(all), 6, 'client_header: 2 algs x 3 ealgs by default');
eq(map(all, (e) => e.alg + '/' + e.ealg)[0], 'hmac-sha-1-96/null', 'client_header: best first');
eq(SA.client_header(1, 2, 3, 4, [ 'hmac-sha-256' ], [ 'null' ]), '', 'client_header: unknown alg dropped');

// ---- Security-Server: parse and choose ---------------------------------------------

let server = 'ipsec-3gpp; q=0.1; alg=hmac-md5-96; ealg=null; spi-c=3333; spi-s=4444; port-c=6000; port-s=6001, ' +
	'ipsec-3gpp;q=0.5;alg=hmac-sha-1-96;ealg=aes-cbc;prot=esp;mod=trans;spi-c=5555;spi-s=6666;port-c=7000;port-s=7001, ' +
	'digest;q=0.9, ' +
	'ipsec-3gpp;q=0.9;alg=hmac-sha-1-96;ealg=blowfish;spi-c=1;spi-s=2;port-c=1;port-s=2';
let p = SA.parse(server);
eq(length(p), 4, 'parse: four entries');
eq([ p[0].alg, p[0].ealg, p[0].spi_c, p[0].port_s, p[0].q ], [ 'hmac-md5-96', 'null', 3333, 6001, 0.1 ],
	'parse: fields, spaces around ; tolerated');
eq(SA.parse('ipsec-3gpp;alg=hmac-md5-96;spi-c=1;spi-s=2;port-c=3;port-s=4')[0].ealg, 'null',
	'parse: absent ealg means null');

let best = SA.choose(p);
eq([ best.alg, best.ealg, best.spi_s, best.port_c ], [ 'hmac-sha-1-96', 'aes-cbc', 6666, 7000 ],
	'choose: highest q among what we support (digest and blowfish skipped)');
eq(SA.choose(p, null, [ 'null' ]).alg, 'hmac-md5-96', 'choose: limited to the ealgs we offered');
eq(SA.choose(SA.parse('ipsec-3gpp;alg=hmac-md5-96;mod=tun;spi-c=1;spi-s=2;port-c=3;port-s=4')), null,
	'choose: tunnel mode refused');
eq(SA.choose(SA.parse('ipsec-3gpp;alg=hmac-md5-96;spi-c=1;port-c=3;port-s=4')), null,
	'choose: an entry without spi-s refused');
eq(SA.verify_header(server), join(', ', map(p, (e) => e.raw)), 'verify_header: the server list as received');

// ---- keys (TS 33.203 Annex I) ----------------------------------------------------

eq(hexenc(SA.keys(CK, IK, 'hmac-sha-1-96', 'null').auth), hexenc(IK) + '00000000', 'keys: sha1 = IK || 0^32');
eq(SA.keys(CK, IK, 'hmac-sha-1-96', 'null').enc, null, 'keys: null cipher has no key');
eq(SA.keys(CK, IK, 'hmac-md5-96', 'aes-cbc'), { auth: IK, enc: CK }, 'keys: md5 = IK, aes = CK');
eq(hexenc(SA.keys(CK, IK, 'hmac-md5-96', 'des-ede3-cbc').enc),
	'b40ba9a3c58b2a05' + 'bbf0d987b21bf8cb' + 'b40ba9a3c58b2a05', 'keys: 3des = CK1 || CK2 || CK1');
eq(SA.keys(substr(CK, 1), IK, 'hmac-md5-96', 'null'), null, 'keys: short CK refused');

// ---- the SA plan (TS 33.203 7.1) -------------------------------------------------

let ue = { addr: '2001:db8::1', port_c: 5062, port_s: 5064, spi_c: 1111, spi_s: 2222 };
let pc = { ...best, addr: '2001:db8::2' };
let plan = SA.plan(ue, pc, 'hmac-sha-1-96', 'aes-cbc', CK, IK, 100);

eq(length(plan.sas), 4, 'plan: four SAs');
eq(map(plan.sas, (s) => [ s.dir, s.src, s.sel.sport, s.dst, s.sel.dport, s.spi ]), [
	[ 'out', '2001:db8::1', 5062, '2001:db8::2', 7001, 6666 ],   // UE client -> P-CSCF server, P-CSCF's spi-s
	[ 'in',  '2001:db8::2', 7000, '2001:db8::1', 5064, 2222 ],   // P-CSCF client -> UE server, our spi-s
	[ 'out', '2001:db8::1', 5064, '2001:db8::2', 7000, 5555 ],   // UE server -> P-CSCF client, P-CSCF's spi-c
	[ 'in',  '2001:db8::2', 7001, '2001:db8::1', 5062, 1111 ],   // P-CSCF server -> UE client, our spi-c
], 'plan: directions, ports and SPIs per TS 33.203 7.1');
eq(map(plan.sas, (s) => s.reqid), [ 100, 101, 102, 103 ], 'plan: one reqid per SA');
eq(plan.sas[0].auth, { name: 'hmac(sha1)', key: IK + '\x00\x00\x00\x00', trunc: 96 }, 'plan: auth');
eq(plan.sas[0].enc, { name: 'cbc(aes)', key: CK }, 'plan: enc');
eq(plan.sas[0].sel.proto, null, 'plan: no proto in the selector, UDP and TCP share the SA');
eq(map(plan.policies, (q) => [ q.dir, q.tmpl.reqid ]), [ [ 'out', 100 ], [ 'in', 101 ], [ 'out', 102 ], [ 'in', 103 ] ],
	'plan: one policy per SA, tied by reqid');
eq(SA.plan(ue, pc, 'hmac-sha-1-96', 'null', CK, IK, 1).sas[0].enc, null, 'plan: null cipher -> no enc');

let vrf = SA.plan(ue, pc, 'hmac-md5-96', 'null', CK, IK, 1, { dev: 'ims', if_id: 7 });
eq(map(vrf.sas, (s) => s.sel.dev), [ 'ims', null, 'ims', null ], 'plan: dev only on outbound selectors');
eq(vrf.policies[1].if_id, 7, 'plan: if_id on policies');

// ---- apply/remove against a recording xfrm -----------------------------------------

function fake_xfrm(fail_at)
{
	let n = 0;
	let x = { calls: [], err: null };
	let rec = (op) => (a) => {
		push(x.calls, [ op, a ]);
		if (fail_at && ++n == fail_at) { x.err = 'kernel: File exists'; return null; }
		return op == 'alloc_spi' ? 4096 + length(x.calls) : true;
	};
	x.sa_add = rec('sa_add'); x.sa_del = rec('sa_del');
	x.policy_add = rec('policy_add'); x.policy_del = rec('policy_del');
	x.alloc_spi = rec('alloc_spi');
	x.error = () => x.err;
	return x;
}

let x = fake_xfrm();
eq(SA.apply(x, plan, [ 2222 ]), null, 'apply: no error');
eq(map(x.calls, (c) => [ c[0], c[1].spi ?? c[1].dir, c[1].update ?? false ]), [
	[ 'sa_add', 6666, false ], [ 'sa_add', 2222, true ], [ 'sa_add', 5555, false ], [ 'sa_add', 1111, false ],
	[ 'policy_add', 'out', false ], [ 'policy_add', 'in', false ], [ 'policy_add', 'out', false ], [ 'policy_add', 'in', false ],
], 'apply: SAs, reserved inbound ones by update, then policies');
eq(x.calls[0][1].dir, null, 'apply: no dir key in an SA request');

x = fake_xfrm(6);   // the second policy fails
let r = SA.apply(x, plan, []);
eq(r, { error: 'kernel: File exists', step: 'policy in 2001:db8::2:7000 -> 2001:db8::1:5064' }, 'apply: error reported');
eq(map(slice(x.calls, 6), (c) => c[0]), [ 'policy_del', 'sa_del', 'sa_del', 'sa_del', 'sa_del' ],
	'apply: rollback removes what was added, policies first');

x = fake_xfrm();
eq(SA.reserve(x, '2001:db8::1', '2001:db8::2'), { spi_c: 4097, spi_s: 4098 }, 'reserve: two inbound SPIs');
eq(x.calls[0][1], { src: '2001:db8::2', dst: '2001:db8::1', min: 0x1000, max: 0x0fffffff }, 'reserve: P-CSCF -> UE');

done();
