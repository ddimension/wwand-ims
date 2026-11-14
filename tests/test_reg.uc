// Host tests for ue/reg.uc: the whole REGISTER exchange against a stand-in
// P-CSCF that checks the Digest AKAv1-MD5 response with the RES of the
// Milenage test set, a stand-in USIM and a recording xfrm.
'use strict';

import { eq, ok, done } from './lib/check.uc';
import * as REG from 'ue_reg';
import * as AKA from 'ue_aka';

let SIP = require('sipd_sip');

// 3GPP TS 35.208 test set 1 (as in test_aka)
let RAND = hexdec('23553cbe9637a89d218ae64dae47bf35');
let RES  = hexdec('a54211d5e3ba50bf');
let CK   = hexdec('b40ba9a3c58b2a05bbf0d987b21bf8cb');
let IK   = hexdec('f769bcd751044604127672711c6d3441');
let AUTN = hexdec('55f328b43577b9b94a9ffac354dfafb3');
let AUTS = hexdec('00112233445566778899aabbccdd');

let UE = '2a02:3030:1:2::5', PC = '2a02:3030:ff::10';
let IMSI = '262021234567890', IMEI = '353456789012345';

// ---- helpers -----------------------------------------------------------------------

eq(REG.hostport('10.0.0.1', 5060), '10.0.0.1:5060', 'hostport v4');
eq(REG.hostport('2001:db8::1', 5064), '[2001:db8::1]:5064', 'hostport v6 in brackets');
eq(REG.imei_urn(IMEI), 'urn:gsma:imei:35345678-901234-0', 'imei_urn: TAC-SNR-spare 0');
eq(REG.imei_urn('123'), null, 'imei_urn: not an IMEI');
eq(REG.pani_eutran(262, 2, 2, 0x1a2b, 0x1234567), '3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=262021A2B1234567',
	'pani: MCC MNC TAC ECI');
eq(REG.pani_eutran(310, 150, 3, 1, 2, true), '3GPP-E-UTRAN-TDD; utran-cell-id-3gpp=31015000010000002',
	'pani: 3-digit MNC, TDD');

// ---- stand-ins ------------------------------------------------------------------

// timers run only when the test says so
function clock()
{
	let c = { now: 0, list: [] };
	c.timer = (ms, fn) => {
		let t = { at: c.now + ms, fn: fn, dead: false };
		push(c.list, t);
		return { cancel: () => { t.dead = true; } };
	};
	c.advance = (ms) => {
		c.now += ms;
		for (let again = true; again; ) {
			again = false;
			for (let t in c.list)
				if (!t.dead && t.at <= c.now) {
					t.dead = true;
					t.fn();
					again = true;
				}
		}
	};
	return c;
}

function card(mode)
{
	let c = { calls: 0 };
	c.open = (aid, cb) => cb(null, 1);
	c.close = (ch, cb) => cb(null);
	c.send = (ch, apdu, cb) => {
		c.calls++;
		if (mode == 'sync-once' && c.calls == 1)
			return cb(null, 'dc0e' + hexenc(AUTS) + '9000');
		cb(null, 'db08' + hexenc(RES) + '10' + hexenc(CK) + '10' + hexenc(IK) + '9000');
	};
	return c;
}

function xfrm()
{
	let x = { calls: [], next: 0x2000 };
	let rec = (op, ret) => (a) => { push(x.calls, [ op, a ]); return ret ? ret(a) : true; };
	x.alloc_spi = rec('alloc_spi', () => ++x.next);
	x.sa_add = rec('sa_add');
	x.sa_del = rec('sa_del');
	x.policy_add = rec('policy_add');
	x.policy_del = rec('policy_del');
	x.error = () => null;
	x.count = (op) => length(filter(x.calls, (c) => c[0] == op));
	return x;
}

// The P-CSCF: answers the unprotected REGISTER on 5060 with 401, the
// protected one on its port-s with 200 if the Digest response and
// Security-Verify are right. `opts.sync` expects an auts first.
function pcscf(opts)
{
	let p = { got: [], sent: [] };
	let server = 'ipsec-3gpp;q=0.1;alg=hmac-md5-96;ealg=null;spi-c=3001;spi-s=3002;port-c=6100;port-s=6101, ' +
		'ipsec-3gpp;q=0.5;alg=hmac-sha-1-96;ealg=null;spi-c=4001;spi-s=4002;port-c=7100;port-s=7101';
	let realm = 'ims.mnc002.mcc262.3gppnetwork.org';
	let nonce = b64enc(RAND + AUTN + 'srv');

	let reply = (req, status, reason, extra) => SIP.response(req, status, reason, { to_tag: 'pc1', headers: extra });

	p.handle = (buf, dst, port, src) => {
		let m = SIP.parse(buf);
		push(p.got, { msg: m, dst: dst, port: port, src: src });

		if (port == 5060) {
			let a = SIP.auth_parse(SIP.get(m, 'authorization'));
			if (opts?.sync && !p.synced) {
				if (a?.auts) {
					p.synced = true;
					p.auts = a.auts;
				}
			}
			return reply(m, 401, 'Unauthorized', [
				[ 'WWW-Authenticate', sprintf('Digest realm="%s", nonce="%s", algorithm=AKAv1-MD5, qop="auth"', realm, nonce) ],
				[ 'Security-Server', server ],
			]);
		}

		if (port == 7101) {
			let a = SIP.auth_parse(SIP.get(m, 'authorization'));
			p.auth = a;
			let ok_auth = SIP.auth_check(a, 'REGISTER', RES);
			let ok_verify = SIP.get(m, 'security-verify') == server;
			if (!ok_auth || !ok_verify)
				return reply(m, 403, sprintf('Forbidden auth=%J verify=%J', ok_auth, ok_verify));
			return reply(m, 200, 'OK', [
				[ 'Contact', replace(SIP.get(m, 'contact'), /expires=[0-9]+/, 'expires=3600') ],
				[ 'Service-Route', '<sip:orig@scscf.ims.example;lr>' ],
				[ 'P-Associated-URI', '<sip:+4916212345678@ims.example>, <tel:+4916212345678>' ],
				[ 'Path', '<sip:term@pcscf.ims.example;lr>' ],
			]);
		}
		return null;
	};
	return p;
}

function run(mode, opts)
{
	let c = clock(), x = xfrm(), P = pcscf(opts), result = null, error = null, finished = 0;
	let queue = [];
	let reg = REG.create({
		imsi: IMSI, mnc_len: 2, imei: IMEI,
		ue_addr: UE, pcscf_addr: PC, port_c: 5062, port_s: 5064,
		card: card(mode), xfrm: x, timer: c.timer, cnonce: 'cafe0001',
		pani: '3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=262021A2B1234567',
		send: (buf, dst, port, src) => {
			if (opts?.silent)
				return;
			let r = P.handle(buf, dst, port, src);
			if (r)
				push(queue, r);
		},
	});
	reg.start((e, r) => { error = e; result = r; finished++; });
	// deliver the P-CSCF's answers one by one, as a socket would
	let flush = () => {
		while (length(queue))
			reg.on_message(shift(queue));
	};
	flush();
	return { reg: reg, P: P, x: x, c: c, flush: flush, result: () => result, error: () => error, finished: () => finished };
}

// ---- the normal exchange ------------------------------------------------------------

let r = run('ok');
eq(r.error(), null, 'register: no error');
eq(r.reg.state, 'registered', 'register: registered');
eq(r.finished(), 1, 'register: callback once');
eq(r.result().expires, 3600, 'register: expiry from our Contact in the 200');
eq(r.result().service_route, [ '<sip:orig@scscf.ims.example;lr>' ], 'register: Service-Route kept');
eq(r.result().associated, [ 'sip:+4916212345678@ims.example', 'tel:+4916212345678' ], 'register: IMPUs');
eq(r.result().sec, { alg: 'hmac-sha-1-96', ealg: 'null' }, 'register: the higher-q offer chosen');

let first = r.P.got[0], second = r.P.got[1];
eq([ first.dst, first.port, first.src ], [ PC, 5060, 5062 ], 'first REGISTER: unprotected to 5060 from port-c');
eq([ second.port, second.src ], [ 7101, 5062 ], 'second REGISTER: port-c -> the P-CSCF port-s, inside the SA');
eq(first.msg.uri, 'sip:ims.mnc002.mcc262.3gppnetwork.org', 'REGISTER Request-URI is the home domain');
eq(SIP.get(first.msg, 'from'), sprintf('<sip:%s@ims.mnc002.mcc262.3gppnetwork.org>;tag=%s', IMSI, r.reg.from_tag),
	'From: the temporary IMPU');
ok(index(SIP.get(first.msg, 'via'), 'SIP/2.0/UDP [2a02:3030:1:2::5]:5064;branch=z9hG4bK') == 0,
	'Via: our address and the protected server port');
let contact = SIP.get(first.msg, 'contact');
ok(index(contact, '<sip:262021234567890@[2a02:3030:1:2::5]:5064>') == 0, 'Contact: protected server port');
ok(index(contact, '+sip.instance="<urn:gsma:imei:35345678-901234-0>"') > 0, 'Contact: sip.instance from the IMEI');
ok(index(contact, '+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"') > 0, 'Contact: MMTEL feature tag');
eq(SIP.get(first.msg, 'require'), 'sec-agree', 'Require: sec-agree');
eq(SIP.get(first.msg, 'proxy-require'), 'sec-agree', 'Proxy-Require: sec-agree');
let a1 = SIP.auth_parse(SIP.get(first.msg, 'authorization'));
eq([ a1.username, a1.realm, a1.nonce, a1.response ],
	[ IMSI + '@ims.mnc002.mcc262.3gppnetwork.org', 'ims.mnc002.mcc262.3gppnetwork.org', '', '' ],
	'first Authorization: the private identity, empty nonce/response');
let sc = SIP.get(first.msg, 'security-client');
ok(index(sc, 'spi-c=8193;spi-s=8194;port-c=5062;port-s=5064') > 0, 'Security-Client: the reserved SPIs and our ports');
eq(SIP.get(first.msg, 'security-verify'), null, 'first REGISTER: no Security-Verify');
eq(SIP.get(first.msg, 'p-access-network-info'), '3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=262021A2B1234567',
	'P-Access-Network-Info passed through');
eq(SIP.get(second.msg, 'call-id'), SIP.get(first.msg, 'call-id'), 'second REGISTER: same Call-ID');
eq(SIP.cseq(second.msg).seq, 2, 'second REGISTER: CSeq 2');
eq([ r.P.auth.qop, r.P.auth.nc, r.P.auth.cnonce, r.P.auth.algorithm ], [ 'auth', '00000001', 'cafe0001', 'AKAv1-MD5' ],
	'second Authorization: qop=auth, nc, cnonce, algorithm');
eq([ r.x.count('alloc_spi'), r.x.count('sa_add'), r.x.count('policy_add') ], [ 2, 4, 4 ],
	'xfrm: two SPIs reserved, four SAs, four policies');
let upd = filter(r.x.calls, (c) => c[0] == 'sa_add' && c[1].update);
eq(sort(map(upd, (c) => c[1].spi)), [ 8193, 8194 ], 'xfrm: the reserved inbound SPIs filled in by update');
let out = filter(r.x.calls, (c) => c[0] == 'sa_add' && c[1].src == UE);
eq(sort(map(out, (c) => c[1].spi)), [ 4001, 4002 ], 'xfrm: outbound SAs with the P-CSCF SPIs');
eq(out[0][1].auth.name, 'hmac(sha1)', 'xfrm: hmac-sha-1-96');

// de-REGISTER inside the SAs, then the SAs go
let derr = 'unset';
let sent_before = length(r.P.got);
eq(r.reg.on_message(''), false, 'garbage ignored');
r.reg.deregister((e) => { derr = e; });
let dm = r.P.got[sent_before];
eq([ dm?.port, SIP.get(dm?.msg, 'expires') ], [ 7101, '0' ], 'deregister: protected REGISTER with Expires 0');
ok(index(SIP.get(dm?.msg, 'contact'), 'expires=0') > 0, 'deregister: Contact expires=0');
eq(SIP.auth_parse(SIP.get(dm?.msg, 'authorization')).nc, '00000002', 'deregister: nc counts on');
r.flush();
eq(derr, null, 'deregister: 200 from the P-CSCF');
eq(r.reg.state, 'idle', 'deregister: idle afterwards');

eq(r.reg.state, 'idle', 'close: idle');

// ---- sync failure: AUTS, then the normal exchange ------------------------------------

r = run('sync-once', { sync: true });
eq(r.error(), null, 'sync: registered after the resync');
eq(length(r.P.got), 3, 'sync: three REGISTERs (initial, auts, protected)');
eq(r.P.auts, b64enc(AUTS), 'sync: the AUTS reached the P-CSCF');
eq(r.P.got[1].port, 5060, 'sync: the auts REGISTER is unprotected');

// ---- timeout: nobody answers --------------------------------------------------------

r = run('ok', { silent: true });
eq(r.reg.state, 'unprotected', 'timeout: waiting');
r.c.advance(64 * 500);
eq(r.error()?.error, 'timeout', 'timeout: given up after 64*T1');
eq(r.x.count('sa_del'), 2, 'timeout: the reserved SPIs released');

// ---- a response that is not ours is ignored ----------------------------------------

r = run('ok', { silent: true });
eq(r.reg.on_message('SIP/2.0 200 OK\r\nCSeq: 1 REGISTER\r\nCall-ID: other\r\nContent-Length: 0\r\n\r\n'), false,
	'foreign Call-ID ignored');
eq(r.reg.state, 'unprotected', 'still waiting');

done();
