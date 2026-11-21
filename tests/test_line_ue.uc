// Host tests for sipd/line_ue.uc as a whole, with stand-ins for ubus, the
// sockets and uloop: the operator profile reaches the registration, and a
// P-CSCF that does not answer is followed by the PDN's next one.
// All identifiers are made-up example values.
'use strict';

import { eq, ok, done } from './lib/check.uc';
import * as LINE from 'sipd_line_ue';

let SIP = require('sipd_sip');

let UE = '2001:db8::5', P1 = '2001:db8:ff::10', P2 = '2001:db8:ff::11';

function world(prof)
{
	let w = { now: 0, timers: [], socks: [], sent: [], logs: [], asked: [], traced: [] };
	w.socket = {
		AF_INET: 2, AF_INET6: 10, SOCK_DGRAM: 2, SOCK_STREAM: 1, SOL_SOCKET: 1, SO_BINDTODEVICE: 25,
		SO_REUSEADDR: 2, IPPROTO_IP: 0, IPPROTO_IPV6: 41, IP_FREEBIND: 15, IPV6_FREEBIND: 78,
		error: () => 'none',
		create: (fam, kind) => {
			let s = { kind: kind, closed: false };
			s.setopt = () => true;
			s.bind = (a) => { s.addr = a; return true; };
			s.listen = () => true;
			s.close = () => { s.closed = true; };
			s.send = (data, flags, dst) => { push(w.sent, { msg: SIP.parse(data), dst: dst, at: w.now }); return true; };
			s.recvmsg = () => null;
			push(w.socks, s);
			return s;
		},
	};
	w.uloop = {
		ULOOP_READ: 1,
		handle: (sk, fn) => ({ delete: () => null }),
		timer: (ms, fn) => {
			let t = { at: w.now + ms, fn: fn, dead: false };
			push(w.timers, t);
			return { cancel: () => { t.dead = true; } };
		},
	};
	w.advance = (ms) => {
		for (let end = w.now + ms; w.now < end; ) {
			w.now += 100;
			for (let t in w.timers)
				if (!t.dead && t.at <= w.now) {
					t.dead = true;
					t.fn();
				}
			w.timers = filter(w.timers, (t) => !t.dead);
		}
	};
	w.bus = { call: (obj, method, args) => {
		if (obj == 'wwand' && method == 'status')
			return { modems: { m0: { imsi: '262991234567890', imei: '353456789012345', iccid: '89499901234567890123' } },
			         contexts: { wwims: { apn: 'ims', ipv6: { pcscf: [ P1, P2 ] }, ipv4: { pcscf: [ '192.0.2.10' ] } } } };
		if (obj == 'network.interface.wwims')
			return { up: true, 'ipv6-address': [ { address: UE } ] };
		if (method == 'modem_cells')
			return { cells: { lte_intra: { plmn: '262/99', tac: 1, global_cell_id: 2, earfcn: 100 } } };
		return null;
	} };
	let n = 0x3000;
	w.xfrm = { alloc_spi: () => ++n, sa_add: () => true, sa_del: () => true,
	           policy_add: () => true, policy_del: () => true, error: () => null };
	w.line = LINE.create({ bus: w.bus, uloop: w.uloop, socket: w.socket, xfrm: w.xfrm, modem: 'm0',
		iface: 'wwims', vrf: 'ims', log: (l, m) => push(w.logs, m),
		trace: (dir, peer, text) => push(w.traced, [ dir, peer, text ]),
		profile_for: (sim) => { push(w.asked, sim); return prof; } });
	// the first transmission of each REGISTER (retransmissions have the same branch)
	w.registers = () => {
		let out = [], seen = {};
		for (let s in w.sent) {
			let b = SIP.get(s.msg, 'via');
			if (s.msg.method == 'REGISTER' && !seen[b]) {
				seen[b] = true;
				push(out, s);
			}
		}
		return out;
	};
	return w;
}

// ---- the profile in the registration ----------------------------------------------------

let w = world({ name: 'op_a', warn: [ 'something odd' ], t1: 1000, t2: 4000, expires: 3600,
	algs: [ 'hmac-sha-1-96' ], ealgs: [ 'null' ], user_agent: 'Example-UE/1.0', pcscf_port: 5070, tcp: false });
w.line.start();
eq(w.asked[0], { imsi: '262991234567890', iccid: '89499901234567890123' }, 'the profile is asked for the SIM in the modem');
let r0 = w.registers()[0];
eq([ r0.dst.address, r0.dst.port ], [ P1, 5070 ], 'REGISTER to the PDN\'s first P-CSCF, the profile\'s port');
eq([ SIP.get(r0.msg, 'expires'), SIP.get(r0.msg, 'user-agent') ], [ '3600', 'Example-UE/1.0' ],
	'the profile\'s expiry and User-Agent');
ok(index(SIP.get(r0.msg, 'security-client'), 'alg=hmac-sha-1-96;ealg=null') >= 0 &&
	index(SIP.get(r0.msg, 'security-client'), 'aes-cbc') < 0, 'the profile\'s sec-agree algorithms');
eq(length(filter(w.socks, (s) => s.kind == 1)), 0, 'sip_transport without tcp: no TCP listener');
eq([ w.line.status().state, w.line.status().profile, w.line.profile().t1 ], [ 'registering', 'op_a', 1000 ],
	'status and profile() name the profile');
ok(length(filter(w.logs, (l) => l == 'ue: operator profile op_a')) == 1 &&
	length(filter(w.logs, (l) => l == 'ue: profile op_a: something odd')) == 1, 'the profile and its warnings are logged');

// ---- SMS over IP ----------------------------------------------------------------------------

eq(LINE.smsc_from_csca([ '+CSCA: "+4917000000",145', 'OK' ]), '+4917000000', 'smsc_from_csca');
eq(LINE.smsc_from_csca([ 'ERROR' ]), null, 'smsc_from_csca: none');
let sms_err = null;
w.line.sms_send('+4915550000003', 'x', (e) => { sms_err = e; });
eq(sms_err?.error, 'smsip_off', 'sms_send: option smsip off');
let ws = world({});
ws.line = LINE.create({ bus: ws.bus, uloop: ws.uloop, socket: ws.socket, xfrm: ws.xfrm, modem: 'm0',
	iface: 'wwims', vrf: 'ims', smsip: true, profile_for: () => ({}) });
ws.line.start();
ws.line.sms_send('+4915550000003', 'x', (e) => { sms_err = e; });
eq(sms_err?.error, 'not_registered', 'sms_send: smsip on, not registered yet');
ok(index(SIP.get(ws.registers()[0].msg, 'contact'), '+g.3gpp.smsip') >= 0 && ws.line.status().smsip,
	'smsip on: the REGISTER\'s Contact has +g.3gpp.smsip, the status says so');
ok(index(SIP.get(w.registers()[0].msg, 'contact'), 'smsip') < 0 && !w.line.status().smsip, 'smsip off: neither');

// ---- P-CSCF failover ----------------------------------------------------------------------

// nobody answers: Timer F (64*T1 = 64 s), then the next P-CSCF after 5 s
w.advance(63000);
eq(length(w.registers()), 1, 'failover: not before Timer F');
w.advance(1000 + 5000);
let rs = w.registers();
eq([ length(rs), rs[1]?.dst?.address ], [ 2, P2 ], 'failover: the second P-CSCF after the first timed out');
ok(length(filter(w.socks, (s) => !s.closed)) == 2, 'failover: the failed attempt\'s sockets are closed');
// that one is silent too: back to the first, still soon (one quick round)
w.advance(64000 + 5000);
rs = w.registers();
eq([ length(rs), rs[2]?.dst?.address ], [ 3, P1 ], 'failover: round robin back to the first');
// after the round the normal retry time (30 s) applies
w.advance(64000 + 5000);
eq(length(w.registers()), 3, 'failover: after one round no quick retry');
w.advance(25000);
rs = w.registers();
eq([ length(rs), rs[3]?.dst?.address ], [ 4, P2 ], 'failover: the next one after the retry time');
eq(length(filter(w.logs, (l) => l == 'ue: operator profile op_a')), 1, 'the profile is announced once, not per attempt');

// one P-CSCF configured by hand: it stays, whatever the PDN lists
let f = world({});
f.line = LINE.create({ bus: f.bus, uloop: f.uloop, socket: f.socket, xfrm: f.xfrm, modem: 'm0',
	iface: 'wwims', vrf: 'ims', pcscf: '2001:db8:ff::99' });
f.line.start();
f.advance(32000 + 5000 + 100);
rs = f.registers();
eq([ length(rs), rs[0].dst.address, rs[1].dst.address, rs[0].dst.port ],
	[ 2, '2001:db8:ff::99', '2001:db8:ff::99', 5060 ], 'a fixed P-CSCF: no failover, the default port and T1');
eq(length(filter(f.socks, (s) => s.kind == 1)), 2, 'no profile: the TCP listener as before');

// access 'vowifi pdn': the tunnel first, the IMS PDN while it does not work
let VP = '2001:db8:ee::7', tunnel = null;
let fb = world({});
fb.line = LINE.create({ bus: fb.bus, uloop: fb.uloop, socket: fb.socket, xfrm: fb.xfrm, modem: 'm0',
	iface: 'wwims', vrf: 'ims', ways: [ 'vowifi', 'pdn' ], access: () => tunnel });
fb.line.start();
rs = fb.registers();
eq(length(rs), 0, 'fallback: right after the start the preferred way gets its grace time');
fb.line.stop();
fb = world({});
fb.line = LINE.create({ bus: fb.bus, uloop: fb.uloop, socket: fb.socket, xfrm: fb.xfrm, modem: 'm0', start_grace_s: 0,
	iface: 'wwims', vrf: 'ims', ways: [ 'vowifi', 'pdn' ], access: () => tunnel });
fb.line.start();
rs = fb.registers();
eq([ length(rs), rs[0]?.dst?.address ], [ 1, P1 ], 'fallback: the tunnel down (grace over) -> REGISTER over the IMS PDN');
let tb = world({});
tunnel = { v6: '2001:db8:ee::2', pcscf: [ VP ], bind: 'wwvowifi', pani: null };
tb.line = LINE.create({ bus: tb.bus, uloop: tb.uloop, socket: tb.socket, xfrm: tb.xfrm, modem: 'm0',
	iface: 'wwims', vrf: 'ims', ways: [ 'vowifi', 'pdn' ], access: () => tunnel });
tb.line.start();
rs = tb.registers();
eq([ length(rs), rs[0]?.dst?.address ], [ 1, VP ], 'fallback: the tunnel up -> REGISTER over VoWiFi, preferred');
let nb = world({});
nb.bus.call = (obj, method, args) => null;
nb.line = LINE.create({ bus: nb.bus, uloop: nb.uloop, socket: nb.socket, xfrm: nb.xfrm, modem: 'm0',
	iface: 'wwims', vrf: 'ims', ways: [ 'vowifi', 'pdn' ], access: () => null, start_grace_s: 0, log: (l, m) => push(nb.logs, m) });
nb.line.start();
ok(!length(nb.registers()) && length(filter(nb.logs, (l) => index(l, 'vowifi: ') >= 0 && index(l, 'pdn: ') >= 0)) > 0,
	'fallback: neither works -> no REGISTER, both reasons logged');
fb.line.stop(); tb.line.stop(); nb.line.stop();

// the tunnel up but its P-CSCF silent: after two failed REGISTERs VoWiFi is
// set aside and the IMS PDN taken, at once
let db = world({});
db.line = LINE.create({ bus: db.bus, uloop: db.uloop, socket: db.socket, xfrm: db.xfrm, modem: 'm0', start_grace_s: 0,
	iface: 'wwims', vrf: 'ims', ways: [ 'vowifi', 'pdn' ], access: () => tunnel, log: (l, m) => push(db.logs, m) });
db.line.start();
db.advance(32000 + 5000 + 32000 + 1000 + 500);
rs = db.registers();
eq(map(rs, (r) => r.dst.address), [ VP, VP, P1 ], 'demotion: two silent REGISTERs over VoWiFi, then the IMS PDN');
ok(length(filter(db.logs, (l) => index(l, 'keeps failing over vowifi') >= 0)) == 1, 'demotion: logged once');
db.line.stop();

// kick: down and the way comes up -> a REGISTER now, not at the retry time
let kt = null;
let kb = world({});
kb.line = LINE.create({ bus: kb.bus, uloop: kb.uloop, socket: kb.socket, xfrm: kb.xfrm, modem: 'm0',
	iface: 'wwims', vrf: 'ims', ways: [ 'vowifi' ], access: () => kt });
kb.line.start();
eq(length(kb.registers()), 0, 'kick: no tunnel, no REGISTER');
kt = tunnel;
kb.line.kick();
kb.advance(100);
eq(length(kb.registers()), 1, 'kick: the tunnel up -> REGISTER at once');
kb.line.stop();

// stop while down: nothing left running
w.line.stop();
let n = length(w.sent);
w.advance(200000);
eq([ length(w.sent), w.line.status().state ], [ n, 'stopped' ], 'stop: no further attempts');

done();
