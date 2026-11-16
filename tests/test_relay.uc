// Host tests for sipd/relay.uc with stand-in sockets, uloop and clock: the
// packets move 1:1 between the sides, and the watchdog reports a side whose
// media stopped.
'use strict';

import { eq, ok, done } from './lib/check.uc';
import * as RELAY from 'sipd_relay';

let LAN = '192.0.2.1', IMS = '2001:db8::5';
let PHONE = { address: '192.0.2.50', port: 30000 }, MGW = { address: '2001:db8:ff::20', port: 21000 };

function world()
{
	let w = { now: 0, timers: [], socks: [], logs: [] };
	w.socket = {
		AF_INET: 2, AF_INET6: 10, SOCK_DGRAM: 2, SOL_SOCKET: 1, SO_BINDTODEVICE: 25,
		IPPROTO_IP: 0, IPPROTO_IPV6: 41, IP_FREEBIND: 15, IPV6_FREEBIND: 78,
		create: (fam, kind) => {
			let s = { fam: fam, q: [], out: [], closed: false, opts: [] };
			s.setopt = (l, o, v) => { push(s.opts, [ l, o, v ]); return true; };
			s.bind = (a) => { s.addr = a; return true; };
			s.close = () => { s.closed = true; };
			s.send = (data, flags, dst) => { push(s.out, { data: data, dst: dst }); return true; };
			s.recvmsg = () => shift(s.q);
			push(w.socks, s);
			return s;
		},
	};
	w.uloop = {
		ULOOP_READ: 1,
		handle: (sk, fn) => { sk.fn = fn; return { delete: () => { sk.fn = null; } }; },
		timer: (ms, fn) => {
			let t = { at: w.now + ms, fn: fn, dead: false };
			push(w.timers, t);
			return { cancel: () => { t.dead = true; } };
		},
	};
	// time passes in steps of 100 ms, the timers due run at each
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
	// a packet arrives on a socket
	w.rx = (sk, from, data) => {
		push(sk.q, { data: data ?? 'rtp', address: from });
		sk.fn?.();
	};
	return w;
}

function call(w, opts)
{
	let r = RELAY.create({ socket: w.socket, uloop: w.uloop, lan_ip: LAN, ims_ip: () => IMS, vrf: 'ims',
		now: () => w.now, log: (l, m) => push(w.logs, m), ...(opts ?? {}) });
	let m = r.alloc();
	r.connect(m, { lan: PHONE, ims: MGW });
	return { r: r, m: m, dead: [] };
}

let phone_rtcp = { address: PHONE.address, port: PHONE.port + 1 };
let mgw_rtcp = { address: MGW.address, port: MGW.port + 1 };

// ---- packets ------------------------------------------------------------------------

let w = world();
let c = call(w);
eq([ c.m.lan_port, c.m.ims_port ], [ 40000, 40000 ], 'alloc: the first even port on each side');
eq(c.m.ims.rtp.opts[0], [ 1, 25, 'ims' ], 'the IMS leg is bound to the VRF');
w.rx(c.m.lan.rtp, PHONE, 'up1');
eq(c.m.ims.rtp.out, [ { data: 'up1', dst: MGW } ], 'LAN -> IMS, unchanged, to the SDP\'s far end');
w.rx(c.m.ims.rtp, MGW, 'down1');
eq(c.m.lan.rtp.out, [ { data: 'down1', dst: PHONE } ], 'IMS -> LAN');
w.rx(c.m.ims.rtcp, mgw_rtcp, 'rr');
eq(c.m.lan.rtcp.out, [ { data: 'rr', dst: phone_rtcp } ], 'RTCP on port + 1');
eq(c.r.stats(c.m), { up: 1, down: 2, ka: 0 }, 'counted');

// ---- the watchdog ---------------------------------------------------------------------

// both sides talk, then the IMS side stops
c.r.watch(c.m, (side, kind) => push(c.dead, [ side, kind, w.now ]));
for (let i = 0; i < 100; i++) {
	w.advance(1000);
	w.rx(c.m.lan.rtp, PHONE);
	w.rx(c.m.ims.rtp, MGW);
}
eq(c.dead, [], 'media on both sides for 100 s: nothing');
for (let i = 0; i < 29; i++) {
	w.advance(1000);
	w.rx(c.m.lan.rtp, PHONE);
}
eq(c.dead, [], 'the IMS side silent for 29 s: not yet');
w.advance(1000);
eq(c.dead, [ [ 'ims', 'rtp', 130000 ] ], 'the IMS side silent for 30 s: reported');
w.advance(120000);
eq(length(c.dead), 1, 'reported once');
ok(length(filter(w.logs, (l) => index(l, 'no RTP from the IMS side for 30 s') >= 0)) == 1, 'and logged');

// the LAN side never sends after the call is up: counted from the arming
w = world();
c = call(w);
w.advance(50000);
c.r.watch(c.m, (side, kind) => push(c.dead, [ side, kind, w.now ]));
for (let i = 0; i < 29; i++) {
	w.advance(1000);
	w.rx(c.m.ims.rtp, MGW);
}
eq(c.dead, [], 'armed 50 s after connect: the time before does not count');
w.advance(1000);
eq(c.dead, [ [ 'lan', 'rtp', 80000 ] ], 'the LAN side silent for 30 s after the arming');

// RTCP does not keep a side alive for the RTP limit, and has its own (off by default)
w = world();
c = call(w, { rtp_timeout: 10, rtcp_timeout: () => 5 });
c.r.watch(c.m, (side, kind) => push(c.dead, [ side, kind, w.now ]));
for (let i = 0; i < 4; i++) {
	w.advance(1000);
	for (let x in [ [ c.m.lan.rtp, PHONE ], [ c.m.ims.rtp, MGW ], [ c.m.lan.rtcp, phone_rtcp ], [ c.m.ims.rtcp, mgw_rtcp ] ])
		w.rx(x[0], x[1]);
}
for (let i = 0; i < 5; i++) {
	w.advance(1000);
	for (let x in [ [ c.m.lan.rtp, PHONE ], [ c.m.ims.rtp, MGW ], [ c.m.lan.rtcp, phone_rtcp ] ])
		w.rx(x[0], x[1]);
}
eq(c.dead, [ [ 'ims', 'rtcp', 9000 ] ], 'rtcp_timeout: the IMS side\'s RTCP stopped, its RTP did not help');

w = world();
c = call(w, { rtp_timeout: 10 });
c.r.watch(c.m, (side, kind) => push(c.dead, [ side, kind, w.now ]));
for (let i = 0; i < 10; i++) {
	w.advance(1000);
	w.rx(c.m.lan.rtp, PHONE);
	w.rx(c.m.ims.rtcp, mgw_rtcp);
}
eq(c.dead, [ [ 'ims', 'rtp', 10000 ] ], 'rtp_timeout: RTCP alone is not media');

// off, and stopped
w = world();
c = call(w, { rtp_timeout: 0 });
c.r.watch(c.m, (side, kind) => push(c.dead, [ side, kind ]));
w.advance(300000);
eq([ c.dead, length(w.timers) ], [ [], 0 ], 'rtp_timeout 0: no watchdog at all');

w = world();
c = call(w);
c.r.watch(c.m, (side, kind) => push(c.dead, [ side, kind ]));
w.advance(10000);
c.r.stop(c.m);
w.advance(60000);
eq(c.dead, [], 'a stopped call is not reported');
ok(c.m.lan.rtp.closed && c.m.ims.rtcp.closed, 'stop closes the sockets');

done();
