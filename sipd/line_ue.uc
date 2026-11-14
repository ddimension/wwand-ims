// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// The router's own IMS UE as a "line" for sipd: it registers over the IMS
// PDN wwand carries (ue/reg.uc, sec-agree, the USIM through wwand), keeps
// the registration up, places calls and hands incoming ones to sipd.
//
//   let line = LINE.create({ bus, uloop, socket, xfrm, modem, iface, vrf,
//                            relay, log, on_incoming })
//   line.start()
//   line.dial(number, ev, { offer(qos, ver), ims_port }) -> ue/call.uc call, or null
//   line.status() -> { state, ue_addr, pcscf, impu, expires }
//   line.stop(cb)                         de-REGISTER, SAs and sockets down
//
// on_incoming(inc): inc = { call, media (relay.alloc()), number, called, set(ev) };
// sipd calls inc.set(ev) to receive the call's events (queued until then).
//
// What the network wants that is not in the RFCs (Vodafone DE, Nokia/ALU
// P-CSCF; research/rg650e-245/NOTES.md, 2026-11-14):
// - our responses to its requests go U:port_c -> P:port_s (its Via), and an
//   18x to a request that came over TCP also goes that way as a UDP copy,
//   or it is never acted on (no ringback, no PRACK, the mailbox);
// - an out-of-dialog OPTIONS pages the UE before every incoming INVITE;
// - the INVITE with its SDP comes over TCP (P:port_c -> U:port_s).
//
// Refresh: a new registration from scratch on the other protected port pair
// (new SAs, no clash with the old policies), the old one taken down after
// the new one stands. Never while a call runs. Any failure, and a new
// address or P-CSCF on the PDN, start over after `retry` seconds.

'use strict';

import * as REG from 'ue_reg';
import * as AKA from 'ue_aka';
import * as CALL from 'ue_call';

const PAIRS = [ [ 5062, 5064 ], [ 5072, 5074 ] ];

// an IPv6 address in AT dotted-decimal form (16 numbers) as text
function v6_dotted(s)
{
	let n = map(split(s ?? '', '.'), (x) => +x);
	if (length(n) != 16)
		return null;
	let g = [];
	for (let i = 0; i < 16; i += 2)
		push(g, sprintf('%x', n[i] * 256 + n[i + 1]));
	let a = join(':', g);
	// shorten the longest run of zero groups (RFC 5952), enough for logs and binds
	let best = null;
	for (let m in [ ':0:0:0:0:0:0:', ':0:0:0:0:0:', ':0:0:0:0:', ':0:0:0:', ':0:0:' ])
		if (index(':' + a + ':', m) >= 0) {
			best = m;
			break;
		}
	if (best) {
		a = replace(':' + a + ':', best, '::');
		a = replace(replace(a, /^:([^:])/, '$1'), /([^:]):$/, '$1');
	}
	return a;
}

// the fields of an AT response line, quotes respected
function at_fields(l)
{
	let out = [], cur = '', q = false;
	for (let i = 0; i < length(l); i++) {
		let ch = substr(l, i, 1);
		if (ch == '"')
			q = !q;
		else if (ch == ',' && !q) {
			push(out, trim(cur));
			cur = '';
		}
		else
			cur += ch;
	}
	push(out, trim(cur));
	return out;
}

// the P-CSCF addresses of the IMS PDN from AT+CGCONTRDP (QMI reports only an
// IPv4 list): +CGCONTRDP: cid,bearer,"apn","addr+mask","gw",dns1,dns2,"pcscf1","pcscf2"
export function pcscf_from_cgcontrdp(lines, apn)
{
	let out = [];
	for (let l in lines ?? []) {
		let m = match(l, /^\+CGCONTRDP: *(.*)$/);
		if (!m)
			continue;
		let f = at_fields(m[1]);
		if (apn && lc(f[2] ?? '') != lc(apn))
			continue;
		for (let i = 7; i < length(f); i++) {
			let a = index(f[i], ':') >= 0 ? f[i] : v6_dotted(f[i]);
			if (!a && match(f[i], /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/))
				a = f[i];
			if (a && index(out, a) < 0)
				push(out, a);
		}
	}
	return out;
}

// the user part (number) of a header's URI: tel:+49..., sip:+49...@...
function SIP_user(msg, name)
{
	let h = null;
	for (let x in msg.headers ?? [])
		if (x[0] == name) {
			h = x[1];
			break;
		}
	let m = match(h ?? '', /<?(tel|sips?):([^@;>]+)/);
	return m ? m[2] : null;
}

export function create(o)
{
	let bus = o.bus, uloop = o.uloop, socket = o.socket;
	let log = o.log ?? (() => null);
	let retry = (o.retry ?? 30) * 1000;
	let at = (cmd, t) => bus.call('wwand', 'modem_at', { modem: o.modem, command: cmd, timeout: t ?? 3000 });

	let self = { state: 'down' };
	let cur = null;           // the registration in use: { reg, res, pair, socks, tcp, env }
	let pair_ix = 0;
	let fails = 0;
	let calls = {};           // call_id -> call (ours, either direction)
	let timers = {};

	let set_timer = (name, ms, fn) => {
		timers[name]?.cancel();
		timers[name] = uloop.timer(ms, () => { timers[name] = null; fn(); });
	};

	let busy = () => length(filter(values(calls), (c) => c.state != 'ended')) > 0;

	// used by closures defined before them (ucode resolves names at compile time)
	let incoming = null, impu = null;

	// ---- what wwand, netifd and the modem know ------------------------------------

	let discover = () => {
		let st = bus.call('wwand', 'status', {});
		let m = st?.modems?.[o.modem];
		let ctx = st?.contexts?.[o.iface];
		if (!m?.imsi || !ctx)
			return { error: sprintf('modem %s / interface %s not ready in wwand', o.modem, o.iface) };

		let ifst = bus.call(sprintf('network.interface.%s', o.iface), 'status', {});
		if (!ifst?.up)
			return { error: sprintf('interface %s is down', o.iface) };
		let v6 = null;
		for (let a in ifst['ipv6-address'] ?? [])
			if (!match(a.address, /^fe80/))
				v6 = a.address;
		let v4 = ifst['ipv4-address']?.[0]?.address;

		let pcscf = o.pcscf ? [ o.pcscf ] : null;
		if (!pcscf) {
			let r = at('AT+CGCONTRDP');
			pcscf = pcscf_from_cgcontrdp(r?.response, o.apn ?? ctx.apn ?? 'ims');
			if (!length(pcscf))
				pcscf = ctx.ipv6?.pcscf ?? ctx.ipv4?.pcscf ?? [];
		}
		let six = filter(pcscf, (a) => index(a, ':') >= 0);
		let fam = (v6 && length(six)) ? 6 : 4;
		let ue = (fam == 6) ? v6 : v4;
		let p = (fam == 6) ? six[0] : filter(pcscf, (a) => index(a, ':') < 0)[0];
		if (!ue || !p)
			return { error: sprintf('no UE address or P-CSCF (ipv6 %s, ipv4 %s, P-CSCF %J)', v6 ?? '-', v4 ?? '-', pcscf) };

		let pani = null;
		let q = at('AT+QENG="servingcell"');
		let mm = match(q?.response?.[0] ?? '',
			/"LTE","(FDD|TDD)",([0-9]+),([0-9]+),([0-9A-Fa-f]+),[0-9]+,[0-9]+,[0-9]+,[0-9]+,[0-9]+,([0-9A-Fa-f]+),/);
		if (mm)
			pani = REG.pani_eutran(+mm[2], +mm[3], length(mm[3]) == 3 ? 3 : 2, hex(mm[5]), hex(mm[4]), mm[1] == 'TDD');

		return { imsi: m.imsi, imei: m.imei, mnc_len: o.mnc_len ?? m.registration?.plmn?.mnc_digits ?? 2,
		         fam: fam, ue_addr: ue, pcscf: p, pani: pani };
	};

	// ---- one registration's transport --------------------------------------------

	let callid_of = (buf) => {
		let mm = match(buf, /\r\n(Call-ID|i)[ \t]*:[ \t]*([^\r\n]+)/i);
		return mm ? trim(mm[2]) : null;
	};

	let open_transport = (env, pair) => {
		let AF = (env.fam == 6) ? socket.AF_INET6 : socket.AF_INET;
		let t = { socks: {}, tcp: null, handles: [], tcp_by_callid: {}, conns: [] };
		for (let port in pair) {
			let s = socket.create(AF, socket.SOCK_DGRAM);
			if (o.vrf && !s.setopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, o.vrf))
				return { error: sprintf('bind to VRF %s: %s', o.vrf, socket.error()) };
			s.setopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);
			if (!s.bind({ address: env.ue_addr, port: port }))
				return { error: sprintf('bind %s port %d: %s', env.ue_addr, port, socket.error()) };
			t.socks[sprintf('%d', port)] = s;
		}
		let l = socket.create(AF, socket.SOCK_STREAM);
		if (o.vrf)
			l.setopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, o.vrf);
		l.setopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);
		if (l.bind({ address: env.ue_addr, port: pair[1] }) && l.listen(4))
			t.tcp = l;
		else
			log('warn', sprintf('ue: no SIP over TCP on port %d: %s', pair[1], socket.error()));
		return t;
	};

	let close_transport = (t) => {
		for (let h in t?.handles ?? [])
			h.delete();
		for (let c in t?.conns ?? [])
			c.close();
		for (let k, s in t?.socks ?? {})
			s.close();
		t?.tcp?.close();
	};

	// one registration: transport, REG, the dispatch of what comes in
	let make_reg = (env, pair, cb) => {
		let t = open_transport(env, pair);
		if (t.error)
			return cb(t, null);
		let r = { env: env, pair: pair, t: t, reg: null, res: null };

		let send = (buf, dst, port, src) => {
			let conn = (substr(buf, 0, 8) == 'SIP/2.0 ') ? t.tcp_by_callid[callid_of(buf) ?? ''] : null;
			if (conn) {
				conn.send(buf);
				// the UDP copy of an 18x (see the top of the file)
				if (match(buf, /^SIP\/2\.0 1[0-9][0-9] /) && substr(buf, 8, 3) != '100' && r.res)
					t.socks[sprintf('%d', pair[0])].send(buf, 0, { address: r.res.pcscf.addr, port: r.res.pcscf.port_s });
				return;
			}
			let s = t.socks[sprintf('%d', src)];
			if (!s?.send(buf, 0, { address: dst, port: port }))
				log('warn', sprintf('ue: send to %s port %d failed: %s', dst, port, socket.error()));
		};
		r.send = send;

		let ubus_call = (obj, method, args, done) => {
			let x = bus.call(obj, method, args);
			if (x == null)
				return done(sprintf('ubus %s %s failed', obj, method), null);
			if (x.error)
				return done(x, null);
			done(null, x);
		};

		r.reg = REG.create({
			imsi: env.imsi, mnc_len: env.mnc_len, imei: env.imei,
			ue_addr: env.ue_addr, pcscf_addr: env.pcscf, port_c: pair[0], port_s: pair[1],
			pani: env.pani, card: AKA.wwand_card(ubus_call, o.modem, o.slot), xfrm: o.xfrm,
			smsip: false, sa_opts: o.vrf ? {} : null, reqid: 0x1500 + 0x10 * pair_ix,
			timer: (ms, fn) => uloop.timer(ms, fn),
			log: (lvl, msg) => log(lvl == 'notice' ? 'info' : lvl, 'ue: ' + msg),
			send: send,
		});

		let dispatch = (data) => {
			if (r.reg.on_message(data))
				return;
			let id = callid_of(data);
			let c = id ? calls[id] : null;
			if (c && c.on_message(data))
				return;
			if (!r.res)
				return;
			let opts = CALL.options_ok(data, { ue_addr: env.ue_addr, port_s: pair[1],
				contact_user: env.imsi, imei_urn: REG.imei_urn(env.imei) });
			if (opts)
				return send(opts, r.res.pcscf.addr, r.res.pcscf.port_s, pair[0]);
			let inv = CALL.initial_invite(data);
			if (inv)
				return incoming(r, inv);
			let nt = CALL.no_transaction(data);
			if (nt) {
				log('debug', 'ue: 481 for ' + split(data, '\r\n')[0]);
				return send(nt, r.res.pcscf.addr, r.res.pcscf.port_s, pair[0]);
			}
			log('debug', 'ue: a message that is not ours: ' + split(data, '\r\n')[0]);
		};

		for (let k, s in t.socks) {
			let sk = s;
			push(t.handles, uloop.handle(sk, () => {
				let b = sk.recvmsg(65535, null, 0);
				if (b)
					dispatch(b.data);
			}, uloop.ULOOP_READ));
		}

		// SIP over TCP: Content-Length framing; the responses to a request that
		// came over a connection go back on it (tcp_by_callid)
		let frame = (b) => {
			let he = index(b, '\r\n\r\n');
			if (he < 0)
				return null;
			let mm = match(substr(b, 0, he), /\r\n(Content-Length|l)[ \t]*:[ \t]*([0-9]+)/i);
			let total = he + 4 + (mm ? +mm[2] : 0);
			return (length(b) >= total) ? total : null;
		};
		if (t.tcp)
			push(t.handles, uloop.handle(t.tcp, () => {
				let c = t.tcp.accept();
				if (!c)
					return;
				push(t.conns, c);
				let rx = '', h;
				h = uloop.handle(c, () => {
					let d = c.recv(65535);
					if (d == null || d == '') {
						for (let id, v in t.tcp_by_callid)
							if (v === c)
								delete t.tcp_by_callid[id];
						h.delete();
						c.close();
						t.conns = filter(t.conns, (x) => x !== c);
						return;
					}
					rx += d;
					for (let n = frame(rx); n != null; n = frame(rx)) {
						let msg = substr(rx, 0, n);
						rx = substr(rx, n);
						let id = callid_of(msg);
						if (id && substr(msg, 0, 8) != 'SIP/2.0 ')
							t.tcp_by_callid[id] = c;
						dispatch(msg);
					}
				}, uloop.ULOOP_READ);
				push(t.handles, h);
			}, uloop.ULOOP_READ));

		r.reg.start((err, res) => {
			if (err) {
				r.reg.close();
				close_transport(t);
				return cb(err, null);
			}
			r.res = res;
			cb(null, r);
		});
	};

	let drop_reg = (r, dereg, cb) => {
		if (!r)
			return cb?.();
		let done = () => {
			close_transport(r.t);
			cb?.();
		};
		if (dereg && r.reg.state == 'registered')
			return r.reg.deregister(() => done());
		r.reg.close();
		done();
	};

	// ---- the registration's life ----------------------------------------------------

	let schedule_refresh, register;

	register = () => {
		if (self.state == 'stopped')
			return;
		let env = discover();
		if (env.error) {
			self.state = 'down';
			log('warn', sprintf('ue: %s; again in %d s', env.error, retry / 1000));
			return set_timer('reg', retry, register);
		}
		let ix = cur ? 1 - pair_ix : pair_ix;
		let pair = PAIRS[ix];
		self.state = cur ? 'refreshing' : 'registering';
		log('info', sprintf('ue: registering %s via P-CSCF %s, ports %d/%d', env.ue_addr, env.pcscf, pair[0], pair[1]));
		pair_ix = ix;
		make_reg(env, pair, (err, r) => {
			if (self.state == 'stopped')
				return drop_reg(r, true);
			if (err) {
				// the first retry comes soon: right after a de-REGISTER (a restart)
				// the network answers the next one with 403 "Wrong response" once
				// (HW 2026-11-14), and a PBX's calls get 503 meanwhile
				let wait = (fails++ == 0) ? 5000 : retry;
				log('warn', sprintf('ue: registration failed: %J; again in %d s', err, wait / 1000));
				// a refresh that failed: the old one may still stand
				self.state = cur ? 'registered' : 'down';
				if (cur && !busy())
					drop_reg(cur, false, () => { cur = null; self.state = 'down'; });
				return set_timer('reg', wait, register);
			}
			fails = 0;
			let old = cur;
			cur = r;
			self.state = 'registered';
			log('info', sprintf('ue: registered as %s, expires %s s', impu(), r.res.expires ?? '?'));
			for (let sa in r.reg.sa_set?.sas ?? [])
				log('debug', sprintf('ue: ESP-SA "%s","%s","%s","0x%08x","AES-CBC [RFC3602]","0x%s","HMAC-SHA-1-96 [RFC2404]","0x%s"',
					env.fam == 6 ? 'IPv6' : 'IPv4', sa.src, sa.dst, sa.spi, sa.enc ? hexenc(sa.enc.key) : '',
					hexenc(sa.auth.key)));
			// the old binding is replaced by the new one (same +sip.instance)
			if (old)
				drop_reg(old, false);
			schedule_refresh();
		});
	};

	impu = () => filter(cur?.res?.associated ?? [], (u) => match(u, /^sip:/))[0] ?? cur?.reg?.ids?.impu;

	schedule_refresh = () => {
		let exp = cur?.res?.expires ?? 3600;
		let at_s = (exp > 1200) ? exp - 600 : int(exp / 2);
		set_timer('reg', at_s * 1000, () => {
			if (busy()) {
				log('info', 'ue: refresh due, a call is running; again in 30 s');
				return set_timer('reg', 30000, () => schedule_refresh());
			}
			register();
		});
	};

	// a new address or P-CSCF on the PDN (re-attach), or the PDN gone: start over
	let watch;
	watch = () => {
		set_timer('watch', 20000, watch);
		if (!cur || self.state != 'registered' || busy())
			return;
		let env = discover();
		if (env.error || env.ue_addr != cur.env.ue_addr || env.pcscf != cur.env.pcscf) {
			log('warn', sprintf('ue: the IMS PDN changed (%s); registering again',
				env.error ?? sprintf('%s via %s', env.ue_addr, env.pcscf)));
			let old = cur;
			cur = null;
			drop_reg(old, false, () => register());
		}
	};

	// ---- calls ----------------------------------------------------------------------

	// our segment for preconditions: the QCI 1 bearer, in AT+CGEQOSRDP
	let qos_wait = (cb) => {
		let t0 = clock(true)[0], tick;
		tick = () => {
			let rr = at('AT+CGEQOSRDP', 2000);
			for (let l in rr?.response ?? [])
				if (match(l, /^\+CGEQOSRDP: *[0-9]+, *1(,|$)/))
					return cb();
			if (clock(true)[0] - t0 >= 10) {
				log('warn', 'ue: no QCI 1 bearer after 10 s; going on');
				return cb();
			}
			uloop.timer(200, tick);
		};
		tick();
	};

	let new_call = (rtp_port) => {
		let r = cur;
		let c = CALL.create({
			ue_addr: r.env.ue_addr, port_c: r.pair[0], port_s: r.pair[1],
			pcscf: r.res.pcscf, route: r.res.service_route, impu: impu(),
			contact_user: r.env.imsi, imei_urn: REG.imei_urn(r.env.imei), pani: r.env.pani,
			sec_verify: r.reg.server_raw, rtp_port: rtp_port,
			timer: (ms, fn) => uloop.timer(ms, fn),
			log: (lvl, msg) => log(lvl, 'ue: ' + msg),
			send: r.send, qos_wait: qos_wait,
		});
		calls[c.call_id] = c;
		return c;
	};

	// a finished call stays known for 64*T1, so the network's late CANCEL,
	// BYE or retransmission still finds it
	let forget = (c) => uloop.timer(64000, () => delete calls[c.call_id]);

	let caller_of = (msg) => {
		let pai = SIP_user(msg, 'p-asserted-identity') ?? SIP_user(msg, 'from');
		return pai;
	};

	incoming = (r, inv) => {
		if (r !== cur) {
			log('warn', 'ue: an INVITE on a registration being replaced');
		}
		let media = o.relay?.alloc();
		let c = new_call(media?.ims_port ?? 40000);
		let inc = { call: c, media: media, number: caller_of(inv),
		            called: SIP_user(inv, 'p-called-party-id') ?? SIP_user(inv, 'to'), handler: null, queue: [] };
		inc.set = (ev) => {
			inc.handler = ev;
			for (let x in inc.queue)
				ev(x[0], x[1]);
			inc.queue = [];
		};
		// incoming() takes the network's Call-ID: file the call under it
		let tmp_id = c.call_id;
		c.incoming(inv, (n, d) => {
			if (n == 'ended')
				forget(c);
			if (inc.handler)
				inc.handler(n, d);
			else
				push(inc.queue, [ n, d ]);
		});
		if (c.call_id != tmp_id) {
			delete calls[tmp_id];
			calls[c.call_id] = c;
		}
		if (c.state == 'ended') {
			o.relay?.stop(media);
			return;
		}
		if (!media) {
			c.reject(503, 'Service Unavailable');
			return;
		}
		o.on_incoming?.(inc);
	};

	// ---- public ------------------------------------------------------------------------

	self.start = function() {
		register();
		set_timer('watch', 20000, watch);
	};

	self.ready = () => self.state == 'registered' || self.state == 'refreshing';

	self.dial = function(number, ev, opts) {
		if (!cur?.res)
			return null;
		let c = new_call(opts?.ims_port ?? 40000);
		c.dial(number, (n, d) => {
			if (n == 'ended')
				forget(c);
			ev(n, d);
		}, { offer: opts?.offer });
		return c;
	};

	self.ue_addr = () => cur?.env?.ue_addr;

	self.status = () => ({
		state: self.state, ue_addr: cur?.env?.ue_addr, pcscf: cur?.env?.pcscf, impu: impu(),
		expires: cur?.res?.expires, ports: cur?.pair, calls: length(keys(calls)),
	});

	self.stop = function(cb) {
		self.state = 'stopped';
		for (let k, t in timers)
			t?.cancel();
		for (let id, c in calls)
			if (c.state != 'ended')
				c.hangup();
		let r = cur;
		cur = null;
		drop_reg(r, true, () => cb?.());
	};

	return self;
};
