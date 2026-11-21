// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// The router's own IMS UE as a "line" for sipd: it registers over the IMS
// PDN wwand carries (ue/reg.uc, sec-agree, the USIM through wwand), keeps
// the registration up, places calls and hands incoming ones to sipd.
//
//   let line = LINE.create({ bus, uloop, socket, xfrm, modem, iface, vrf,
//                            relay, log, on_incoming, profile_for, trace })
//   (trace(dir, peer, text): every SIP message on the IMS side, optional)
//   line.start()
//   line.dial(number, ev, { offer(qos, ver), ims_port }) -> ue/call.uc call, or null
//   line.status() -> { state, ue_addr, pcscf, impu, expires, profile, reg_event }
//   line.profile() -> the operator profile's values in use (sipd/profile.uc ue_opts)
//   line.sms_send(number, text, cb)       an SMS over IMS (option smsip), cb(err, { parts, refs })
//   line.retry_now()                      register at once when down (the access came up)
//   line.stop(cb)                         de-REGISTER, SAs and sockets down
//
// SMS over IP (o.smsip, ue/smsip.uc): the registration carries
// +g.3gpp.smsip, an SMS that arrives goes to o.deliver(pdu_hex, cb(err))
// (sipd: wwand's modem_sms_deliver, into the modem's store), o.encode_submit
// builds the parts of one
// to send (wwand's sms_pdu). The SC: the profile's sms_smsc, else the one an
// SMS arrived from, else the SIM's (AT+CSCA?).
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
//
// profile_for({ imsi, iccid }) gives the operator profile's values for the
// SIM in the modem (asked at every registration: the SIM may have changed);
// they set the SIP timers, the expiry asked for, the sec-agree algorithms,
// the User-Agent and whether the UE listens on TCP and subscribes to reg.
//
// P-CSCF failover: the PDN names several P-CSCFs; a REGISTER that times out
// or meets a 5xx moves on to the next of the same address family.
//
// reg-event (ue/regevent.uc): each registration subscribes to its own
// state. "terminated" for our contact starts a new registration,
// "shortened" brings the refresh forward.

'use strict';

import * as REG from 'ue_reg';
import * as AKA from 'ue_aka';
import * as CALL from 'ue_call';
import * as SUB from 'ue_regevent';
import * as SMSIP from 'ue_smsip';

const PAIRS = [ [ 5062, 5064 ], [ 5072, 5074 ] ];

// a full eight-group IPv6 address ("2a01:8f0:400:955:0:0:0:5", as wwand's
// codec and the dotted form below give it) in its short form
function v6_short(a)
{
	if (length(split(a, ':')) != 8)
		return a;
	a = join(':', map(split(a, ':'), (x) => sprintf('%x', hex(x))));
	// shorten the longest run of zero groups (RFC 5952), enough for logs and binds
	let best = null;
	for (let m in [ ':0:0:0:0:0:0:', ':0:0:0:0:0:', ':0:0:0:0:', ':0:0:0:', ':0:0:' ])
		if (index(':' + a + ':', m) >= 0) {
			best = m;
			break;
		}
	if (best) {
		// the first run only (RFC 5952 4.2.3): two equal runs keep the second
		a = replace(':' + a + ':', best, '::', 1);
		a = replace(replace(a, /^:([^:])/, '$1'), /([^:]):$/, '$1');
	}
	return a;
}

// an IPv6 address in AT dotted-decimal form (16 numbers) as text
function v6_dotted(s)
{
	let n = map(split(s ?? '', '.'), (x) => +x);
	if (length(n) != 16)
		return null;
	let g = [];
	for (let i = 0; i < 16; i += 2)
		push(g, sprintf('%x', n[i] * 256 + n[i + 1]));
	return v6_short(join(':', g));
}

// the P-CSCF addresses of the IMS PDN as wwand reports them (status
// contexts.<iface>.ipv6/ipv4.pcscf: QMI WDS Get Current Settings, the IPv6
// list 0x2E and the IPv4 list 0x23), IPv6 first, short form, no duplicates
export function pcscf_from_status(ctx)
{
	let out = [];
	for (let l in [ ctx?.ipv6?.pcscf, ctx?.ipv4?.pcscf ])
		for (let a in (type(l) == 'array') ? l : [])
			if (type(a) == 'string') {
				let s = (index(a, ':') >= 0) ? v6_short(a) : a;
				if (index(out, s) < 0)
					push(out, s);
			}
	return out;
}

// P-Access-Network-Info from wwand's modem_cells (QMI NAS Get Cell Location
// Info): the serving LTE cell's PLMN, TAC and 28-bit cell identity. TDD from
// the EARFCN (bands 33 and up start at 36000, TS 36.101 5.7.3). null without one.
export function pani_of(cells)
{
	let l = cells?.cells?.lte_intra;
	let m = match(l?.plmn ?? '', /^([0-9]{3})\/([0-9]{2,3})$/);
	if (!m || l.tac == null || l.global_cell_id == null)
		return null;
	return REG.pani_eutran(+m[1], +m[2], length(m[2]), l.tac, l.global_cell_id, (l.earfcn ?? 0) >= 36000);
}

// MCCs whose networks use 3-digit MNCs (ITU-T E.212 assignments; the US and
// Canada, most of the Americas, India 405)
const MNC3_MCC = [ 302, 310, 311, 312, 313, 314, 315, 316, 334, 338, 342, 344, 346, 348, 354, 356,
	358, 360, 365, 366, 376, 405, 708, 722, 732 ];

// the MNC length of the card's HOME network, for the IMS domain from the
// IMSI (TS 23.003 13.2): the serving network's when not roaming and the IMSI
// begins with it, else by the IMSI's MCC. Config ims_modem.mnc_len wins.
export function home_mnc_len(m)
{
	let p = m?.registration?.plmn;
	let imsi = m?.imsi ?? '';
	if (p?.mnc_digits && !m.registration.roaming) {
		let mnc = sprintf('%d', p.mnc);
		while (length(mnc) < p.mnc_digits)
			mnc = '0' + mnc;
		if (substr(imsi, 0, 3 + p.mnc_digits) == sprintf('%03d', p.mcc) + mnc)
			return p.mnc_digits;
	}
	return (index(MNC3_MCC, +substr(imsi, 0, 3)) >= 0) ? 3 : 2;
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

// the P-CSCF addresses of the IMS PDN from AT+CGCONTRDP, for a wwand that does
// not report them (a core without the IPv6 list): +CGCONTRDP: cid,bearer,"apn","addr+mask","gw",dns1,dns2,"pcscf1","pcscf2"
export function pcscf_from_cgcontrdp(lines, apn)
{
	let out = [];
	for (let l in lines ?? []) {
		let m = match(l, /^\+CGCONTRDP: *(.*)$/);
		if (!m)
			continue;
		let f = at_fields(m[1]);
		// the APN as dialled, or with the operator suffix the modem may add
		// ("ims.mnc002.mcc262.gprs")
		let a_l = lc(f[2] ?? ''), want = lc(apn ?? '');
		if (apn && a_l != want && substr(a_l, 0, length(want) + 1) != want + '.')
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

// P-CSCF failover (TS 24.229 5.1.1.2, 5.1.1.4): a REGISTER nobody answered,
// or answered with a server error, is tried at another P-CSCF. A 4xx is the
// network's answer about us, not about that P-CSCF.
export function pcscf_failed(err)
{
	return err?.error == 'timeout' || (err?.error == 'status' && (err.status ?? 0) >= 500);
}

// the P-CSCF for attempt `ix` out of the PDN's list (round robin)
export function pcscf_pick(list, ix)
{
	return length(list) ? list[ix % length(list)] : null;
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

// the SC from `AT+CSCA?` (+CSCA: "+491234",145), or null
export function smsc_from_csca(lines)
{
	for (let l in lines ?? []) {
		let m = match(l, /^\+CSCA: *"(\+?[0-9]+)"/);
		if (m)
			return m[1];
	}
	return null;
}

export function create(o)
{
	let bus = o.bus, uloop = o.uloop, socket = o.socket;
	let log = o.log ?? (() => null);
	let retry = (o.retry ?? 30) * 1000;
	let at = (cmd, t) => bus.call('wwand', 'modem_at', { modem: o.modem, command: cmd, timeout: t ?? 3000 });

	let self = { state: 'down' };
	let cur = null;           // the registration in use: { reg, res, pair, socks, tcp, env }
	let attempt = null;       // the one being set up, until it stands or failed
	let pair_ix = 0;
	let pcscf_ix = 0;         // which of the PDN's P-CSCFs (moved on by a failure)
	let fails = 0;
	let prof = {}, prof_name = false;
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

	// the operator profile for the SIM in the modem; said once per change
	let profile_of = (m) => {
		let u = o.profile_for?.({ imsi: m.imsi, iccid: m.iccid }) ?? {};
		if ((u.name ?? null) !== prof_name) {
			prof_name = u.name ?? null;
			log('info', prof_name ? sprintf('ue: operator profile %s', prof_name)
				: 'ue: no operator profile for this SIM; built-in defaults');
			for (let w in u.warn ?? [])
				log('warn', sprintf('ue: profile %s: %s', prof_name, w));
		}
		prof = u;
		return u;
	};

	// light: only what the PDN watch compares (address, P-CSCF), no cell
	let discover = (light) => {
		let st = bus.call('wwand', 'status', {});
		let m = st?.modems?.[o.modem];
		let fixed = (type(o.pcscf) == 'array') ? o.pcscf : (o.pcscf ? [ o.pcscf ] : []);
		let v4, v6 = null, pcscf, acc = null;

		if (o.access) {
			// VoWiFi (vowifi/ctl.uc): the tunnel's inner addresses and the
			// P-CSCFs the ePDG named, in the tunnel's VRF; no IMS PDN
			if (!m?.imsi)
				return { error: sprintf('modem %s not ready in wwand', o.modem) };
			acc = o.access();
			if (!acc)
				return { error: 'the VoWiFi tunnel is not up' };
			v4 = acc.v4;
			v6 = acc.v6;
			pcscf = length(fixed) ? fixed : (acc.pcscf ?? []);
		}
		else {
			let ctx = st?.contexts?.[o.iface];
			if (!m?.imsi || !ctx)
				return { error: sprintf('modem %s / interface %s not ready in wwand', o.modem, o.iface) };

			let ifst = bus.call(sprintf('network.interface.%s', o.iface), 'status', {});
			if (!ifst?.up)
				return { error: sprintf('interface %s is down', o.iface) };
			for (let a in ifst['ipv6-address'] ?? [])
				if (!match(a.address, /^fe80/))
					v6 = a.address;
			v4 = ifst['ipv4-address']?.[0]?.address;

			// a fixed one from the config, else QMI through wwand, else AT
			pcscf = length(fixed) ? fixed : pcscf_from_status(ctx);
			if (!length(pcscf)) {
				let r = at('AT+CGCONTRDP');
				pcscf = pcscf_from_cgcontrdp(r?.response, o.apn ?? ctx.apn ?? 'ims');
			}
		}
		let six = filter(pcscf, (a) => index(a, ':') >= 0);
		let fam = (v6 && length(six)) ? 6 : 4;
		let ue = (fam == 6) ? v6 : v4;
		let cand = (fam == 6) ? six : filter(pcscf, (a) => index(a, ':') < 0);
		let p = pcscf_pick(cand, pcscf_ix);
		if (!ue || !p)
			return { error: sprintf('no UE address or P-CSCF (ipv6 %s, ipv4 %s, P-CSCF %J)', v6 ?? '-', v4 ?? '-', pcscf) };

		let pani = acc ? acc.pani : (light ? null : pani_of(bus.call('wwand', 'modem_cells', { modem: o.modem })));
		if (!pani && !light && !acc) {
			// no QMI cell info (an AT-only or NCM modem): Quectel's own report
			let q = at('AT+QENG="servingcell"');
			let mm = match(q?.response?.[0] ?? '',
				/"LTE","(FDD|TDD)",([0-9]+),([0-9]+),([0-9A-Fa-f]+),[0-9]+,[0-9]+,[0-9]+,[0-9]+,[0-9]+,([0-9A-Fa-f]+),/);
			if (mm)
				pani = REG.pani_eutran(+mm[2], +mm[3], length(mm[3]) == 3 ? 3 : 2, hex(mm[5]), hex(mm[4]), mm[1] == 'TDD');
		}

		return { imsi: m.imsi, imei: m.imei, mnc_len: o.mnc_len ?? home_mnc_len(m),
		         fam: fam, ue_addr: ue, pcscf: p, pcscfs: cand, pani: pani, prof: profile_of(m),
		         vrf: acc ? acc.bind : o.vrf, vowifi: !!acc };
	};

	// ---- one registration's transport --------------------------------------------

	let callid_of = (buf) => {
		let mm = match(buf, /\r\n(Call-ID|i)[ \t]*:[ \t]*([^\r\n]+)/i);
		return mm ? trim(mm[2]) : null;
	};

	let open_transport = (env, pair) => {
		let AF = (env.fam == 6) ? socket.AF_INET6 : socket.AF_INET;
		// IP_FREEBIND: bind() to our cellular /32 succeeds even before the kernel
		// sees it as local (fresh attach, before the l3mdev hotplug re-asserts the
		// VRF `local` route). Per-socket, no net.ipv4.ip_nonlocal_bind reliance.
		let freebind = (sk) => sk?.setopt(env.fam == 6 ? socket.IPPROTO_IPV6 : socket.IPPROTO_IP,
			env.fam == 6 ? socket.IPV6_FREEBIND : socket.IP_FREEBIND, 1);
		let t = { socks: {}, tcp: null, handles: [], tcp_by_callid: {}, conns: [] };
		// a failure closes what was opened so far: a socket left bound would
		// make every retry fail on its port
		let fail = (s, msg) => {
			let e = { error: sprintf('%s: %s', msg, socket.error()) };
			s?.close();
			for (let k, x in t.socks)
				x.close();
			return e;
		};
		for (let port in pair) {
			let s = socket.create(AF, socket.SOCK_DGRAM);
			if (!s)
				return fail(null, 'socket');
			if (env.vrf && !s.setopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, env.vrf))
				return fail(s, sprintf('bind to VRF %s', env.vrf));
			freebind(s);
			s.setopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);
			if (!s.bind({ address: env.ue_addr, port: port }))
				return fail(s, sprintf('bind %s port %d', env.ue_addr, port));
			t.socks[sprintf('%d', port)] = s;
		}
		// the profile's sip_transport without tcp: no listener
		if (env.prof?.tcp === false)
			return t;
		let l = socket.create(AF, socket.SOCK_STREAM);
		if (l && env.vrf)
			l.setopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, env.vrf);
		freebind(l);
		l?.setopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);
		if (l && l.bind({ address: env.ue_addr, port: pair[1] }) && l.listen(4))
			t.tcp = l;
		else {
			log('warn', sprintf('ue: no SIP over TCP on port %d: %s', pair[1], socket.error()));
			l?.close();
		}
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
			o.trace?.('ims ->', conn ? 'TCP' : sprintf('UDP %s:%d', dst, port), buf);
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
			smsip: !!o.smsip, sa_opts: env.vrf ? {} : null, reqid: 0x1500 + 0x10 * pair_ix,
			t1: env.prof?.t1, t2: env.prof?.t2, expires: env.prof?.expires,
			algs: env.prof?.algs, ealgs: env.prof?.ealgs,
			user_agent: env.prof?.user_agent, pcscf_port: env.prof?.pcscf_port,
			timer: (ms, fn) => uloop.timer(ms, fn),
			log: (lvl, msg) => log(lvl == 'notice' ? 'info' : lvl, 'ue: ' + msg),
			send: send,
		});

		let dispatch = (data) => {
			if (r.reg.on_message(data))
				return;
			if (r.sub?.on_message(data))
				return;
			if (r.sms?.on_message(data))
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
				if (b) {
					o.trace?.('ims <-', 'UDP', b.data);
					dispatch(b.data);
				}
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
						o.trace?.('ims <-', 'TCP', msg);
						dispatch(msg);
					}
				}, uloop.ULOOP_READ);
				push(t.handles, h);
			}, uloop.ULOOP_READ));

		attempt = r;
		r.reg.start((err, res) => {
			if (attempt === r)
				attempt = null;
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
		r.sub?.close();
		r.sms?.close();
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

	let schedule_refresh, register, refresh_due, start_sub, start_sms;

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
				// ... and so does the first try at each other P-CSCF
				let n = length(env.pcscfs);
				let moved = pcscf_failed(err) && n > 1;
				if (moved)
					pcscf_ix = (pcscf_ix + 1) % n;
				let wait = (fails == 0 || (moved && fails < n)) ? 5000 : retry;
				fails++;
				log('warn', sprintf('ue: registration failed: %J; again in %d s%s', err, wait / 1000,
					moved ? sprintf(' via P-CSCF %s', pcscf_pick(env.pcscfs, pcscf_ix)) : ''));
				// the kernel refused the sec-agree SAs (EINVAL: a crypto
				// driver that cannot take the key, ue/kcrypto.uc): the owner
				// may unload it before the next try
				if (err?.error == 'xfrm' && match(sprintf('%J', err.detail), /Invalid argument/))
					o.on_xfrm_refused?.(err);
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
			start_sub(r);
			start_sms(r);
		});
	};

	impu = () => filter(cur?.res?.associated ?? [], (u) => match(u, /^sip:/))[0] ?? cur?.reg?.ids?.impu;

	// the refresh when it is due; while a call runs it is retried every 30 s
	// (not rescheduled from the expiry: that would push it past it)
	refresh_due = () => {
		if (busy()) {
			log('info', 'ue: refresh due, a call is running; again in 30 s');
			return set_timer('reg', 30000, refresh_due);
		}
		register();
	};

	schedule_refresh = () => {
		let exp = cur?.res?.expires ?? 3600;
		let at_s = (exp > 1200) ? exp - 600 : int(exp / 2);
		set_timer('reg', at_s * 1000, refresh_due);
	};

	// the network ended our registration (reg-event): a new one from scratch,
	// once no call runs. "deactivated" asks for it at once (RFC 3680 4.5),
	// anything else (rejected, probation, ...) waits the retry time.
	let gone;
	gone = (r, event) => {
		if (r !== cur || self.state == 'stopped')
			return;
		if (busy())
			return set_timer('reg', 5000, () => gone(r, event));
		log('warn', sprintf('ue: the network ended the registration (%s); registering again', event ?? 'no reason'));
		cur = null;
		self.state = 'down';
		drop_reg(r, false, () => set_timer('reg', (event == 'deactivated') ? 1000 : retry, register));
	};

	start_sub = (r) => {
		if (r.env.prof?.reg_event === false)
			return;
		r.sub = SUB.create({
			ue_addr: r.env.ue_addr, port_c: r.pair[0], port_s: r.pair[1],
			pcscf: r.res.pcscf, route: r.res.service_route, impu: impu(),
			contact_user: r.env.imsi, imei_urn: REG.imei_urn(r.env.imei), pani: r.env.pani,
			sec_verify: r.reg.server_raw, t1: r.env.prof?.t1, t2: r.env.prof?.t2,
			user_agent: r.env.prof?.user_agent,
			timer: (ms, fn) => uloop.timer(ms, fn),
			log: (lvl, msg) => log(lvl, 'ue: ' + msg),
			send: r.send,
			on_event: (what, d) => {
				// during a refresh the old registration's subscription reports
				// its own replacement: only the one in use, and only at rest
				if (r !== cur || self.state != 'registered')
					return;
				if (what == 'shortened') {
					let s = max(int((d.expires ?? 0) / 2), 1);
					log('info', sprintf('ue: registration shortened to %s s; refresh in %d s', d.expires ?? '?', s));
					return set_timer('reg', s * 1000, refresh_due);
				}
				if (what == 'terminated')
					gone(r, d.event);
			},
		});
		r.sub.start();
	};

	// ---- SMS over IP ------------------------------------------------------------------

	// the SC: the profile's, else the one the last SMS came from, else the SIM's
	let smsc_seen = null, smsc_sim = false;
	let smsc_of = () => {
		if (prof.sms_smsc)
			return prof.sms_smsc;
		if (smsc_seen)
			return smsc_seen;
		if (smsc_sim === false)
			smsc_sim = smsc_from_csca(at('AT+CSCA?')?.response);
		return smsc_sim;
	};

	start_sms = (r) => {
		if (!o.smsip)
			return;
		r.sms = SMSIP.create({
			ue_addr: r.env.ue_addr, port_c: r.pair[0], port_s: r.pair[1],
			pcscf: r.res.pcscf, route: r.res.service_route, impu: impu(), pani: r.env.pani,
			sec_verify: r.reg.server_raw, t1: r.env.prof?.t1, t2: r.env.prof?.t2,
			user_agent: r.env.prof?.user_agent,
			timer: (ms, fn) => uloop.timer(ms, fn),
			log: (lvl, msg) => log(lvl, 'ue: ' + msg),
			send: r.send,
			smsc: smsc_of,
			psi: prof.sms_psi ? ((sc) => replace(prof.sms_psi, '%s', sc)) : null,
			encode_submit: o.encode_submit,
			deliver: (pdu, cb) => o.deliver ? o.deliver(pdu, cb) : cb({ error: 'no_store' }),
			on_smsc: (n) => { smsc_seen = n; },
		});
	};

	// a new address or P-CSCF on the PDN (re-attach), or the PDN gone: start over
	let watch;
	watch = () => {
		set_timer('watch', 20000, watch);
		if (!cur || self.state != 'registered' || busy())
			return;
		let env = discover(true);
		// the P-CSCF in use no longer among the PDN's counts as a change
		if (env.error || env.ue_addr != cur.env.ue_addr || index(env.pcscfs, cur.env.pcscf) < 0) {
			log('warn', sprintf('ue: the IMS %s changed (%s); registering again', o.access ? 'access (VoWiFi)' : 'PDN',
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
			t1: r.env.prof?.t1, t2: r.env.prof?.t2, user_agent: r.env.prof?.user_agent,
			alert_delay: r.env.prof?.alert_delay,
			timer: (ms, fn) => uloop.timer(ms, fn),
			log: (lvl, msg) => log(lvl, 'ue: ' + msg),
			// over VoWiFi there is no dedicated bearer to wait for
			send: r.send, qos_wait: r.env.vowifi ? null : qos_wait,
		});
		calls[c.call_id] = c;
		return c;
	};

	// a finished call stays known for 64*T1 (64 s without a profile), so the network's late CANCEL,
	// BYE or retransmission still finds it
	let forget = (c) => uloop.timer(prof.t1 ? 64 * prof.t1 : 64000, () => delete calls[c.call_id]);

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
		// a diverted call: what the network says about it, for the LAN side
		let hvals = (name) => map(filter(inv.headers ?? [], (x) => x[0] == name), (x) => x[1]);
		let inc = { call: c, media: media, number: caller_of(inv),
		            called: SIP_user(inv, 'p-called-party-id') ?? SIP_user(inv, 'to'),
		            history: hvals('history-info'), diversion: hvals('diversion'), handler: null, queue: [] };
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
		}, { offer: opts?.offer, privacy: opts?.privacy });
		return c;
	};

	self.ue_addr = () => cur?.env?.ue_addr;

	self.status = () => ({
		state: self.state, ue_addr: cur?.env?.ue_addr, pcscf: cur?.env?.pcscf, impu: impu(),
		expires: cur?.res?.expires, ports: cur?.pair, calls: length(keys(calls)),
		profile: prof.name, reg_event: cur?.sub?.state, smsip: !!o.smsip, sec: cur?.res?.sec,
	});

	self.profile = () => prof;

	// register now instead of at the next retry: the access came up
	// (sipd, once the VoWiFi tunnel stands)
	self.retry_now = function() {
		if (self.state == 'down')
			set_timer('reg', 0, register);
	};

	self.sms_send = function(number, text, cb) {
		if (!o.smsip)
			return cb({ error: 'smsip_off', detail: 'SMS over IP is off (ims_modem option smsip)' }, null);
		if (!cur?.sms || self.state != 'registered')
			return cb({ error: 'not_registered' }, null);
		cur.sms.send(number, text, cb);
	};

	self.stop = function(cb) {
		self.state = 'stopped';
		for (let k, t in timers)
			t?.cancel();
		for (let id, c in calls)
			if (c.state != 'ended')
				c.hangup();
		// a registration still being set up: its retransmissions, reserved
		// SPIs and sockets go as well
		if (attempt) {
			attempt.reg.close();
			close_transport(attempt.t);
			attempt = null;
		}
		let r = cur;
		cur = null;
		drop_reg(r, true, () => cb?.());
	};

	return self;
};
