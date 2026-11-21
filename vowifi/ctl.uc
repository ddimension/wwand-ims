// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// The VoWiFi tunnel's life (vowifi/tunnel.uc says what it is): load the
// connection into charon over vici, start it, learn the inner addresses and
// the P-CSCFs, and hand them to netifd, which puts them on the XFRM
// interface with a routing table of their own, where the router's IMS UE
// (sipd/line_ue.uc) binds and finds its route.
//
// It keeps the tunnel up for as long as it runs: whenever it is not up —
// the start failed, charon reported the IKE or CHILD SA down, or charon
// itself went away (restarted, crashed: the vici connection closes) — it
// loads the connection again and starts it, after 5 s, then backing off to
// 60 s, without giving up. A new charon knows nothing of what was loaded.
//
// charon's own log for this connection (vici's `log` events, by IKE SA
// name) goes to syslog: level 0/1 as info, the failures as warn. Its other
// connections stay out.
//
//   let t = CTL.create({ vici, uloop, log, run, notify, imsi, mnc_len, conn, if_id, dev,
//                        epdg, apn, proposals, esp_proposals, remote_auth, pani, on_up })
//   t.start(cb(err))     the first attempt's outcome; it goes on after a failure
//   t.status()           { state, v4, v6, pcscf: [ … ], dev, epdg, error, tries }
//   t.access()           what line_ue takes instead of the IMS PDN, or null
//   t.vici_closed(why)   VICI.create's on_close
//   t.stop(cb)
//
// netifd owns everything on the router side (wwand's split): the XFRM
// interface (OpenWrt's proto xfrm, ifid = if_id) and the IP
// configuration (proto wwandvowifi on '@<dev>', files/vowifi-proto.sh, which
// asks sipd's vowifi_addr = access()). `notify()` tells it the tunnel's state
// changed (sipd: `network.interface.<name> renew`). `run(argv)` runs one
// command (sipd passes system()): only to drop charon's own copy of the
// virtual IP.

'use strict';

import * as TUN from 'vowifi_tunnel';

const BACKOFF = [ 5000, 10000, 20000, 40000, 60000 ];

// one attempt (load-conn, initiate with its own 60 s limit, list-sas) that
// has not ended after this long has lost charon: an answer that never came
// (HW 2026-11-21: charon died during an initiate and the vici connection
// stayed silent) — the connection is dropped and the attempt counts as failed
const ATTEMPT_MS = 90000;

// charon installs the virtual IP itself as well, where its outer route
// points (the LAN bridge here): that copy goes, the one netifd put on the
// XFRM interface stays, and charon's settings stay as they are for its
// other connections. Only for addresses and a device name of the expected
// shape (they go into a shell line).
export function drop_charon_vip_cmds(o, v4, v6)
{
	let out = [];
	if (!match(o.dev ?? '', /^[A-Za-z0-9_.-]+$/))
		return out;
	if (v4 && match(v4, /^[0-9.]+$/))
		push(out, [ 'sh', '-c', sprintf('ip -4 -o addr show to %s/32 | while read -r _ dev _; do [ "$dev" = %s ] || ip -4 addr del %s/32 dev "$dev"; done', v4, o.dev, v4) ]);
	if (v6 && match(v6, /^[0-9A-Fa-f:]+$/))
		push(out, [ 'sh', '-c', sprintf('ip -6 -o addr show to %s/128 | while read -r _ dev _; do [ "$dev" = %s ] || ip -6 addr del %s/128 dev "$dev"; done', v6, o.dev, v6) ]);
	return out;
}

// a vici `log` event of our connection as a syslog line, or null: level 0
// and 1 of the IKE, CFG, CHD and KNL groups as info; anything that says it
// failed as warn; NET/ENC chatter (packets, encodings) only when it fails
// `detail` (option vowifi_loglevel, charon's levels 0-4): above 1 every
// group of the connection up to that level, as debug — the messages of the
// tunnel's setup, which `initiate` streams as control-log at that level
// (vici's global log event stops at level 1, LEVEL_CTRL: vici_logger.c)
// The tunnel's two netifd interfaces, created at run time (network
// add_dynamic) rather than written into /etc/config/network: the XFRM
// interface (OpenWrt's proto xfrm, its zone into the firewall: firewall4
// takes an interface's `zone` data, HW 2026-11-21) and the one that takes
// its addresses (proto wwandvowifi on '@<dev>', addresses and routes into
// the tunnel's table). o: { dev, iface, if_id, mtu, table, zone }
export function net_specs(o)
{
	let t = sprintf('%d', o.table ?? 31);
	return [
		{ name: o.dev, proto: 'xfrm', ifid: +(o.if_id ?? 7001), mtu: +(o.mtu ?? 1280), zone: o.zone ?? 'ims' },
		{ name: o.iface, proto: 'wwandvowifi', device: '@' + o.dev, ip4table: t, ip6table: t,
		  peerdns: false, delegate: false },
	];
}

export function log_line(m, detail, conn)
{
	conn ??= TUN.CONN;
	if (m?.['ikesa-name'] != conn && m?.['ikesa-name'] != null || m?.msg == null)
		return null;
	let lvl = +(m.level ?? 1), grp = m.group ?? '';
	let bad = match(m.msg, /fail|error|unacceptable|AUTH_FAILED|not supported|giving up|timed out|no (proposal|matching)|NO_PROPOSAL_CHOSEN|TS_UNACCEPTABLE/i) != null;
	if (bad)
		return { level: 'warn', msg: sprintf('charon: %s', m.msg) };
	if (detail > 1 && lvl <= detail)
		return { level: (lvl <= 1) ? 'info' : 'debug', msg: sprintf('charon[%s%d]: %s', grp, lvl, m.msg) };
	if (lvl > 1 || index([ 'IKE', 'CFG', 'CHD', 'KNL' ], grp) < 0)
		return null;
	return { level: 'info', msg: sprintf('charon: %s', m.msg) };
}

export function create(o)
{
	let self = {};
	let log = o.log ?? (() => null);
	let vici = o.vici;
	let st = { state: 'stopped', v4: null, v6: null, pcscf: [], error: null, tries: 0 };
	let plmn = TUN.plmn_of(o.imsi, o.mnc_len);
	// the charon connection of this line (several lines: wwand-vowifi<i>)
	let CONN = o.conn ?? TUN.CONN;
	let retry_t = null, busy = false, first_cb = null, watch_t = null, gen = 0, listening = false;

	let run_all = (cmds) => {
		for (let c in cmds) {
			let rc = o.run(c);
			// the VRF or the link already there, an address already gone: fine
			if (rc != 0)
				log('debug', sprintf('vowifi: %s -> %d', join(' ', c), rc));
		}
	};

	let set_down = (why) => {
		let was = st.state;
		st = { state: (was == 'stopped') ? 'stopped' : 'down', v4: null, v6: null, pcscf: [], error: why, tries: st.tries };
		if (was == 'up') {
			log('warn', sprintf('vowifi: tunnel down (%s)', why ?? '?'));
			// netifd takes the addresses away
			o.notify?.();
		}
	};

	let attempt, schedule;

	schedule = () => {
		if (st.state == 'stopped' || retry_t || busy)
			return;
		let ms = BACKOFF[min(st.tries, length(BACKOFF) - 1)];
		retry_t = o.uloop.timer(ms, () => {
			retry_t = null;
			attempt();
		});
	};

	let finished = (err) => {
		watch_t?.cancel();
		watch_t = null;
		busy = false;
		let cb = first_cb;
		first_cb = null;
		if (err) {
			st.tries++;
			set_down(err.detail ?? err.error);
			log('warn', sprintf('vowifi: no tunnel (%s); again in %d s', st.error,
				BACKOFF[min(st.tries, length(BACKOFF) - 1)] / 1000));
			schedule();
		}
		else {
			st.tries = 0;
			o.on_up?.();
		}
		cb?.(err);
	};

	// the SA's virtual IPs onto the interface
	let addresses = () => {
		let sa = null, my = gen;
		let done = (err) => (my == gen) ? finished(err) : null;
		vici.stream('list-sas', { ike: CONN }, 'list-sa', (m) => { sa ??= m; }, (err) => {
			if (st.state == 'stopped')
				return done(null);
			let v = TUN.vips_of(sa, CONN);
			if (err || (!v.v4 && !v.v6))
				return done(err ?? { error: 'no_vip', detail: 'the ePDG gave no inner address' });
			if (my != gen)
				return;
			st.state = 'up';
			st.v4 = v.v4;
			st.v6 = v.v6;
			st.error = null;
			run_all(drop_charon_vip_cmds(o, v.v4, v.v6));
			// netifd takes the addresses from vowifi_addr (status()) now
			o.notify?.();
			log('info', sprintf('vowifi: tunnel up to %s, inner %s%s%s, P-CSCF %s', v.remote ?? '?',
				v.v4 ?? '', (v.v4 && v.v6) ? ' ' : '', v.v6 ?? '', join(' ', st.pcscf) || 'none'));
			done(null);
		});
	};

	// load the connection (a new charon has none) and start it
	attempt = () => {
		if (st.state == 'stopped' || busy || st.state == 'up')
			return;
		busy = true;
		st.state = 'connecting';
		st.pcscf = [];
		// the answers of an attempt the watchdog gave up on are not this one's
		let my = ++gen;
		let done = (err) => (my == gen) ? finished(err) : null;
		watch_t = o.uloop.timer(ATTEMPT_MS, () => {
			watch_t = null;
			if (my != gen || !busy)
				return;
			gen++;
			log('warn', sprintf('vowifi: no answer from charon for %d s; connecting to it again', ATTEMPT_MS / 1000));
			vici.reset?.('no answer from charon');
			finished({ error: 'charon', detail: 'no answer from charon' });
		});
		vici.request('load-conn', TUN.conn_config({ imsi: o.imsi, plmn: plmn, conn: CONN, if_id: o.if_id, epdg: o.epdg,
			apn: o.apn, proposals: o.proposals, esp_proposals: o.esp_proposals, remote_auth: o.remote_auth,
			rekey_s: o.rekey_s, esp_rekey_s: o.esp_rekey_s, dpd_s: o.dpd_s }),
			(err, res) => {
				if (err || res?.success != 'yes')
					return done({ error: 'load-conn', detail: err?.detail ?? res?.errmsg ?? 'refused' });
				// with a log level above 1 the setup's messages at that level
				// (control-log), which charon's global log never carries
				let detail = +(o.loglevel ?? 1);
				vici.stream('initiate', { child: 'ims', ike: CONN, timeout: '60000', 'init-limits': 'no',
				                          loglevel: sprintf('%d', detail) },
					'control-log', (m) => {
						if (detail <= 1)
							return;
						let l = log_line({ ...m, 'ikesa-name': m?.['ikesa-name'] ?? CONN }, detail, CONN);
						if (l)
							log(l.level, l.msg);
					}, (e, r) => {
						if (e || r?.success != 'yes')
							return done({ error: 'initiate', detail: e?.detail ?? r?.errmsg ?? 'initiate failed' });
						if (my == gen)
							addresses();
					});
			});
	};

	// an IKE or CHILD SA of ours down (DPD, the ePDG's delete, a failed
	// rekey): the next attempt soon, unless charon brings it back first
	let sa_down = (what) => {
		if (st.state != 'up')
			return;
		set_down(sprintf('charon: %s SA down', what));
		schedule();
	};

	self.start = function(cb) {
		if (!plmn)
			return cb?.({ error: 'imsi', detail: 'no IMSI to build the identity from' });
		st.state = 'down';
		st.tries = 0;
		// once: a start after a stop keeps the listeners it has
		if (!listening) {
			listening = true;
			vici.listen('log', (m) => {
				if (m?.['ikesa-name'] != CONN)
					return;
				// the P-CSCFs of our own attempt only
				let p = busy ? TUN.pcscf_from_log(m?.msg) : null;
				if (p && index(st.pcscf, p) < 0)
					push(st.pcscf, p);
				// while an initiate streams its own (control-log), not twice
				let l = (busy && +(o.loglevel ?? 1) > 1) ? null : log_line(m, +(o.loglevel ?? 1), CONN);
				if (l)
					log(l.level, l.msg);
			});
			vici.listen('ike-updown', (m) => {
				if (m?.[CONN] && m.up != 'yes')
					sa_down('IKE');
			});
			vici.listen('child-updown', (m) => {
				if (m?.[CONN] && m.up != 'yes')
					sa_down('CHILD');
			});
		}
		first_cb = cb;
		attempt();
	};

	// charon went away: what it held is gone with it, the SAs included
	self.vici_closed = function(why) {
		if (st.state == 'stopped')
			return;
		watch_t?.cancel();
		watch_t = null;
		gen++;
		busy = false;
		set_down(sprintf('charon: %s', why ?? 'gone'));
		schedule();
	};

	self.status = () => ({ ...st, dev: o.dev, epdg: o.epdg ?? (plmn ? TUN.epdg_fqdn(plmn) : null) });

	// line_ue's view: the UE address and P-CSCFs the tunnel gave, and the
	// device its sockets bind to (the IMS PDN's VRF there). The tunnel's
	// netifd interface must be in the IMS firewall zone (wwandctl ims
	// setup), or the replies to the protected server port are rejected (ICMP
	// port unreachable, HW 2026-11-21). The sec-agree SAs inside the tunnel
	// need no if_id.
	// No VRF here: netifd (OpenWrt 25.12, 2026.02.26) turns IPv6 off on every
	// VRF port without an ipv6 setting of its own (vrf.c, "Disable IPv6 for
	// vrf ports"; gone in 2026.07), and the XFRM interface proto xfrm creates
	// cannot carry one — the IPv6-only tunnel would be dead (HW 2026-11-21).
	// The isolation is netifd's policy routing instead: ip6table/ip4table put
	// the default route into the tunnel's table, the `from`/`to` rules of the
	// inner address select it; the sockets bind to the address and the
	// XFRM interface.
	self.access = () => (st.state == 'up') ? { v4: st.v4, v6: st.v6, pcscf: [ ...st.pcscf ],
		pani: o.pani ?? 'IEEE-802.11', bind: o.dev } : null;

	self.stop = function(cb) {
		retry_t?.cancel();
		retry_t = null;
		watch_t?.cancel();
		watch_t = null;
		gen++;
		let was_up = (st.state == 'up');
		st.state = 'stopped';
		vici.request('terminate', { ike: CONN, timeout: '5000' }, () => {
			vici.request('unload-conn', { name: CONN }, () => {
				st = { state: 'stopped', v4: null, v6: null, pcscf: [], error: 'stopped', tries: 0 };
				if (was_up)
					o.notify?.();
				cb?.();
			});
		});
	};

	return self;
}
