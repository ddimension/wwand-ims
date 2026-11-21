// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// The VoWiFi tunnel's life (vowifi/tunnel.uc says what it is): load the
// connection into charon over vici, start it, learn the inner addresses and
// the P-CSCFs, and put them on an XFRM interface in a VRF of its own, where
// the router's IMS UE (sipd/line_ue.uc) binds and finds its route. Brought
// up again when charon reports it down.
//
//   let t = CTL.create({ vici, uloop, log, run, imsi, mnc_len, if_id, dev, vrf,
//                        table, epdg, apn, proposals, esp_proposals, remote_auth })
//   t.start(cb(err))     load + initiate; cb once the tunnel is up or failed
//   t.status()           { state, v4, v6, pcscf: [ … ], dev, vrf, error }
//   t.access()           what line_ue takes instead of the IMS PDN, or null
//   t.stop(cb)
//
// `run(argv)` runs one `ip` command and returns its exit code (the link,
// addresses and routes; sipd passes system()). Link and addresses are this
// module's own: the tunnel interface is not a netifd interface.

'use strict';

import * as TUN from 'vowifi_tunnel';

export function link_cmds(o, v4, v6)
{
	let t = sprintf('%d', o.table);
	let out = [
		[ 'ip', 'link', 'add', o.vrf, 'type', 'vrf', 'table', t ],
		[ 'ip', 'link', 'set', o.vrf, 'up' ],
		[ 'ip', 'link', 'add', o.dev, 'type', 'xfrm', 'if_id', sprintf('%d', o.if_id) ],
		[ 'ip', 'link', 'set', o.dev, 'master', o.vrf, 'mtu', sprintf('%d', o.mtu ?? 1280), 'up' ],
	];
	// The address goes on by hand, not through netifd: no host route next
	// to it, so an IPv4 /32 keeps its `local` route in the VRF table (the
	// IMS PDN needs files/wwand-ims-l3mdev.hotplug for that). No policy rule
	// of our own: the UE binds to the VRF, the l3mdev rule routes it, and a
	// netifd restart that flushes the rules has the hotplug put that back.
	if (v4) {
		push(out, [ 'ip', '-4', 'addr', 'add', v4 + '/32', 'dev', o.dev ]);
		push(out, [ 'ip', '-4', 'route', 'replace', 'default', 'dev', o.dev, 'table', t ]);
	}
	if (v6) {
		push(out, [ 'ip', '-6', 'addr', 'add', v6 + '/128', 'dev', o.dev, 'nodad' ]);
		push(out, [ 'ip', '-6', 'route', 'replace', 'default', 'dev', o.dev, 'table', t ]);
	}
	return out;
}

export function unlink_cmds(o)
{
	return [ [ 'ip', 'link', 'del', o.dev ] ];
}

export function create(o)
{
	let self = {};
	let log = o.log ?? (() => null);
	let vici = o.vici;
	let st = { state: 'down', v4: null, v6: null, pcscf: [], error: null };
	let plmn = TUN.plmn_of(o.imsi, o.mnc_len);
	let retry_t = null, stopped = false;

	let run_all = (cmds) => {
		for (let c in cmds) {
			let rc = o.run(c);
			// the VRF or the link already there is fine
			if (rc != 0)
				log('debug', sprintf('vowifi: %s -> %d', join(' ', c), rc));
		}
	};

	let link_down = () => run_all(unlink_cmds(o));

	let go_down = (why) => {
		if (st.state == 'down' && st.error == why)
			return;
		log('warn', sprintf('vowifi: tunnel down (%s)', why ?? '?'));
		link_down();
		st = { state: 'down', v4: null, v6: null, pcscf: [], error: why };
	};

	let addresses, initiate;

	// the SA's virtual IPs onto the interface
	addresses = (cb) => {
		let sa = null;
		vici.stream('list-sas', { ike: TUN.CONN }, 'list-sa', (m) => { sa ??= m; }, (err) => {
			let v = TUN.vips_of(sa);
			if (err || (!v.v4 && !v.v6))
				return cb(err ?? { error: 'no_vip', detail: 'the ePDG gave no inner address' });
			run_all(link_cmds(o, v.v4, v.v6));
			st.state = 'up';
			st.v4 = v.v4;
			st.v6 = v.v6;
			st.error = null;
			log('info', sprintf('vowifi: tunnel up to %s, inner %s%s%s, P-CSCF %s', v.remote ?? '?',
				v.v4 ?? '', (v.v4 && v.v6) ? ' ' : '', v.v6 ?? '', join(' ', st.pcscf) || 'none'));
			cb(null);
		});
	};

	initiate = (cb) => {
		st.state = 'connecting';
		st.pcscf = [];
		let lines = [];
		vici.stream('initiate', { child: 'ims', ike: TUN.CONN, timeout: '60000', 'init-limits': 'no' },
			'control-log', (m) => push(lines, m.msg), (err, res) => {
				if (err || res?.success != 'yes') {
					let why = err?.detail ?? res?.errmsg ?? 'initiate failed';
					go_down(why);
					log('debug', sprintf('vowifi: %s', join(' | ', slice(lines, -8))));
					return cb?.({ error: 'initiate', detail: why });
				}
				addresses((e) => {
					if (e)
						go_down(e.detail ?? e.error);
					cb?.(e);
				});
			});
	};

	let again = () => {
		if (stopped || retry_t)
			return;
		retry_t = o.uloop.timer(30000, () => {
			retry_t = null;
			if (!stopped && st.state == 'down')
				initiate(null);
		});
	};

	self.start = function(cb) {
		if (!plmn)
			return cb({ error: 'imsi', detail: 'no IMSI to build the identity from' });
		stopped = false;
		// P-CSCFs from the p-cscf plugin's log lines; a tunnel that charon
		// reports down is brought back after 30 s
		vici.listen('log', (m) => {
			let p = TUN.pcscf_from_log(m?.msg);
			if (p && index(st.pcscf, p) < 0)
				push(st.pcscf, p);
		});
		vici.listen('ike-updown', (m) => {
			if (m?.[TUN.CONN] && m.up != 'yes') {
				go_down('charon: IKE SA down');
				again();
			}
		});
		vici.request('load-conn', TUN.conn_config({ imsi: o.imsi, plmn: plmn, if_id: o.if_id, epdg: o.epdg,
			apn: o.apn, proposals: o.proposals, esp_proposals: o.esp_proposals, remote_auth: o.remote_auth }),
			(err, res) => {
				if (err || res?.success != 'yes')
					return cb({ error: 'load-conn', detail: err?.detail ?? res?.errmsg });
				initiate((e) => {
					if (e)
						again();
					cb(e);
				});
			});
	};

	self.status = () => ({ ...st, dev: o.dev, vrf: o.vrf, epdg: o.epdg ?? (plmn ? TUN.epdg_fqdn(plmn) : null) });

	// line_ue's view: the UE address and P-CSCFs the tunnel gave, and the
	// VRF its sockets bind to, as on the IMS PDN. The XFRM interface and its
	// VRF must be in the IMS firewall zone (wwandctl ims setup), or the
	// replies to the protected server port are rejected (ICMP port
	// unreachable, HW 2026-11-21). The sec-agree SAs inside the tunnel need
	// no if_id.
	self.access = () => (st.state == 'up') ? { v4: st.v4, v6: st.v6, pcscf: [ ...st.pcscf ], vrf: o.vrf,
		pani: o.pani ?? 'IEEE-802.11', bind: o.vrf } : null;

	self.stop = function(cb) {
		stopped = true;
		retry_t?.cancel();
		retry_t = null;
		vici.request('terminate', { ike: TUN.CONN, timeout: '5000' }, () => {
			vici.request('unload-conn', { name: TUN.CONN }, () => {
				link_down();
				st = { state: 'down', v4: null, v6: null, pcscf: [], error: 'stopped' };
				cb?.();
			});
		});
	};

	return self;
}
