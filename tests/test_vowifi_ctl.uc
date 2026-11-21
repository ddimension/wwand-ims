// Host tests for vowifi/ctl.uc against a stand-in for vici: load-conn,
// initiate, the P-CSCF from charon's log, the virtual IPs from list-sas,
// the link commands, a tunnel that goes down. Made-up identifiers.
'use strict';

import { eq, ok, done } from './lib/check.uc';
import * as CTL from 'vowifi_ctl';
import * as TUN from 'vowifi_tunnel';

let O = { if_id: 7001, dev: 'imswifi0', vrf: 'imswifi', table: 31 };
eq(CTL.link_cmds(O, '10.45.0.2', '2001:db8:aa::2'), [
	[ 'ip', 'link', 'add', 'imswifi', 'type', 'vrf', 'table', '31' ],
	[ 'ip', 'link', 'set', 'imswifi', 'up' ],
	[ 'ip', 'link', 'add', 'imswifi0', 'type', 'xfrm', 'if_id', '7001' ],
	[ 'ip', 'link', 'set', 'imswifi0', 'master', 'imswifi', 'mtu', '1280', 'up' ],
	[ 'ip', '-4', 'addr', 'add', '10.45.0.2/32', 'dev', 'imswifi0' ],
	[ 'ip', '-4', 'route', 'replace', 'default', 'dev', 'imswifi0', 'table', '31' ],
	[ 'ip', '-6', 'addr', 'add', '2001:db8:aa::2/128', 'dev', 'imswifi0', 'nodad' ],
	[ 'ip', '-6', 'route', 'replace', 'default', 'dev', 'imswifi0', 'table', '31' ] ],
	'link_cmds: VRF, XFRM interface with the if_id, addresses, default routes in the VRF table');
eq(length(CTL.link_cmds(O, null, '2001:db8:aa::2')), 6, 'link_cmds: v6 only');

function world(answers)
{
	let w = { reqs: [], listeners: {}, cmds: [], timers: [] };
	w.vici = {
		request: (cmd, msg, cb) => { push(w.reqs, [ cmd, msg ]); cb(null, answers[cmd] ?? { success: 'yes' }); },
		stream: (cmd, msg, ev, item, cb) => {
			push(w.reqs, [ cmd, msg ]);
			if (cmd == 'initiate')
				for (let l in answers.pcscf_logs ?? [])
					for (let fn in w.listeners.log ?? [])
						fn({ msg: l });
			for (let m in answers[ev] ?? [])
				item(m);
			cb(null, answers[cmd] ?? { success: 'yes' });
		},
		listen: (ev, fn) => { w.listeners[ev] ??= []; push(w.listeners[ev], fn); },
	};
	w.uloop = { timer: (ms, fn) => { let t = { ms: ms, fn: fn }; t.cancel = () => { t.dead = true; }; push(w.timers, t); return t; } };
	w.ctl = CTL.create({ vici: w.vici, uloop: w.uloop, run: (c) => { push(w.cmds, c); return 0; },
		imsi: '262991234567890', mnc_len: 2, ...O });
	return w;
}

let SA = { [TUN.CONN]: { state: 'ESTABLISHED', 'remote-host': '198.51.100.7', 'local-vips': [ '10.45.0.2', '2001:db8:aa::2' ] } };
let w = world({ 'list-sa': [ SA ], pcscf_logs: [ 'received P-CSCF server IP 2001:db8:ff::10', 'something else',
	'received P-CSCF server IP 2001:db8:ff::11' ] });
let err = 'unset';
w.ctl.start((e) => { err = e; });
eq(err, null, 'start: up');
eq(map(w.reqs, (r) => r[0]), [ 'load-conn', 'initiate', 'list-sas' ], 'start: load-conn, initiate, list-sas');
eq(w.reqs[0][1][TUN.CONN].local.id, '0262991234567890@nai.epc.mnc099.mcc262.3gppnetwork.org', 'start: the NAI from the IMSI');
eq(w.reqs[1][1], { child: 'ims', ike: TUN.CONN, timeout: '60000', 'init-limits': 'no' }, 'start: initiate the child');
let st = w.ctl.status();
eq([ st.state, st.v4, st.v6, st.pcscf, st.epdg ], [ 'up', '10.45.0.2', '2001:db8:aa::2', [ '2001:db8:ff::10', '2001:db8:ff::11' ],
	'epdg.epc.mnc099.mcc262.pub.3gppnetwork.org' ], 'status: inner addresses, P-CSCFs from the log, the ePDG');
eq(w.ctl.access(), { v4: '10.45.0.2', v6: '2001:db8:aa::2', pcscf: [ '2001:db8:ff::10', '2001:db8:ff::11' ],
	vrf: 'imswifi', pani: 'IEEE-802.11', bind: 'imswifi' }, 'access: what line_ue takes');
eq(length(w.cmds), 8, 'start: the link set up');

// charon reports the IKE SA down: link removed, again in 30 s
w.cmds = [];
w.listeners['ike-updown'][0]({ up: 'no', [TUN.CONN]: {} });
eq([ w.ctl.status().state, w.cmds[0], w.ctl.access(), w.timers[0]?.ms ],
	[ 'down', [ 'ip', 'link', 'del', 'imswifi0' ], null, 30000 ], 'down: link removed, a new try armed');
w.reqs = [];
w.timers[0].fn();
eq(map(w.reqs, (r) => r[0]), [ 'initiate', 'list-sas' ], 'down: the retry initiates again');
eq(w.ctl.status().state, 'up', 'down: and is up again');

// initiate fails
w = world({ initiate: { success: 'no', errmsg: 'establishing CHILD_SA failed' } });
w.ctl.start((e) => { err = e; });
eq([ err?.error, err?.detail, w.ctl.status().state, w.ctl.status().error ],
	[ 'initiate', 'establishing CHILD_SA failed', 'down', 'establishing CHILD_SA failed' ], 'initiate fails: down with the reason');
eq(w.timers[0]?.ms, 30000, 'initiate fails: tried again later');

// no inner address
w = world({ 'list-sa': [ { [TUN.CONN]: { state: 'ESTABLISHED', 'local-vips': [] } } ] });
w.ctl.start((e) => { err = e; });
eq([ err?.error, w.ctl.status().state ], [ 'no_vip', 'down' ], 'no virtual IP: down');

// load-conn refused
w = world({ 'load-conn': { success: 'no', errmsg: 'bad config' } });
w.ctl.start((e) => { err = e; });
eq(err, { error: 'load-conn', detail: 'bad config' }, 'load-conn refused');

// stop
w = world({ 'list-sa': [ SA ] });
w.ctl.start(() => null);
w.reqs = []; w.cmds = [];
let stopped = false;
w.ctl.stop(() => { stopped = true; });
eq([ stopped, map(w.reqs, (r) => r[0]), w.cmds, w.ctl.status().state ],
	[ true, [ 'terminate', 'unload-conn' ], [ [ 'ip', 'link', 'del', 'imswifi0' ] ], 'down' ], 'stop: terminate, unload, link gone');

done();
