// Host tests for vowifi/ctl.uc against a stand-in for vici: load-conn,
// initiate, the P-CSCF from charon's log, the virtual IPs from list-sas, the
// link commands, the tunnel kept up (IKE/CHILD SA down, charon gone, a start
// that fails, with backoff), charon's log to syslog. Made-up identifiers.
'use strict';

import { eq, ok, done } from './lib/check.uc';
import * as CTL from 'vowifi_ctl';
import * as TUN from 'vowifi_tunnel';

let O = { if_id: 7001, dev: 'imswifi0' };
let dv = CTL.drop_charon_vip_cmds(O, '10.45.0.2', '2001:db8:aa::2');
ok(length(dv) == 2 && dv[1][0] == 'sh' && index(dv[1][2], 'ip -6 -o addr show to 2001:db8:aa::2/128') == 0 &&
	index(dv[1][2], '[ "$dev" = imswifi0 ] ||') >= 0, 'drop_charon_vip_cmds: charon\'s copy elsewhere goes, ours stays');
eq(CTL.drop_charon_vip_cmds(O, '10.0.0.1; reboot', 'x;y'), [], 'drop_charon_vip_cmds: nothing of an unexpected shape into a shell');

eq(CTL.net_specs({ dev: 'imswifi0', iface: 'wwvowifi', if_id: 7001 }), [
	{ name: 'imswifi0', proto: 'xfrm', ifid: 7001, mtu: 1280, zone: 'ims' },
	{ name: 'wwvowifi', proto: 'wwandvowifi', device: '@imswifi0', ip4table: '31', ip6table: '31', peerdns: false, delegate: false } ],
	'net_specs: the XFRM interface into the ims zone, the address interface on its alias, table 31');

// charon's log to syslog
let L = (group, level, msg, name) => ({ group: group, level: sprintf('%d', level), msg: msg, 'ikesa-name': name ?? TUN.CONN });
eq(CTL.log_line(L('IKE', 1, 'IKE_SA wwand-vowifi[3] established')), { level: 'info', msg: 'charon: IKE_SA wwand-vowifi[3] established' },
	'log_line: IKE level 1 -> info');
eq(CTL.log_line(L('ENC', 1, 'parsed IKE_AUTH response 1 [ IDr EAP/REQ/AKA ]')), null, 'log_line: ENC chatter left out');
eq(CTL.log_line(L('IKE', 2, 'sending keep alive')), null, 'log_line: level 2 left out');
eq(CTL.log_line(L('CFG', 1, 'constraint check failed: identity required')).level, 'warn', 'log_line: a failure -> warn');
eq(CTL.log_line(L('IKE', 1, 'established', 'other-vpn')), null, 'log_line: another connection of charon left out');
eq(CTL.log_line(L('ENC', 2, 'parsed IKE_AUTH response 1 [ N(AUTH_FAILED) ]'), 2).level, 'warn', 'log_line detail: a failure stays warn');
eq(CTL.log_line(L('NET', 2, 'sending packet: from 10.0.0.1[4500] to 198.51.100.7[4500] (484 bytes)'), 2),
	{ level: 'debug', msg: 'charon[NET2]: sending packet: from 10.0.0.1[4500] to 198.51.100.7[4500] (484 bytes)' }, 'log_line detail 2: NET level 2 as debug');
eq(CTL.log_line(L('ENC', 3, 'raw'), 2), null, 'log_line detail 2: level 3 left out');

function world(answers)
{
	let w = { reqs: [], listeners: {}, cmds: [], timers: [], logs: [], ups: 0, answers: answers };
	let pick = (cmd) => {
		let a = w.answers[cmd];
		if (type(a) == 'array')
			return length(a) > 1 ? shift(a) : a[0];
		return a ?? { success: 'yes' };
	};
	w.vici = {
		request: (cmd, msg, cb) => { push(w.reqs, cmd); cb(null, pick(cmd)); },
		stream: (cmd, msg, ev, item, cb) => {
			push(w.reqs, cmd);
			if (cmd == 'initiate')
				for (let l in w.answers.logs ?? [])
					for (let fn in w.listeners.log ?? [])
						fn(l);
			for (let m in w.answers[ev] ?? [])
				item?.(m);
			// a charon that died mid-request: the answer never comes
			if (w.answers.hang == cmd)
				return;
			cb(null, pick(cmd));
		},
		reset: (why) => { push(w.reqs, 'reset:' + why); },
		listen: (ev, fn) => { w.listeners[ev] ??= []; push(w.listeners[ev], fn); },
	};
	w.uloop = { timer: (ms, fn) => { let t = { ms: ms, fn: fn }; t.cancel = () => { t.dead = true; }; push(w.timers, t); return t; } };
	w.fire = () => { let t = w.timers[length(w.timers) - 1]; if (!t.dead) { t.dead = true; t.fn(); } };
	w.notified = 0;
	w.ctl = CTL.create({ vici: w.vici, uloop: w.uloop, run: (c) => { push(w.cmds, c); return 0; },
		notify: () => { w.notified++; },
		log: (l, m) => push(w.logs, [ l, m ]), on_up: () => { w.ups++; },
		imsi: '262991234567890', mnc_len: 2, ...O });
	return w;
}

let SA = { [TUN.CONN]: { state: 'ESTABLISHED', 'remote-host': '198.51.100.7', 'local-vips': [ '10.45.0.2', '2001:db8:aa::2' ] } };
let LOGS = [ L('CFG', 1, 'received P-CSCF server IP 2001:db8:ff::10'), L('CFG', 1, 'received P-CSCF server IP 2001:db8:ff::11'),
	L('IKE', 1, 'received P-CSCF server IP 2001:db8:ff::99', 'other-vpn') ];

let w = world({ 'list-sa': [ SA ], logs: LOGS });
let err = 'unset';
w.ctl.start((e) => { err = e; });
eq(err, null, 'start: up');
eq(w.reqs, [ 'load-conn', 'initiate', 'list-sas' ], 'start: load-conn, initiate, list-sas');
let st = w.ctl.status();
eq([ st.state, st.v4, st.v6, st.pcscf, st.epdg, w.ups ], [ 'up', '10.45.0.2', '2001:db8:aa::2', [ '2001:db8:ff::10', '2001:db8:ff::11' ],
	'epdg.epc.mnc099.mcc262.pub.3gppnetwork.org', 1 ], 'status: inner addresses, P-CSCFs of our connection only, on_up');
eq(w.ctl.access(), { v4: '10.45.0.2', v6: '2001:db8:aa::2', pcscf: [ '2001:db8:ff::10', '2001:db8:ff::11' ],
	pani: 'IEEE-802.11', bind: 'imswifi0' }, 'access: what line_ue takes, bound to the XFRM interface (no VRF)');
ok(length(filter(w.logs, (x) => x[1] == 'charon: received P-CSCF server IP 2001:db8:ff::10')) == 1 &&
	!length(filter(w.logs, (x) => index(x[1], '::99') >= 0)), 'start: our charon lines in syslog, not another connection\'s');
eq([ length(w.cmds), w.cmds[0][0], w.notified ], [ 2, 'sh', 1 ], 'start: charon\'s copies dropped, netifd told, no link of its own');

// the IKE SA down: link removed, after 5 s a new load-conn and initiate
w.cmds = []; w.reqs = [];
w.listeners['ike-updown'][0]({ up: 'no', [TUN.CONN]: {} });
eq([ w.ctl.status().state, w.notified, w.ctl.access(), w.timers[length(w.timers) - 1].ms ],
	[ 'down', 2, null, 5000 ], 'IKE SA down: netifd told, again in 5 s');
w.fire();
eq([ w.reqs, w.ctl.status().state, w.ups ], [ [ 'load-conn', 'initiate', 'list-sas' ], 'up', 2 ], 'IKE SA down: loaded and up again');

// the CHILD SA down alone
w.reqs = [];
w.listeners['child-updown'][0]({ up: 'no', [TUN.CONN]: {} });
eq(w.ctl.status().state, 'down', 'CHILD SA down: down');
w.fire();
eq(w.ctl.status().state, 'up', 'CHILD SA down: back up');
w.listeners['ike-updown'][0]({ up: 'yes', [TUN.CONN]: {} });
w.listeners['ike-updown'][0]({ up: 'no', other: {} });
eq(w.ctl.status().state, 'up', 'updown: an up event, or another connection\'s down, changes nothing');

// charon gone (restart, crash): down, then loaded again into the new charon
w.reqs = [];
w.ctl.vici_closed('charon closed the connection');
eq([ w.ctl.status().state, w.ctl.status().error ], [ 'down', 'charon: charon closed the connection' ], 'charon gone: down');
w.fire();
eq([ w.reqs, w.ctl.status().state ], [ [ 'load-conn', 'initiate', 'list-sas' ], 'up' ], 'charon gone: the connection loaded again, up');

// a start that keeps failing: backoff 5, 10, 20, 40, 60, 60 s, never giving up
w = world({ initiate: [ { success: 'no', errmsg: 'establishing CHILD_SA failed' } ] });
w.ctl.start((e) => { err = e; });
eq([ err?.error, err?.detail, w.ctl.status().state ], [ 'initiate', 'establishing CHILD_SA failed', 'down' ], 'initiate fails: down');
let waits = [ w.timers[length(w.timers) - 1].ms ];
for (let i = 0; i < 5; i++) {
	w.fire();
	push(waits, w.timers[length(w.timers) - 1].ms);
}
eq(waits, [ 10000, 20000, 40000, 60000, 60000, 60000 ], 'initiate fails: backoff up to 60 s, never giving up');
ok(length(filter(w.reqs, (r) => r == 'load-conn')) == 6, 'initiate fails: every try loads the connection again');
// then it works: tries reset
w.answers.initiate = { success: 'yes' };
w.answers['list-sa'] = [ SA ];
w.fire();
eq([ w.ctl.status().state, w.ctl.status().tries ], [ 'up', 0 ], 'then it works: up, the backoff reset');

// load-conn refused (charon not running yet), no inner address
w = world({ 'load-conn': { success: 'no', errmsg: 'bad config' } });
w.ctl.start((e) => { err = e; });
eq([ err, w.timers[length(w.timers) - 1]?.ms ], [ { error: 'load-conn', detail: 'bad config' }, 10000 ], 'load-conn refused: tried again');
w = world({ 'list-sa': [ { [TUN.CONN]: { state: 'ESTABLISHED', 'local-vips': [] } } ] });
w.ctl.start((e) => { err = e; });
eq([ err?.error, w.ctl.status().state ], [ 'no_vip', 'down' ], 'no virtual IP: down');

// charon silent during an initiate (died, the connection stayed open): the
// watchdog gives up after 90 s, drops the connection, tries again
w = world({ hang: 'initiate', 'list-sa': [ SA ] });
w.ctl.start((e) => { err = e; });
let wd = w.timers[length(w.timers) - 1];
eq([ w.ctl.status().state, wd.ms ], [ 'connecting', 90000 ], 'silent charon: connecting, the watchdog armed');
w.fire();
eq([ err?.error, w.ctl.status().state, w.reqs[length(w.reqs) - 1], w.timers[length(w.timers) - 1].ms ],
	[ 'charon', 'down', 'reset:no answer from charon', 10000 ], 'silent charon: after 90 s down, connection reset, again in 10 s');
w.answers.hang = null;
w.fire();
eq(w.ctl.status().state, 'up', 'silent charon: the next attempt comes up');

// stop: terminate, unload, link gone, no retries any more
w = world({ 'list-sa': [ SA ] });
w.ctl.start(() => null);
w.reqs = []; w.cmds = [];
let stopped = false;
let nn = w.notified;
w.ctl.stop(() => { stopped = true; });
eq([ stopped, w.reqs, w.cmds, w.ctl.status().state, w.notified ],
	[ true, [ 'terminate', 'unload-conn' ], [], 'stopped', nn + 1 ], 'stop: terminate, unload, netifd told');
let n = length(w.timers);
w.ctl.vici_closed('x');
w.listeners['ike-updown'][0]({ up: 'no', [TUN.CONN]: {} });
eq(length(w.timers), n, 'stop: no new attempt afterwards');

done();
