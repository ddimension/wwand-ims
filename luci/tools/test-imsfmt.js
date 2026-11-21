#!/usr/bin/env node
/* Checks for the pure helper resources/wwand/imsfmt.js, evaluated the way
 * wwand-ipa's tools/test-ipafmt.js does it: as a function body with the few
 * globals LuCI provides, no DOM. Run by tests/run.sh when node is there.
 *
 *   node luci/tools/test-imsfmt.js
 * All numbers are made-up example values.
 */
'use strict';

process.env.TZ = 'UTC';

const fs = require('fs');
const path = require('path');

const src = fs.readFileSync(path.join(__dirname, '..', 'htdocs', 'luci-static', 'resources', 'wwand', 'imsfmt.js'), 'utf8')
	.replace(/^\s*'require [^']*';\s*$/gm, '');

/* LuCI's String.prototype.format, reduced to the %s and %d the helper uses */
String.prototype.format = function () {
	let args = arguments, i = 0;
	return this.replace(/%([sd%])/g, (m, c) => (c == '%') ? '%' : (c == 'd' ? String(Math.trunc(+args[i++]) || 0) : String(args[i++])));
};

const fmt = new Function('baseclass', '_', src)({ extend: (o) => o }, (s) => s);

let checks = 0, failures = 0;
function eq(got, want, label) {
	checks++;
	if (JSON.stringify(got) !== JSON.stringify(want)) {
		failures++;
		console.log(`FAIL: ${label}\n  got:  ${JSON.stringify(got)}\n  want: ${JSON.stringify(want)}`);
	}
}

const T = 1763690000;	/* 2025-11-21 01:53:20 UTC */

eq([ fmt.dur(45), fmt.dur(720), fmt.dur(11100), fmt.dur(-3) ], [ '45s', '12m 0s', '3h 5m', '0s' ], 'dur');
eq(fmt.when(T, T + 60), '01:53:20', 'when: today -> the time only');
eq(fmt.when(T, T + 86400), '2025-11-21 01:53:20', 'when: another day -> with the date');
eq(fmt.when(null, T), '-', 'when: none');
eq([ fmt.number(null), fmt.number('+4915550000001') ], [ 'withheld', '+4915550000001' ], 'number');
eq(fmt.packets({ up: 421, down: 122 }), '421 ↑ / 122 ↓', 'packets');
eq([ fmt.result('missed'), fmt.result_class('missed'), fmt.result_class('answered'), fmt.result_class('declined') ],
	[ 'missed', 'danger', 'success', 'notice' ], 'result and its badge');

eq(fmt.ue_rows({ ue: { state: 'registered', impu: 'sip:+4915550000001@ims.example', ue_addr: '2001:db8::5',
                       pcscf: '2001:db8:ff::10', expires: 7190, profile: null, reg_event: 'active' } }), [
	[ 'Registration', 'registered' ], [ 'Public identity', 'sip:+4915550000001@ims.example' ],
	[ 'UE address', '2001:db8::5' ], [ 'P-CSCF', '2001:db8:ff::10' ], [ 'Registration expiry', '1h 59m' ],
	[ 'Operator profile', 'built-in defaults' ], [ 'SMS over IMS', 'off' ], [ 'Registration events', 'subscribed' ] ], 'ue_rows');
eq(fmt.ue_rows({ ue: null }), [], 'ue_rows: backend qmi has none');

eq(fmt.vowifi_rows({ vowifi: { state: 'up', epdg: 'epdg.example.net', v6: '2001:db8:aa::2', v4: null,
                                pcscf: [ '2001:db8:ff::10', '2001:db8:ff::11' ], dev: 'imswifi0' } }), [
	[ 'Tunnel', 'up' ], [ 'ePDG', 'epdg.example.net' ], [ 'Inner address', '2001:db8:aa::2' ],
	[ 'P-CSCF', '2001:db8:ff::10, 2001:db8:ff::11' ], [ 'Interface', 'imswifi0' ] ], 'vowifi_rows: up');
eq(fmt.vowifi_rows({ vowifi: { state: 'down', error: 'establishing CHILD_SA failed', dev: 'imswifi0', vrf: 'imswifi' } }).pop(),
	[ 'Last error', 'establishing CHILD_SA failed' ], 'vowifi_rows: down with its error');
eq(fmt.vowifi_rows({ vowifi: null }), [], 'vowifi_rows: none over the IMS PDN');

eq(fmt.gw_rows({ backend: 'ue', modem: 'wwmodem0', listen: '192.168.1.1', port: 5060, started: T, now: T + 90 }), [
	[ 'Backend', 'router IMS UE' ], [ 'Modem', 'wwmodem0' ], [ 'SIP listener', '192.168.1.1:5060' ],
	[ 'Running for', '1m 30s' ] ], 'gw_rows');
eq(fmt.gw_rows({ line: 'ue2', backend: 'ue', modem: 'wwmodem1', listen: '192.168.1.1', port: 5061, sim: 'vf_card' })
	.map(function(r) { return r[0]; }), [ 'Line', 'Backend', 'Modem', 'SIP listener', 'SIM settings' ], 'gw_rows: the line and its SIM settings');

eq(fmt.ext_rows({ extensions: { phone: { registered: true, address: '192.168.1.20', port: 5062, transport: 'UDP', expires: 3500 },
                                 fax: { registered: false } } }), [
	[ 'fax', 'not registered', '-', '-' ],
	[ 'phone', 'registered', '192.168.1.20:5062 (UDP)', '58m 20s' ] ], 'ext_rows: sorted, unregistered ones too');

eq(fmt.call_rows({ now: T + 40, call: { dir: 'in', number: '+4915550000002', extension: 'phone', state: 'up',
                                        start: T, answered: T + 10, codec: 'AMR-WB', packets: { up: 5, down: 7 } } }), [
	[ 'Direction', '↙ incoming' ], [ 'Number', '+4915550000002' ], [ 'Extension', 'phone' ],
	[ 'State', 'connected' ], [ 'Started', '01:53:20' ], [ 'Talking for', '30s' ], [ 'Codec', 'AMR-WB' ],
	[ 'RTP packets', '5 ↑ / 7 ↓' ] ], 'call_rows: a call in progress');
eq(fmt.call_rows({ now: T + 4, call: { dir: 'out', number: '+4915550000003', state: 'ringing', start: T } })[5],
	[ 'Ringing for', '4s' ], 'call_rows: not answered yet');
eq(fmt.call_rows({ call: null }), [], 'call_rows: none');

eq(fmt.history_rows([
	{ start: T, answered: T + 5, end: T + 65, dir: 'in', number: '+4915550000002', extension: 'phone',
	  result: 'answered', reason: 'IMS side ended (remote)', codec: 'AMR-WB' },
	{ start: T - 100, end: T - 90, dir: 'out', number: '+4915550000003', result: 'failed', reason: 'dial failed' },
], T + 70), [
	[ '01:53:20', '↙ incoming', '+4915550000002', 'phone', 'answered', '1m 0s', 'AMR-WB', 'IMS side ended (remote)', 'answered' ],
	[ '01:51:40', '↗ outgoing', '+4915550000003', '-', 'failed', '-', '-', 'dial failed', 'failed' ] ], 'history_rows');
eq(fmt.history_rows(null, T), [], 'history_rows: none');

/* the views parse (LuCI evaluates them as function bodies, as here) */
for (const v of [ 'ims-status.js', 'ims-config.js' ]) {
	checks++;
	try {
		new Function(fs.readFileSync(path.join(__dirname, '..', 'htdocs', 'luci-static', 'resources', 'view', 'wwand', v), 'utf8'));
	} catch (e) {
		failures++;
		console.log(`FAIL: view ${v} does not parse: ${e.message}`);
	}
}

console.log(`test-imsfmt: ${checks} checks, ${failures} failures`);
process.exit(failures ? 1 : 0);
