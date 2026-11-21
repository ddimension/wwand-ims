// Host tests for ue/reader.uc: rsim-card's line protocol against a
// simulated card (T=0: 61xx answered with GET RESPONSE, 6Cxx resent), the
// identity read from the card (ICCID, IMSI, MNC length), the card interface
// the AKA code takes, the helper's command line. Made-up identifiers.
'use strict';

import { eq, ok, done } from './lib/check.uc';
import * as R from 'ue_reader';

// decoders (TS 31.102)
eq(R.imsi_of('082926990000000010'), '262990000000001', 'imsi_of: EF_IMSI, parity nibble first, swapped');
eq(R.iccid_of('98942009000000000010'), '89490290000000000001', 'iccid_of: swapped BCD');
eq(R.mnc_len_of('00000002'), 2, 'mnc_len_of: EF_AD byte 4');
eq(R.mnc_len_of('000000'), null, 'mnc_len_of: an AD without the MNC length');

eq(R.argv_for('pcsc:0'), [ '/usr/bin/rsim-card', 'pcsc:0' ], 'argv_for: a local reader');
eq(R.argv_for('ssh:root@192.0.2.1:wwand:iccid:8949'), [ '/usr/bin/ssh', '-T', '-y', '-K', '15', '-i',
	'/etc/wwand/rsim/id_dropbear', 'root@192.0.2.1', "rsim-card 'wwand:iccid:8949'" ], 'argv_for: over SSH');

// a card behind a fake rsim-card: answers in T=0, keeps what was selected
function card()
{
	let c = { sent: [], pending: '', df: 'MF' };
	let EF = { '2FE2': '98942009000000000010', '6F07': '082926990000000010', '6FAD': '00000002' };
	let answer = (t) => {
		push(c.sent, t);
		if (substr(t, 0, 8) == '00A40004') {
			let fid = substr(t, 10, 4);
			if (fid == '3F00' || EF[fid]) {
				c.ef = fid;
				c.pending = '621E8202412183022FE2';
				return '61' + sprintf('%02X', length(c.pending) / 2);
			}
			return '6A82';
		}
		if (substr(t, 0, 8) == '00A40404') {
			c.pending = '6F1A84';
			return '6103';
		}
		if (substr(t, 0, 6) == '00C000') {
			let p = c.pending;
			c.pending = '';
			return p + '9000';
		}
		if (substr(t, 0, 4) == '00B0') {
			let want = hex(substr(t, 8, 2)), d = EF[c.ef] ?? '';
			if (want != length(d) / 2)
				return sprintf('6C%02X', length(d) / 2);
			return d + '9000';
		}
		if (substr(t, 0, 4) == '0088') {
			c.pending = 'DB08' + 'AABBCCDDEEFF0011' + '10' + '00112233445566778899AABBCCDDEEFF' + '10' + 'FFEEDDCCBBAA99887766554433221100';
			return sprintf('61%02X', length(c.pending) / 2);
		}
		return '6D00';
	};
	c.spawn = (argv, on_line, on_exit) => {
		c.argv = argv;
		return {
			write: (line) => {
				let req = json(line);
				if (req.op == 'power_up')
					return on_line('{"ok":true,"atr":"3B9F96"}');
				if (req.op == 'power_down')
					return on_line('{"ok":true}');
				if (req.op == 'tpdu')
					return on_line(sprintf('%J', { ok: true, data: answer(req.data) }));
			},
			close: () => { c.closed = true; },
			die: () => on_exit(),
		};
	};
	return c;
}

let c = card();
let r = R.create({ spec: 'pcsc:0', spawn: c.spawn });
let info = null, err = 'unset';
r.start((e, i) => { err = e; info = i; });
eq([ err, info ], [ null, { atr: '3B9F96', iccid: '89490290000000000001', imsi: '262990000000001', mnc_len: 2 } ],
	'start: the card powered up, ICCID, IMSI and MNC length read from it');
ok(length(filter(c.sent, (t) => substr(t, 0, 6) == '00C000')) >= 3, 'start: 61xx answered with GET RESPONSE');
ok(length(filter(c.sent, (t) => match(t, /^00B0/))) >= 3, 'start: READ BINARY of each EF');

// the AKA card interface: open the USIM, an AUTHENTICATE resolved through 61xx
let ch = 'unset', resp = null;
r.card().open('a0000000871002', (e, x) => { ch = e ?? x; });
r.card().send(0, '00880081221011223344556677889900AABBCCDDEEFF', (e, x) => { resp = x; });
eq(ch, 0, 'card: the USIM on the basic channel');
ok(match(resp ?? '', /^DB08AABBCCDDEEFF0011.*9000$/), 'card: AUTHENTICATE answered with RES/CK/IK and 9000');

// over ubus (ext-aka): the same shape as wwand's modem_apdu
let got = null;
r.apdu({ op: 'open', aid: 'a0000000871002' }, (e, x) => { got = x; });
eq(got, { channel: 0 }, 'apdu: open -> channel');
r.apdu({ op: 'send', channel: 0, apdu: '00A40004023F00' }, (e, x) => { got = x; });
ok(match(got?.response ?? '', /9000$/), 'apdu: send -> response with SW');

r.stop();
ok(c.closed, 'stop: the helper closed');

// the helper ends under a running line: pending requests fail, the owner is told
let gone = 0, c3 = card(), h3 = null;
let r3 = R.create({ spec: 'pcsc:0', on_gone: () => gone++, spawn: (a, l, x) => (h3 = c3.spawn(a, l, x)) });
r3.start((e, i) => null);
h3.die();
eq(gone, 1, 'helper gone: on_gone called');
r3.stop();

// a card without the USIM application
let c2 = card();
let s0 = c2.spawn;
let r2 = R.create({ spec: 'pcsc:0', spawn: (a, l, x) => {
	let h = s0(a, l, x);
	let w = h.write;
	h.write = (line) => (index(line, '00A40404') >= 0) ? l('{"ok":true,"data":"6A82"}') : w(line);
	return h;
} });
r2.start((e, i) => { err = e; });
eq(err?.detail, 'no USIM application', 'start: a card without a USIM');

// +sip.instance without an IMEI: a UUID URN, the same for the same name
let fake_md5 = (s) => '0123456789abcdef0123456789abcdef';
eq(R.instance_urn('x', fake_md5), 'urn:uuid:01234567-89ab-3def-8123-456789abcdef', 'instance_urn: a version-3 shaped UUID');

done();
