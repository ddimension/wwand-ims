// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// A SIM card without a modem: the card behind wwand-rsim's helper rsim-card
// (a PC/SC or Smartmouse reader here, a reader or another wwand router's
// modem over SSH, a SIM bank, a phone over Bluetooth SAP — whatever its
// reader spec names). VoWiFi needs nothing else of a modem: the USIM's
// AUTHENTICATE for EAP-AKA and IMS-AKA, and the identity (IMSI, MNC length,
// ICCID) read from the card itself.
//
// rsim-card speaks one JSON line per request on stdin/stdout ({"op":
// "power_up"} -> {"ok":true,"atr":…}, {"op":"tpdu","data":"<hex>"} ->
// {"ok":true,"data":"<response hex + SW>"}; wwand-rsim helper/README.md).
// The commands are T=0 TPDUs: 61xx is answered with GET RESPONSE, 6Cxx by
// sending the command again with that Le — here, so a card() user sees the
// final answer, as over wwand's modem_apdu.
//
//   let R = READER.create({ spec, spawn, log, ssh_key, on_gone })
//   R.start(cb(err, { atr, iccid, imsi, mnc_len }))
//   R.card()        the AKA card interface (open/send/close, as AKA.wwand_card)
//   R.info()        what start() read
//   R.stop()
//
// spawn(argv, on_line, on_exit) -> { write(line), close() } (sipd: wwand_io
// spawn with pipes, the way wwand-rsim runs the helper).

'use strict';

export const HELPER = '/usr/bin/rsim-card';
export const SSH_KEY_DIR = '/etc/wwand/rsim';

function shq(s)
{
	return "'" + replace(sprintf('%s', s), /'/g, "'\\''") + "'";
}

// the helper's command line for a reader spec: a local reader, or one on
// another machine as ssh:<user>@<host>:<reader> (dropbear's ssh, as the
// router runs it; the key wwand-rsim made, `wwandctl rsim ssh-key`)
export function argv_for(spec, key)
{
	let m = match(spec ?? '', /^ssh:([A-Za-z0-9._-]+@[A-Za-z0-9._-]+):(.+)$/);
	if (!m)
		return [ HELPER, spec ];
	return [ '/usr/bin/ssh', '-T', '-y', '-K', '15', '-i', key ?? (SSH_KEY_DIR + '/id_dropbear'),
	         m[1], 'rsim-card ' + shq(m[2]) ];
}

// BCD, nibbles swapped (ICCID, IMSI), F padding dropped
function swapped_bcd(h)
{
	let out = '';
	for (let i = 0; i + 1 < length(h); i += 2)
		out += substr(h, i + 1, 1) + substr(h, i, 1);
	return replace(out, /[Ff]+$/, '');
}

// EF_IMSI (TS 31.102 4.2.2): length, then the digits swapped with the
// parity nibble first
export function imsi_of(ef_hex)
{
	if (!ef_hex || length(ef_hex) < 4)
		return null;
	let n = hex(substr(ef_hex, 0, 2));
	let d = swapped_bcd(substr(ef_hex, 2, 2 * n));
	let imsi = substr(d, 1);
	return match(imsi, /^[0-9]{6,15}$/) ? imsi : null;
}

export function iccid_of(ef_hex)
{
	let d = swapped_bcd(ef_hex ?? '');
	return match(d, /^[0-9]{10,22}$/) ? d : null;
}

// EF_AD (TS 31.102 4.2.18): byte 4, low nibble = the MNC's length
export function mnc_len_of(ef_hex)
{
	if (!ef_hex || length(ef_hex) < 8)
		return null;
	let n = hex(substr(ef_hex, 6, 2)) & 0x0F;
	return (n == 2 || n == 3) ? n : null;
}

// a UUID URN of a name (RFC 4122 name-based shape over an MD5 hex digest):
// +sip.instance for a UE without an IMEI, the same at every start
export function instance_urn(name, md5)
{
	let h = md5(name);
	return sprintf('urn:uuid:%s-%s-3%s-%x%s-%s', substr(h, 0, 8), substr(h, 8, 4), substr(h, 13, 3),
		(hex(substr(h, 16, 1)) & 0x3) | 0x8, substr(h, 17, 3), substr(h, 20, 12));
}

function sw_of(r)
{
	return (r && length(r) >= 4) ? uc(substr(r, length(r) - 4)) : null;
}

// the helper as a line channel: wwand_io spawn with pipes, stdout read from
// uloop line by line (as wwand-rsim runs it)
export function spawn_lines(io, uloop, argv, on_line, on_exit)
{
	let h = io?.spawn(argv);
	if (!h)
		return null;
	let buf = '', uh = null, wq = '', wtimer = null, gone = false;
	let finish = () => {
		if (gone)
			return;
		gone = true;
		wtimer?.cancel();
		uh?.delete();
		h.close();
		on_exit();
	};
	let pump;
	pump = () => {
		wtimer = null;
		while (length(wq)) {
			let n = h.write(wq);
			if (n === false)
				return finish();
			if (n === null || n === 0)
				return (wtimer = uloop.timer(20, pump));
			wq = substr(wq, n);
		}
	};
	uh = uloop.handle(h.fileno(), () => {
		for (;;) {
			let chunk = h.read();
			if (chunk === false)
				return finish();
			if (chunk == null || chunk === '')
				break;
			buf += chunk;
		}
		let i;
		while ((i = index(buf, '\n')) >= 0) {
			let line = substr(buf, 0, i);
			buf = substr(buf, i + 1);
			if (length(line))
				on_line(line);
		}
	}, uloop.ULOOP_READ);
	return {
		write: (line) => {
			if (gone)
				return;
			wq += line;
			if (!wtimer)
				pump();
		},
		// EOF on its stdin powers the card down and ends rsim-card; the kill
		// is for one that does not
		close: () => {
			if (gone)
				return;
			let hh = h;
			uh?.delete();
			uh = null;
			gone = true;
			wtimer?.cancel();
			uloop.timer(2000, () => { hh.kill(); hh.close(); });
		},
	};
}

export function create(o)
{
	let self = {};
	let log = o.log ?? (() => null);
	let h = null, queue = [], cur = null, inf = null, closed = false;

	let fail_all = (why) => {
		let q = cur ? [ cur, ...queue ] : queue;
		cur = null;
		queue = [];
		for (let x in q)
			x.cb({ error: 'card', detail: why }, null);
	};

	let next;
	next = () => {
		if (cur || !length(queue) || !h)
			return;
		cur = shift(queue);
		h.write(sprintf('%J\n', cur.req));
	};

	let on_line = (line) => {
		let msg = null;
		try { msg = json(line); } catch (e) { msg = null; }
		if (type(msg) != 'object' || msg.event != null)
			return;	// the helper's own news (card removed/inserted)
		let c = cur;
		cur = null;
		if (c)
			c.cb((msg.ok === false) ? { error: 'card', detail: msg.error ?? 'refused' } : null, msg);
		next();
	};

	let open_helper = () => {
		if (h)
			return true;
		h = o.spawn(argv_for(o.spec, o.ssh_key), on_line, () => {
			h = null;
			if (!closed)
				log('warn', sprintf('card %s: rsim-card ended', o.spec));
			fail_all('rsim-card ended');
			// a new helper would talk to an unpowered card: the owner starts over
			if (!closed)
				o.on_gone?.();
		});
		return h != null;
	};

	let call = (req, cb) => {
		if (!open_helper())
			return cb({ error: 'card', detail: 'cannot run rsim-card' }, null);
		push(queue, { req: req, cb: cb });
		next();
	};

	// one command with T=0's follow-ups resolved: the response data + SW
	let tpdu;
	tpdu = (apdu, cb, data) => call({ op: 'tpdu', data: apdu }, (err, r) => {
		if (err)
			return cb(err, null);
		let resp = uc(r?.data ?? '');
		let sw = sw_of(resp);
		if (sw == null)
			return cb({ error: 'card', detail: 'no status word' }, null);
		let body = (data ?? '') + substr(resp, 0, length(resp) - 4);
		if (substr(sw, 0, 2) == '61')
			// GET RESPONSE on the command's channel (its CLA's low bits)
			return tpdu(sprintf('%02XC00000%s', hex(substr(apdu, 0, 2)) & 0x03, substr(sw, 2)), cb, body);
		if (substr(sw, 0, 2) == '6C')
			return tpdu(substr(apdu, 0, 8) + substr(sw, 2), cb, data);
		cb(null, body + sw);
	});

	let ok_sw = (r) => (sw_of(r) == '9000' || substr(sw_of(r) ?? '', 0, 2) == '91');

	// a transparent EF's contents: SELECT by FID in the current DF/ADF, READ
	// BINARY of its size (or `len`)
	let read_ef = (fid, len, cb) => tpdu('00A40004' + '02' + fid, (e, r) => {
		if (e || !ok_sw(r))
			return cb(e ?? { error: 'card', detail: sprintf('SELECT %s: %s', fid, sw_of(r)) }, null);
		tpdu(sprintf('00B00000%02X', len), (e2, r2) =>
			(e2 || !ok_sw(r2)) ? cb(e2 ?? { error: 'card', detail: sprintf('READ %s: %s', fid, sw_of(r2)) }, null)
			                   : cb(null, substr(r2, 0, length(r2) - 4)));
	});

	self.start = function(cb) {
		call({ op: 'power_up' }, (err, r) => {
			if (err)
				return cb(err, null);
			let i = { atr: r?.atr };
			// ICCID under the MF, then the USIM ADF's IMSI and AD
			tpdu('00A40004023F00', () => read_ef('2FE2', 10, (e, iccid) => {
				i.iccid = e ? null : iccid_of(iccid);
				tpdu('00A4040407A0000000871002', (e2, r2) => {
					if (e2 || !ok_sw(r2))
						return cb(e2 ?? { error: 'card', detail: 'no USIM application' }, null);
					read_ef('6F07', 9, (e3, ef) => {
						i.imsi = e3 ? null : imsi_of(ef);
						if (!i.imsi)
							return cb({ error: 'card', detail: 'no IMSI on the card' }, null);
						read_ef('6FAD', 4, (e4, ad) => {
							i.mnc_len = e4 ? null : mnc_len_of(ad);
							inf = i;
							cb(null, i);
						});
					});
				});
			}));
		});
	};

	self.info = () => inf;

	// the card the AKA code takes (ue/aka.uc authenticate): the USIM on the
	// basic channel — the card is ours alone, no logical channel needed
	self.card = () => ({
		open: (aid, cb) => tpdu(sprintf('00A40404%02X%s', length(aid) / 2, aid), (e, r) =>
			cb(e ?? (ok_sw(r) ? null : sprintf('SELECT %s: %s', aid, sw_of(r))), 0)),
		send: (ch, apdu, cb) => tpdu(apdu, (e, r) => cb(e, r)),
		close: (ch, cb) => cb(null),
	});

	// the same for another process (vowifi's ext-aka through sipd's ubus):
	// { op: open|send|close, aid, channel, apdu } -> { channel } / { response }
	self.apdu = function(req, cb) {
		let c = self.card();
		if (req?.op == 'open')
			return c.open(req.aid, (e, ch) => cb(e, e ? null : { channel: ch }));
		if (req?.op == 'send')
			return c.send(req.channel, req.apdu, (e, r) => cb(e, e ? null : { response: r }));
		if (req?.op == 'close')
			return c.close(req.channel, (e) => cb(e, {}));
		cb({ error: 'card', detail: 'unknown op' }, null);
	};

	self.stop = function() {
		closed = true;
		if (h) {
			h.write(sprintf('%J\n', { op: 'power_down' }));
			h.close();
		}
		h = null;
	};

	return self;
}
