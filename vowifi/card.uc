// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// The EAP-AKA card for strongSwan's ext-aka plugin: charon runs
// `/usr/libexec/strongswan/ext-aka aka <identity> <RAND hex> <AUTN hex>`
// (the feed's strongswan, patches/1000-ext-aka-plugin.patch), and this runs
// the AUTHENTICATE on the USIM in the modem whose IMSI the identity names,
// over wwand's APDU channel (ue/aka.uc, the same path IMS-AKA takes).
//
// Output, one value per line, hex: "RES …", "CK …", "IK …"; or "AUTS …"
// when the card reports a synchronisation failure. Exit 0 then; any error
// exits 1 with a line on stderr.
//
//   CARD.imsi_of('0262011234567890@nai.epc.mnc001.mcc262.3gppnetwork.org')
//   CARD.modem_of(status, imsi)      the wwand modem with that IMSI
//   CARD.run(args, call, cb(code, out_lines, err_line))
//     call(object, method, args, cb(err, res)): a ubus call

'use strict';

import * as AKA from 'ue_aka';

// the IMSI of a permanent NAI: a leading 0 (EAP-AKA, TS 23.003 19.3.2), the
// digits, the realm. A bare IMSI goes too.
export function imsi_of(identity)
{
	let m = match(identity ?? '', /^0?([0-9]{6,15})(@|$)/);
	return m ? m[1] : null;
}

// the modem whose card has that IMSI; the only one when there is one modem
// and its IMSI is not known yet
export function modem_of(status, imsi)
{
	let ms = status?.modems ?? {};
	let names = sort(keys(ms));
	for (let n in names)
		if (ms[n]?.imsi == imsi || ms[n]?.info?.imsi == imsi)
			return n;
	return (length(names) == 1 && ms[names[0]]?.imsi == null) ? names[0] : null;
}

// the card of an IMS line without a modem (sipd's card_apdu, ims_modem
// option card), as the AKA code takes it
export function sipd_card(call, obj, imsi)
{
	let base = { imsi: imsi };
	return {
		open: (aid, cb) => call(obj, 'card_apdu', { ...base, op: 'open', aid: aid },
			(err, r) => cb(err ?? (r?.channel == null ? 'no channel' : null), r?.channel)),
		send: (ch, apdu, cb) => call(obj, 'card_apdu', { ...base, op: 'send', channel: ch, apdu: apdu },
			(err, r) => cb(err ?? (r?.response == null ? 'no response' : null), r?.response)),
		close: (ch, cb) => call(obj, 'card_apdu', { ...base, op: 'close', channel: ch }, (err) => cb(err)),
	};
}

// the sipd line that holds the card with this IMSI: asks each wwand-ims.*
// object (lines() -> names); cb(obj or null)
function line_with(call, lines, imsi, cb)
{
	let names = filter(lines?.() ?? [], (n) => n != 'wwand-ims');
	let step;
	step = (i) => {
		if (i >= length(names))
			return cb(null);
		call(names[i], 'card_apdu', { imsi: imsi, op: 'close', channel: 0 }, (err) => err ? step(i + 1) : cb(names[i]));
	};
	step(0);
}

export function run(args, call, cb, lines)
{
	if (args?.[0] != 'aka' || length(args) < 4)
		return cb(1, [], 'usage: ext-aka aka <identity> <RAND hex> <AUTN hex>');
	let imsi = imsi_of(args[1]);
	let rand = match(args[2], /^[0-9a-fA-F]{32}$/) ? hexdec(args[2]) : null;
	let autn = match(args[3], /^[0-9a-fA-F]{32}$/) ? hexdec(args[3]) : null;
	if (!imsi || rand == null || autn == null)
		return cb(1, [], 'ext-aka: an identity with an IMSI, and RAND and AUTN of 16 bytes');

	call('wwand', 'status', {}, (err, st) => {
		if (err)
			return cb(1, [], sprintf('ext-aka: wwand status: %J', err));
		let auth = (card, where) => AKA.authenticate(card, AKA.AID_USIM, rand, autn, (e, r) => {
			if (e && !r)
				return cb(1, [], sprintf('ext-aka: AUTHENTICATE on %s: %J', where, e));
			if (r.sync)
				return cb(0, [ 'AUTS ' + hexenc(r.auts) ], null);
			cb(0, [ 'RES ' + hexenc(r.res), 'CK ' + hexenc(r.ck), 'IK ' + hexenc(r.ik) ], null);
		});
		let modem = modem_of(st, imsi);
		if (modem)
			return auth(AKA.wwand_card(call, modem), modem);
		// no modem has it: a line's card without a modem (sipd)
		line_with(call, lines, imsi, (obj) => obj ? auth(sipd_card(call, obj, imsi), obj)
		                                          : cb(1, [], sprintf('ext-aka: no modem or card with IMSI %s', imsi)));
	});
}
