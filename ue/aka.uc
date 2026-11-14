// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// IMS-AKA on the router: the USIM AUTHENTICATE (3GPP TS 31.102 7.1.2, 3G
// context), the Digest AKAv1-MD5 nonce and password (RFC 3310), and the IMS
// identities derived from the IMSI (3GPP TS 23.003 13.3, 13.4b).
//
// The card is reached through wwand's raw APDU channel
// (`ubus call wwand modem_apdu {modem, op: open|send|close, ...}`): a logical
// channel of its own to the USIM, so the modem's session on the basic channel
// is not touched. The transport is passed in as { open, send, close } with
// callbacks, so the host tests can stand in for the card.

'use strict';

// partial AIDs (ISO 7816-4 selection by the first bytes of the DF name);
// RID A000000087 = 3GPP, application code 1002 = USIM, 1004 = ISIM
// (ETSI TS 101 220 Annex E)
export const AID_USIM = 'a0000000871002';
export const AID_ISIM = 'a0000000871004';

export const RAND_LEN = 16;
export const AUTN_LEN = 16;
export const AUTS_LEN = 14;

// ucode has no function hoisting: helpers stay above their first use
export function hex(s)
{
	return hexenc(s ?? '');
}

export function unhex(h)
{
	h = lc(h ?? '');
	if (length(h) % 2 || match(h, /[^0-9a-f]/))
		return null;
	return length(h) ? hexdec(h) : '';
}

// ISO 7816-4 5.4.1: logical channels 0-3 sit in the low bits of a first
// interindustry CLA, 4-19 in a further interindustry CLA (0x40 | ch - 4)
export function cla(channel)
{
	channel = +(channel ?? 0);
	if (channel < 0 || channel > 19)
		return null;
	return channel < 4 ? channel : (0x40 | (channel - 4));
}

// AUTHENTICATE, P2 0x81 = 3G/IMS security context (TS 31.102 7.1.2.1),
// data = L RAND || L AUTN, Le 00
export function authenticate_apdu(channel, rand, autn)
{
	if (length(rand) != RAND_LEN || length(autn) != AUTN_LEN || cla(channel) == null)
		return null;
	return sprintf('%02x880081%02x%02x%s%02x%s00', cla(channel), 2 + RAND_LEN + AUTN_LEN,
		RAND_LEN, hex(rand), AUTN_LEN, hex(autn));
}

// the status word of a response in hex, and the data before it
export function split_sw(resp_hex)
{
	resp_hex = lc(resp_hex ?? '');
	if (length(resp_hex) < 4 || length(resp_hex) % 2)
		return null;
	return { data: substr(resp_hex, 0, length(resp_hex) - 4), sw: substr(resp_hex, -4) };
}

// T=0 procedure bytes the card may answer with before the data:
// 61xx = xx bytes ready (GET RESPONSE), 6Cxx = wrong Le, send again with xx.
// Returns the next APDU, or null when the response is final.
export function followup(channel, last_apdu, sw)
{
	let sw1 = substr(sw, 0, 2), sw2 = substr(sw, 2, 2);

	if (sw1 == '61')
		return sprintf('%02xc00000%s', cla(channel), sw2);
	if (sw1 == '6c')
		return substr(last_apdu, 0, length(last_apdu) - 2) + sw2;
	return null;
}

// the AUTHENTICATE answer (TS 31.102 7.1.2.1):
//   DB L RES L CK L IK [L Kc]  -> { res, ck, ik, kc? }   (binary strings)
//   DC L AUTS                  -> { sync: true, auts }
//   SW 9862                    -> { error: 'mac' }       (AUTN MAC wrong)
export function parse_authenticate(data_hex, sw)
{
	if (sw == '9862')
		return { error: 'mac' };
	if (sw != '9000')
		return { error: 'status', sw: sw };

	let d = unhex(data_hex);

	if (d == null || length(d) < 2)
		return { error: 'short' };

	let tag = ord(d, 0), off = 1;
	let take = () => {
		if (off >= length(d))
			return null;
		let n = ord(d, off);
		if (off + 1 + n > length(d))
			return null;
		let v = substr(d, off + 1, n);
		off += 1 + n;
		return v;
	};

	if (tag == 0xdc) {
		let auts = take();
		return (auts != null && length(auts) == AUTS_LEN) ? { sync: true, auts: auts } : { error: 'short' };
	}

	if (tag != 0xdb)
		return { error: 'tag', tag: sprintf('%02x', tag) };

	let res = take(), ck = take(), ik = take();

	if (res == null || length(res) < 4 || length(res) > 16 || length(ck) != 16 || length(ik) != 16)
		return { error: 'short' };

	let out = { res: res, ck: ck, ik: ik };
	let kc = take();
	if (kc != null && length(kc) == 8)
		out.kc = kc;
	return out;
}

// One AUTHENTICATE over `card` ({ open(aid, cb), send(channel, apdu, cb),
// close(channel, cb) }, cb(err, value)): open a channel to the USIM, run the
// command and its T=0 follow-ups, close the channel. cb(err, result) with
// result as parse_authenticate gives it. The channel is closed on every path.
export function authenticate(card, aid, rand, autn, cb)
{
	card.open(aid ?? AID_USIM, (err, ch) => {
		if (err)
			return cb({ error: 'open', detail: err }, null);

		let finish = (e, r) => card.close(ch, () => cb(e, r));
		let apdu = authenticate_apdu(ch, rand, autn);

		if (apdu == null)
			return finish({ error: 'args' }, null);

		let rounds = 0, step;
		step = (cmd) => card.send(ch, cmd, (e, resp) => {
			if (e)
				return finish({ error: 'send', detail: e }, null);

			let r = split_sw(resp);
			if (!r)
				return finish({ error: 'response', detail: resp }, null);

			let next = followup(ch, cmd, r.sw);
			if (next && ++rounds <= 4)
				return step(next);

			let p = parse_authenticate(r.data, r.sw);
			finish(p.error ? p : null, p.error ? null : p);
		});

		step(apdu);
	});
}

// The wwand ubus APDU channel as a card for authenticate().
// `call(object, method, args, cb)` is the caller's ubus invocation, so this
// module does not need a ubus connection of its own.
export function wwand_card(call, modem, slot)
{
	let base = { modem: modem };
	if (slot)
		base.slot = +slot;

	return {
		open: (aid, cb) => call('wwand', 'modem_apdu', { ...base, op: 'open', aid: aid },
			(err, r) => cb(err ?? (r?.channel == null ? 'no channel' : null), r?.channel)),
		send: (ch, apdu, cb) => call('wwand', 'modem_apdu', { ...base, op: 'send', channel: ch, apdu: apdu },
			(err, r) => cb(err ?? (r?.response == null ? 'no response' : null), r?.response)),
		close: (ch, cb) => call('wwand', 'modem_apdu', { ...base, op: 'close', channel: ch },
			(err) => cb(err)),
	};
}

// ---- Digest AKAv1-MD5 (RFC 3310) -------------------------------------------

// nonce = base64(RAND || AUTN || server data)
export function nonce_split(nonce_b64)
{
	let n = b64dec(nonce_b64 ?? '');

	if (n == null || length(n) < RAND_LEN + AUTN_LEN)
		return null;
	return {
		rand: substr(n, 0, RAND_LEN),
		autn: substr(n, RAND_LEN, AUTN_LEN),
		server_data: substr(n, RAND_LEN + AUTN_LEN),
	};
}

// AKAv1: the Digest password is RES itself, as bytes (RFC 3310 3.3)
export function akav1_password(res)
{
	return res;
}

// the auts parameter of the Authorization after a sync failure (RFC 3310 3.4)
export function auts_param(auts)
{
	return b64enc(auts);
}

// ---- identities (TS 23.003) ------------------------------------------------

// the home network domain from the IMSI: ims.mnc<MNC, 3 digits>.mcc<MCC>.
// 3gppnetwork.org (13.2). mnc_len is EF_AD byte 4 (2 or 3), it is not
// derivable from the IMSI alone.
export function home_domain(imsi, mnc_len)
{
	if (!match(imsi ?? '', /^[0-9]{6,15}$/) || (mnc_len != 2 && mnc_len != 3))
		return null;
	let mcc = substr(imsi, 0, 3), mnc = substr(imsi, 3, mnc_len);
	return sprintf('ims.mnc%03d.mcc%s.3gppnetwork.org', +mnc, mcc);
}

// private and temporary public identity without an ISIM (13.3, 13.4b)
export function identities(imsi, mnc_len)
{
	let domain = home_domain(imsi, mnc_len);

	if (!domain)
		return null;
	return {
		domain: domain,
		impi: sprintf('%s@%s', imsi, domain),
		impu: sprintf('sip:%s@%s', imsi, domain),
		realm: domain,
	};
}
