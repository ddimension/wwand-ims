// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// SMS over IP (3GPP TS 24.341) for the router's own IMS UE: SIP MESSAGE with
// Content-Type application/vnd.3gpp.sms, whose body is an RP message of the
// SMS relay layer (TS 24.011 7.3) carrying the TPDU (TS 23.040).
//
// MT: the network's MESSAGE holds an RP-DATA (network -> MS) with the SC
//     address and an SMS-DELIVER. We answer the MESSAGE with 200, hand the
//     SMS to o.deliver (wwand writes it into the modem's store,
//     `modem_sms_deliver`), and send the delivery report as a MESSAGE of our
//     own: RP-ACK, or RP-ERROR "memory capacity exceeded" when the store did
//     not take it, so the SC tries again later (TS 24.341 5.3.2.4/5.3.2.5: to the SC the network
//     named, In-Reply-To the received Call-ID).
// MO: each part (o.encode_submit, wwand's sms_pdu) goes as an RP-DATA (MS ->
//     network) in a MESSAGE to the SC; the network takes it with 202 and
//     sends the result as a MESSAGE with RP-ACK or RP-ERROR for its message
//     reference, which we answer with 200 (TS 24.341 5.3.1).
//
// WHAT IS NOT MEASURED YET: the headers and the response codes follow the
// specification as written down here, not a trace of a network. Before
// relying on it, check them against one (option sip_trace) — the Request-URI
// of the MO MESSAGE in particular (`psi`: a tel URI of the SC by default).
//
//   let s = SMSIP.create({ ue_addr, port_c, port_s, pcscf: { addr, port_s }, route,
//                          impu, pani, sec_verify, timer, send, log, t1, t2, user_agent,
//                          smsc () -> '+49…' | null, psi (smsc) -> uri, encode_submit,
//                          deliver (pdu_hex, cb(err)), on_smsc (number) })
//   s.on_message(buf) -> true when it was an SMS message or the answer to one
//   s.send(number, text, cb(err, { parts, refs }))
//   s.close()
//
// No sockets and no timers of its own, as in ue/reg.uc.

'use strict';

import * as fs from 'fs';
import { hostport } from 'ue_reg';

let SIP = require('sipd_sip');

export const CTYPE = 'application/vnd.3gpp.sms';

// RP message types (TS 24.011 8.2.2): MS -> network even, network -> MS odd
export const RP = { DATA_MS: 0, DATA_N: 1, ACK_MS: 2, ACK_N: 3, ERROR_MS: 4, ERROR_N: 5, SMMA_MS: 6 };
const RP_UD_IEI = 0x41;

// RP causes we send (TS 24.011 8.2.5.4)
export const CAUSE = { MEMORY_EXCEEDED: 22, PROTOCOL_ERROR: 111, UNSPECIFIED: 41 };

// how long the network has to send the RP-ACK of an MO part (TS 24.011 TR1M:
// 35 to 45 s)
const TR1M_MS = 45000;

function rnd_hex(n)
{
	let f = fs.open('/dev/urandom', 'r');
	let b = f ? f.read(n) : null;
	if (f)
		f.close();
	return hexenc(b ?? sprintf('%016x', time()));
}

function bytes(s)
{
	let out = [];
	for (let i = 0; i < length(s ?? ''); i++)
		push(out, ord(s, i));
	return out;
}

function str(a)
{
	return join('', map(a, (x) => chr(x)));
}

// ---- the RP layer ------------------------------------------------------------------

// an RP address value (TS 24.011 8.2.5.1/8.2.5.2): type of number + BCD,
// semi-octets swapped, F-padded. '+49…' is international (0x91). As bytes,
// without its length octet.
export function address_value(number)
{
	if (number == null || number == '')
		return [];
	let intl = substr(number, 0, 1) == '+';
	let d = intl ? substr(number, 1) : number;
	if (!match(d, /^[0-9]+$/))
		return null;
	let out = [ intl ? 0x91 : 0x81 ];
	for (let i = 0; i < length(d); i += 2) {
		let lo = +substr(d, i, 1);
		let hi = (i + 1 < length(d)) ? +substr(d, i + 1, 1) : 0x0f;
		push(out, (hi << 4) | lo);
	}
	return out;
}

// the value of an RP address back to '+49…'
export function address_number(v)
{
	if (!length(v ?? []))
		return null;
	let digits = '';
	for (let i = 1; i < length(v); i++) {
		digits += sprintf('%d', v[i] & 0x0f);
		if ((v[i] >> 4) != 0x0f)
			digits += sprintf('%d', v[i] >> 4);
	}
	return (((v[0] >> 4) & 0x07) == 1 ? '+' : '') + digits;
}

// RP-DATA MS -> network: MTI, MR, RP-OA (empty), RP-DA (the SC), RP-UD (the TPDU)
export function rp_data_mo(mr, smsc, tpdu)
{
	let da = address_value(smsc);
	if (da == null || !length(da))
		return null;
	return str([ RP.DATA_MS, mr & 0xff, 0x00, length(da), ...da, length(tpdu), ...tpdu ]);
}

// RP-ACK MS -> network for an SMS-DELIVER, with its SMS-DELIVER-REPORT (TP-MTI
// 00, no parameters: TS 23.040 9.2.2.1a)
export function rp_ack_mo(mr)
{
	return str([ RP.ACK_MS, mr & 0xff, RP_UD_IEI, 0x02, 0x00, 0x00 ]);
}

// RP-ERROR MS -> network: the cause, and the SMS-DELIVER-REPORT for an error
// (TP-FCS D3 "memory capacity exceeded" with cause 22, else FF unspecified)
export function rp_error_mo(mr, cause)
{
	let fcs = (cause == CAUSE.MEMORY_EXCEEDED) ? 0xd3 : 0xff;
	return str([ RP.ERROR_MS, mr & 0xff, 0x01, cause & 0x7f, RP_UD_IEI, 0x03, 0x00, fcs, 0x00 ]);
}

// an RP message -> { mti, mr, oa, da, ud, cause } (oa/da/ud as byte lists),
// or null when it is too short for what its type says
export function rp_parse(body)
{
	let a = bytes(body);
	if (length(a) < 2)
		return null;
	let m = { mti: a[0] & 0x07, mr: a[1] };
	let p = 2;
	let take = () => {
		if (p >= length(a))
			return null;
		let n = a[p++];
		if (p + n > length(a))
			return null;
		let v = slice(a, p, p + n);
		p += n;
		return v;
	};

	if (m.mti == RP.DATA_N || m.mti == RP.DATA_MS) {
		m.oa = take();
		m.da = (m.oa != null) ? take() : null;
		m.ud = (m.da != null) ? take() : null;
		return (m.ud != null) ? m : null;
	}
	if (m.mti == RP.ERROR_N || m.mti == RP.ERROR_MS) {
		let c = take();
		if (c == null || !length(c))
			return null;
		m.cause = c[0] & 0x7f;
	}
	// RP-ACK / RP-ERROR: an optional RP-User-Data IE
	if (p < length(a) && a[p] == RP_UD_IEI) {
		p++;
		m.ud = take();
	}
	return m;
}

// the hex PDU wwand stores and decodes (sms_pdu.decode_deliver): the SC
// address as an SMSC field (length in octets, type, BCD), then the TPDU
export function deliver_pdu(oa, tpdu)
{
	return hexenc(str([ length(oa ?? []), ...(oa ?? []), ...tpdu ]));
}

// ---- the UE side -------------------------------------------------------------------

export function create(o)
{
	let self = { closed: false };
	let log = o.log ?? (() => null);
	let timer = o.timer;
	let t1 = o.t1 ?? 500, t2 = o.t2 ?? 4000;
	let default_route = length(o.route ?? []) ? o.route : [ sprintf('<sip:%s;lr>', hostport(o.pcscf.addr, o.pcscf.port_s)) ];
	let txs = {};		// Call-ID -> our MESSAGE's client transaction
	let waits = {};	// RP message reference -> { done, timer } (MO: the RP-ACK to come)
	let seen = {};		// Call-ID|CSeq of the MT MESSAGEs taken: a retransmission is not a second SMS
	let mr_next = 0;

	let tx_stop = (id) => {
		let t = txs[id];
		if (!t)
			return;
		t.retx?.cancel();
		t.timer_f?.cancel();
		delete txs[id];
	};

	// one non-INVITE client transaction over UDP (RFC 3261 17.1.2): E from
	// T1 doubling up to T2, F after 64*T1. cb(response or null on timeout)
	let transmit = (id, buf, cb) => {
		let t = { buf: buf, wait: t1, cb: cb };
		txs[id] = t;
		t.timer_f = timer(64 * t1, () => {
			if (txs[id] !== t)
				return;
			tx_stop(id);
			cb(null);
		});
		let tick;
		tick = () => {
			if (txs[id] !== t)
				return;
			o.send(t.buf, o.pcscf.addr, o.pcscf.port_s, o.port_c);
			t.retx = timer(t.wait, tick);
			t.wait = (t.wait * 2 > t2) ? t2 : t.wait * 2;
		};
		tick();
	};

	// a MESSAGE of ours to `uri` with an RP message; extra headers (In-Reply-To)
	let message = (uri, body, extra, cb) => {
		let id = rnd_hex(12) + '@' + hostport(o.ue_addr);
		let hs = [
			[ 'Via', sprintf('SIP/2.0/UDP %s;branch=z9hG4bK%s;rport', hostport(o.ue_addr, o.port_s), rnd_hex(8)) ],
			[ 'Max-Forwards', '70' ],
		];
		for (let r in default_route)
			push(hs, [ 'Route', r ]);
		push(hs, [ 'From', sprintf('<%s>;tag=%s', o.impu, rnd_hex(6)) ]);
		push(hs, [ 'To', sprintf('<%s>', uri) ]);
		push(hs, [ 'Call-ID', id ]);
		push(hs, [ 'CSeq', '1 MESSAGE' ]);
		for (let h in extra ?? [])
			push(hs, h);
		push(hs, [ 'P-Preferred-Identity', sprintf('<%s>', o.impu) ]);
		push(hs, [ 'Request-Disposition', 'no-fork' ]);
		push(hs, [ 'Content-Type', CTYPE ]);
		push(hs, [ 'Security-Verify', o.sec_verify ]);
		push(hs, [ 'Require', 'sec-agree' ]);
		push(hs, [ 'Proxy-Require', 'sec-agree' ]);
		push(hs, [ 'P-Access-Network-Info', o.pani ]);
		push(hs, [ 'User-Agent', o.user_agent ?? 'wwand-ims' ]);
		transmit(id, SIP.build(sprintf('MESSAGE %s SIP/2.0', uri), hs, body), cb);
	};

	let reply = (msg, status, reason) =>
		o.send(SIP.response(msg, status, reason), o.pcscf.addr, o.pcscf.port_s, o.port_c);

	// MT: an SMS for us. The SC to report to is the one the network named
	// (P-Asserted-Identity, else From); its number also tells us our SC.
	let on_rp_data = (msg, rp) => {
		let sc = SIP.uri_of(SIP.get(msg, 'p-asserted-identity') ?? SIP.get(msg, 'from') ?? '');
		let number = address_number(rp.oa);
		if (number)
			o.on_smsc?.(number);
		let report = (body) => {
			if (!sc)
				return log('warn', 'smsip: no SC address to send the delivery report to');
			message(sc, body, [ [ 'In-Reply-To', SIP.get(msg, 'call-id') ] ], (r) => {
				if (!r || r.status >= 300)
					log('warn', sprintf('smsip: delivery report for RP-MR %d: %s', rp.mr, r ? r.status : 'no answer'));
			});
		};
		o.deliver(deliver_pdu(rp.oa, rp.ud), (err) => {
			if (err) {
				log('warn', sprintf('smsip: SMS not stored (%J): RP-ERROR', err));
				// a store that can never take it (no write on this modem, a PDU
				// it does not decode) is not "full": the SC would wait for room
				let never = (err?.error == 'invalid_pdu' || err?.error == 'unsupported_on_backend');
				return report(rp_error_mo(rp.mr, never ? CAUSE.PROTOCOL_ERROR : CAUSE.MEMORY_EXCEEDED));
			}
			log('info', sprintf('smsip: SMS received (RP-MR %d)', rp.mr));
			report(rp_ack_mo(rp.mr));
		});
	};

	// MO: the network's RP-ACK or RP-ERROR for one of our parts. It may come
	// before the final response to our MESSAGE: then it waits for that one,
	// whose error still wins (w.settle, in send_part)
	let on_rp_result = (rp) => {
		let w = waits[sprintf('%d', rp.mr)];
		if (!w || w.rp)
			return log('debug', sprintf('smsip: an RP result for no part of ours (RP-MR %d)', rp.mr));
		w.rp = rp;
		w.settle();
	};

	self.on_message = function(buf) {
		if (self.closed)
			return false;
		let msg = SIP.parse(buf);
		if (!msg)
			return false;
		let id = SIP.get(msg, 'call-id');

		// the answer to a MESSAGE of ours
		if (msg.status != null) {
			let t = txs[id];
			if (!t || SIP.cseq(msg)?.method != 'MESSAGE')
				return false;
			if (msg.status >= 200) {
				tx_stop(id);
				t.cb(msg);
			}
			return true;
		}

		if (msg.method != 'MESSAGE' || index(lc(SIP.get(msg, 'content-type') ?? ''), CTYPE) != 0)
			return false;

		let key = sprintf('%s|%s', id, SIP.get(msg, 'cseq'));
		reply(msg, 200, 'OK');
		if (seen[key])
			return true;
		seen[key] = true;
		timer(64 * t1, () => { delete seen[key]; });

		let rp = rp_parse(msg.body);
		if (!rp) {
			log('warn', 'smsip: a MESSAGE whose RP message does not parse');
			return true;
		}
		if (rp.mti == RP.DATA_N)
			on_rp_data(msg, rp);
		else if (rp.mti == RP.ACK_N || rp.mti == RP.ERROR_N)
			on_rp_result(rp);
		else
			log('debug', sprintf('smsip: RP message type %d not handled', rp.mti));
		return true;
	};

	// a message reference no part in flight has (TS 24.011 8.2.3), or null
	let free_mr = () => {
		for (let n = 0; n < 256; n++) {
			mr_next = (mr_next + 1) & 0xff;
			if (!waits[sprintf('%d', mr_next)])
				return mr_next;
		}
		return null;
	};

	// one part: done when BOTH the 2xx for its MESSAGE and the network's RP
	// result are in, in either order; a final error or no RP result within
	// TR1M of the 2xx ends it
	let send_part = (smsc, tpdu, cb) => {
		let mr = free_mr();
		if (mr == null)
			return cb({ error: 'busy', detail: 'all 256 message references in flight' }, null);
		let body = rp_data_mo(mr, smsc, tpdu);
		let k = sprintf('%d', mr);
		let w = { rp: null, accepted: false, timer: null };
		let finish = (err) => {
			if (waits[k] !== w)
				return;
			delete waits[k];
			w.timer?.cancel();
			cb(err, mr);
		};
		w.done = finish;
		w.settle = () => {
			if (!w.accepted || !w.rp)
				return;
			finish((w.rp.mti == RP.ACK_N) ? null : { error: 'rp_error', cause: w.rp.cause });
		};
		waits[k] = w;
		message(o.psi ? o.psi(smsc) : 'tel:' + smsc, body, null, (r) => {
			if (!r || r.status >= 300)
				return finish({ error: r ? 'status' : 'timeout', status: r?.status, reason: r?.reason });
			w.accepted = true;
			if (w.rp)
				return w.settle();
			w.timer = timer(TR1M_MS, () => finish({ error: 'no_report' }));
		});
	};

	self.send = function(number, text, cb) {
		let smsc = o.smsc?.();
		if (!smsc)
			return cb({ error: 'no_smsc', detail: 'no SMS centre: set option sms_smsc, or the SIM has none' }, null);
		let pdus = o.encode_submit(number, text, { ref: (mr_next + 7) & 0xff });
		if (!length(pdus ?? []))
			return cb({ error: 'invalid_argument' }, null);

		let refs = [], i = 0, step;
		step = () => {
			if (self.closed)
				return cb({ error: 'closed' }, null);
			if (i >= length(pdus))
				return cb(null, { parts: length(pdus), refs: refs, via: 'ims' });
			// the TPDU without the SMSC octet encode_submit puts in front
			let hex = substr(pdus[i++].pdu, 2);
			send_part(smsc, bytes(hexdec(hex)), (err, mr) => {
				if (err)
					return cb({ ...err, part: i, parts: length(pdus) }, null);
				push(refs, mr);
				step();
			});
		};
		step();
	};

	self.close = function() {
		self.closed = true;
		for (let id in keys(txs))
			tx_stop(id);
		for (let k, w in { ...waits })
			w.done({ error: 'closed' });
		waits = {};
	};

	return self;
}
