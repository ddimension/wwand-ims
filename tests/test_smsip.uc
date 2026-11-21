// Host tests for ue/smsip.uc: the RP layer (TS 24.011) with hand-built
// messages, an SMS that arrives (MESSAGE -> 200, delivered, RP-ACK or
// RP-ERROR back to the SC) and one that is sent (MESSAGE with RP-DATA, 202,
// the network's RP-ACK). All numbers and addresses are made-up examples.
'use strict';

import { eq, ok, done } from './lib/check.uc';
import * as SMSIP from 'ue_smsip';
import * as sms_pdu from 'wwand.sms_pdu';

let SIP = require('sipd_sip');

let UE = '2001:db8::5', PC = '2001:db8:ff::10';
let IMPU = 'sip:+4915550000001@ims.example.net';

let hexb = (s) => hexenc(s);

// ---- the RP layer ---------------------------------------------------------------------

eq(SMSIP.address_value('+4917000000'), [ 0x91, 0x94, 0x71, 0x00, 0x00, 0x00 ], 'address: international, swapped BCD');
eq(SMSIP.address_value('12345'), [ 0x81, 0x21, 0x43, 0xf5 ], 'address: unknown type, F-padded');
eq(SMSIP.address_value('+49 1'), null, 'address: not a number');
eq(SMSIP.address_number([ 0x91, 0x94, 0x71, 0x00, 0x00, 0x00 ]), '+4917000000', 'address back to the number');

eq(hexb(SMSIP.rp_data_mo(5, '+4917000000', [ 0x01, 0x02 ])), '0005000691947100000002' + '0102',
	'RP-DATA MS->N: MTI 0, MR, empty OA, the SC as DA, the TPDU');
eq(SMSIP.rp_data_mo(5, null, [ 1 ]), null, 'RP-DATA MS->N: no SC, none');
eq(hexb(SMSIP.rp_ack_mo(7)), '0207' + '41020000', 'RP-ACK MS->N with an empty SMS-DELIVER-REPORT');
eq(hexb(SMSIP.rp_error_mo(7, 22)), '0407' + '0116' + '410300d300', 'RP-ERROR MS->N: cause 22, TP-FCS D3');

// an RP-DATA network -> MS as the network sends it: SC +4917000000, a
// SMS-DELIVER from +4915550000002 with the GSM7 text "hi"
let TPDU = [ 0x04, 13, 0x91, 0x94, 0x51, 0x55, 0x00, 0x00, 0x00, 0xf2, 0x00, 0x00,
	0x62, 0x11, 0x12, 0x02, 0x00, 0x00, 0x80, 0x02, 0xe8, 0x34 ];
let SC = [ 0x91, 0x94, 0x71, 0x00, 0x00, 0x00 ];
let RP_MT = join('', map([ 0x01, 0x2a, length(SC), ...SC, 0x00, length(TPDU), ...TPDU ], (x) => chr(x)));
let rp = SMSIP.rp_parse(RP_MT);
eq([ rp.mti, rp.mr, rp.oa, rp.da, rp.ud ], [ 1, 0x2a, SC, [], TPDU ], 'rp_parse: RP-DATA N->MS');
let pdu = SMSIP.deliver_pdu(rp.oa, rp.ud);
let dm = sms_pdu.decode_deliver(pdu);
eq([ dm?.smsc, dm?.sender, dm?.text ], [ '+4917000000', '+4915550000002', 'hi' ],
	'deliver_pdu: what wwand decodes (SC as the SMSC field)');
eq(SMSIP.rp_parse(chr(0x03, 0x09)), { mti: 3, mr: 9 }, 'rp_parse: RP-ACK N->MS, no user data');
eq(SMSIP.rp_parse(chr(0x05, 0x09, 0x01, 0x2a)), { mti: 5, mr: 9, cause: 42 }, 'rp_parse: RP-ERROR N->MS, its cause');
eq(SMSIP.rp_parse(chr(0x01, 0x2a, 0x09, 0x91)), null, 'rp_parse: truncated RP-DATA');

// ---- stand-ins --------------------------------------------------------------------------

function clock()
{
	let c = { now: 0, list: [] };
	c.timer = (ms, fn) => {
		let t = { at: c.now + ms, fn: fn, dead: false };
		push(c.list, t);
		return { cancel: () => { t.dead = true; } };
	};
	c.advance = (ms) => {
		c.now += ms;
		for (let again = true; again; ) {
			again = false;
			for (let t in c.list)
				if (!t.dead && t.at <= c.now) {
					t.dead = true;
					t.fn();
					again = true;
				}
		}
	};
	return c;
}

function setup(o)
{
	let s = { clk: clock(), out: [], delivered: [], smsc_seen: null };
	s.sms = SMSIP.create({
		ue_addr: UE, port_c: 5062, port_s: 5064, pcscf: { addr: PC, port_s: 6000 }, route: [],
		impu: IMPU, pani: '3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=26299000100000001',
		sec_verify: 'ipsec-3gpp; q=0.1; alg=hmac-sha-1-96; spi-c=1; spi-s=2; port-c=6001; port-s=6000',
		timer: s.clk.timer, smsc: () => o?.smsc ?? '+4917000000', psi: o?.psi,
		encode_submit: sms_pdu.encode_submit,
		deliver: (p, cb) => { push(s.delivered, p); cb(o?.store_err); },
		on_smsc: (n) => { s.smsc_seen = n; },
		send: (buf, dst, port, src) => push(s.out, { msg: SIP.parse(buf), buf: buf, dst: dst, port: port, src: src }),
	});
	s.last = () => s.out[length(s.out) - 1];
	return s;
}

// a MESSAGE from the network with an RP message
function net_message(body, cid)
{
	return SIP.build('MESSAGE sip:262990123456789@[2001:db8::5]:5064 SIP/2.0', [
		[ 'Via', 'SIP/2.0/UDP [2001:db8:ff::10]:6000;branch=z9hG4bKnet' + (cid ?? '1') ],
		[ 'From', '<sip:+4917000000@ims.example.net>;tag=sc1' ],
		[ 'To', '<' + IMPU + '>' ],
		[ 'Call-ID', 'net-' + (cid ?? '1') + '@ims.example.net' ],
		[ 'CSeq', '1 MESSAGE' ],
		[ 'P-Asserted-Identity', '<sip:+4917000000@ims.example.net>' ],
		[ 'Content-Type', 'application/vnd.3gpp.sms' ],
	], body);
}

// ---- MT ---------------------------------------------------------------------------------

let s = setup();
eq(s.sms.on_message(net_message(RP_MT)), true, 'MT: the MESSAGE is ours');
eq(s.out[0].msg.status, 200, 'MT: 200 for the MESSAGE');
eq([ length(s.delivered), s.delivered[0], s.smsc_seen ], [ 1, pdu, '+4917000000' ], 'MT: delivered, the SC learnt');
let rep = s.out[1].msg;
eq([ rep.method, rep.uri, SIP.get(rep, 'in-reply-to'), SIP.get(rep, 'content-type') ],
	[ 'MESSAGE', 'sip:+4917000000@ims.example.net', 'net-1@ims.example.net', 'application/vnd.3gpp.sms' ],
	'MT: the delivery report to the SC the network named, In-Reply-To its Call-ID');
eq(hexb(rep.body), '022a41020000', 'MT: RP-ACK with the message reference');
ok(SIP.get(rep, 'security-verify') != null && SIP.get(rep, 'p-preferred-identity') == '<' + IMPU + '>' &&
	s.out[1].dst == PC && s.out[1].port == 6000 && s.out[1].src == 5062, 'MT: the report inside the SAs, U:port_c -> P:port_s');
eq(s.sms.on_message(net_message(RP_MT)), true, 'MT: a retransmission');
eq([ length(s.delivered), s.last().msg.status ], [ 1, 200 ], 'MT: answered again, not delivered twice');
// the report is answered
s.sms.on_message(SIP.response(rep, 200, 'OK'));
s.clk.advance(40000);
eq(filter(s.out, (x) => x.msg.method == 'MESSAGE' && x !== s.out[1]), [], 'MT: the 200 stops the report\'s retransmissions');

// the store refused it: RP-ERROR, memory capacity exceeded
s = setup({ store_err: { error: 'ubus' } });
s.sms.on_message(net_message(RP_MT, '2'));
eq(hexb(s.out[1].msg.body), '042a0116410300d300', 'MT: not stored -> RP-ERROR cause 22');

// a modem that cannot store SMS at all: protocol error, not "full"
s = setup({ store_err: { error: 'unsupported_on_backend' } });
s.sms.on_message(net_message(RP_MT, '8'));
eq(hexb(s.out[1].msg.body), '042a016f410300ff00', 'MT: no write on this modem -> RP-ERROR cause 111');

// not an SMS: not ours
eq(s.sms.on_message(replace(net_message(RP_MT, '3'), 'application/vnd.3gpp.sms', 'text/plain')), false,
	'MT: a MESSAGE of another type is not ours');

// ---- MO ---------------------------------------------------------------------------------

s = setup();
let res = null, err = null;
s.sms.send('+4915550000003', 'hello', (e, r) => { err = e; res = r; });
let mo = s.out[0].msg;
eq([ mo.method, mo.uri, SIP.get(mo, 'request-disposition'), SIP.get(mo, 'content-type') ],
	[ 'MESSAGE', 'tel:+4917000000', 'no-fork', 'application/vnd.3gpp.sms' ], 'MO: a MESSAGE to the SC');
let mrp = SMSIP.rp_parse(mo.body);
let sub_pdu = lc(substr(sms_pdu.encode_submit('+4915550000003', 'hello', { ref: 0 })[0].pdu, 2));
eq([ mrp.mti, mrp.oa, SMSIP.address_number(mrp.da), hexenc(join('', map(mrp.ud, (x) => chr(x)))) ],
	[ 0, [], '+4917000000', sub_pdu ], 'MO: RP-DATA MS->N with the SMS-SUBMIT TPDU');
s.sms.on_message(SIP.response(mo, 202, 'Accepted'));
eq([ err, res ], [ null, null ], 'MO: 202 alone is not the result yet');
s.sms.on_message(net_message(chr(0x03, mrp.mr), '4'));
eq(s.last().msg.status, 200, 'MO: the network\'s RP-ACK MESSAGE answered with 200');
eq([ err, res ], [ null, { parts: 1, refs: [ mrp.mr ], via: 'ims' } ], 'MO: sent');

// the RP-ACK before the 2xx: it waits for the 2xx, and a final error then wins
s = setup();
res = null; err = null;
s.sms.send('+4915550000003', 'x', (e, r) => { err = e; res = r; });
mo = s.out[0].msg;
s.sms.on_message(net_message(chr(0x03, SMSIP.rp_parse(mo.body).mr), '9'));
eq([ err, res ], [ null, null ], 'MO: an RP-ACK before the 2xx is not the result yet');
s.sms.on_message(SIP.response(mo, 202, 'Accepted'));
eq(res?.parts, 1, 'MO: then the 2xx completes it');
s = setup();
res = null; err = null;
s.sms.send('+4915550000003', 'x', (e, r) => { err = e; res = r; });
mo = s.out[0].msg;
s.sms.on_message(net_message(chr(0x03, SMSIP.rp_parse(mo.body).mr), '10'));
s.sms.on_message(SIP.response(mo, 500, 'Server Error'));
eq([ err?.error, err?.status, res ], [ 'status', 500, null ], 'MO: an RP-ACK then a 500 -> the 500 wins');

// message references: never one in flight twice
s = setup();
let mrs = {};
for (let i = 0; i < 3; i++)
	s.sms.send('+4915550000003', 'x', (e, r) => null);
for (let x in s.out)
	mrs[sprintf('%d', SMSIP.rp_parse(x.msg.body).mr)] = true;
eq(length(keys(mrs)), 3, 'MO: three parts in flight, three references');

// two parts, one after the other
s = setup();
res = null; err = null;
let long = '';
for (let i = 0; i < 20; i++)
	long += 'abcdefghij';
s.sms.send('+4915550000003', long, (e, r) => { err = e; res = r; });
let m1 = s.out[0].msg;
s.sms.on_message(SIP.response(m1, 202, 'Accepted'));
eq(length(filter(s.out, (x) => x.msg.method == 'MESSAGE')), 1, 'MO 2 parts: the second waits for the first\'s RP-ACK');
s.sms.on_message(net_message(chr(0x03, SMSIP.rp_parse(m1.body).mr), '5'));
let m2 = filter(s.out, (x) => x.msg.method == 'MESSAGE')[1]?.msg;
ok(m2 != null && SMSIP.rp_parse(m2.body).mr != SMSIP.rp_parse(m1.body).mr, 'MO 2 parts: the second, its own reference');
s.sms.on_message(SIP.response(m2, 202, 'Accepted'));
s.sms.on_message(net_message(chr(0x03, SMSIP.rp_parse(m2.body).mr), '6'));
eq(res?.parts, 2, 'MO 2 parts: both sent');

// refused, RP-ERROR, no report, no SC, a psi of the profile
s = setup();
s.sms.send('+4915550000003', 'x', (e, r) => { err = e; });
s.sms.on_message(SIP.response(s.out[0].msg, 403, 'Forbidden'));
eq([ err?.error, err?.status ], [ 'status', 403 ], 'MO: a final error for the MESSAGE');
s = setup();
s.sms.send('+4915550000003', 'x', (e, r) => { err = e; });
s.sms.on_message(SIP.response(s.out[0].msg, 202, 'Accepted'));
s.sms.on_message(net_message(chr(0x05, SMSIP.rp_parse(s.out[0].msg.body).mr, 0x01, 0x2a), '7'));
eq([ err?.error, err?.cause ], [ 'rp_error', 42 ], 'MO: the network\'s RP-ERROR and its cause');
s = setup();
err = null;
s.sms.send('+4915550000003', 'x', (e, r) => { err = e; });
s.sms.on_message(SIP.response(s.out[0].msg, 202, 'Accepted'));
s.clk.advance(45000);
eq(err?.error, 'no_report', 'MO: no RP-ACK within TR1M');
s = setup({ smsc: '' });
s.sms.send('+4915550000003', 'x', (e, r) => { err = e; });
eq([ err?.error, length(s.out) ], [ 'no_smsc', 0 ], 'MO: no SC -> refused, nothing sent');
s = setup({ psi: (sc) => sprintf('sip:%s@ims.example.net;user=phone', sc) });
s.sms.send('+4915550000003', 'x', (e, r) => null);
eq(s.out[0].msg.uri, 'sip:+4917000000@ims.example.net;user=phone', 'MO: the profile\'s PSI for the SC');

// close: a part in flight fails, nothing more is sent
s = setup();
s.sms.send('+4915550000003', 'x', (e, r) => { err = e; });
s.sms.close();
let n = length(s.out);
s.clk.advance(60000);
eq([ err?.error, length(s.out) ], [ 'closed', n ], 'close: the waiting part fails, no retransmissions');

done();
