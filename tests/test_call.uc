// Host tests for ue/call.uc: an outgoing call against a stand-in P-CSCF that
// answers with 100, a reliable 183, 180, 200 and checks the PRACK, the ACKs,
// the BYE and the CANCEL the UE sends back.
'use strict';

import { eq, ok, done } from './lib/check.uc';
import * as CALL from 'ue_call';

let SIP = require('sipd_sip');

let UE = '2a00:20:1::5', PC = '2a01:8f0:400:953::5';
let IMPU = 'sip:+4915550000001@ims.mnc002.mcc262.3gppnetwork.org';

// ---- helpers -----------------------------------------------------------------

eq(CALL.tel_uri('+4915550123456'), 'tel:+4915550123456', 'tel_uri: E.164');
eq(CALL.tel_uri('+49 1555 0123456'), 'tel:+4915550123456', 'tel_uri: separators dropped');
eq(CALL.tel_uri('015550123456'), null, 'tel_uri: national refused');
ok(CALL.is_emergency('112') && CALL.is_emergency('110') && CALL.is_emergency('+49112') && CALL.is_emergency('+44112'),
	'is_emergency: 112, 110, with country codes');
ok(!CALL.is_emergency('+4915550123456'), 'is_emergency: an ordinary number is not');
let offer = CALL.sdp_offer(UE, 40000, 7);
ok(index(offer, 'c=IN IP6 ' + UE) >= 0 && index(offer, 'm=audio 40000 RTP/AVP 97 98 100 101') >= 0,
	'sdp_offer: IPv6 address, AMR-WB, AMR, two DTMF types');

// ---- stand-ins ------------------------------------------------------------------

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

function setup()
{
	let s = { clk: clock(), out: [], events: [] };
	s.call = CALL.create({
		ue_addr: UE, port_c: 5062, port_s: 5064,
		pcscf: { addr: PC, port_s: 6000, port_c: 32838 },
		route: [],
		impu: IMPU, contact_user: '001010123456789', imei_urn: 'urn:gsma:imei:35345678-901234-0',
		pani: '3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=26202B08B0C7EC01',
		sec_verify: 'ipsec-3gpp; q=0.1; alg=hmac-sha-1-96; ealg=aes-cbc; spi-c=1; spi-s=2; port-c=32838; port-s=6000',
		rtp_port: 40000, timer: s.clk.timer, call_id: 'cid1', from_tag: 'ft1',
		send: (buf, dst, port, src) => push(s.out, { msg: SIP.parse(buf), buf: buf, dst: dst, port: port, src: src }),
	});
	s.last = () => s.out[length(s.out) - 1];
	s.ev = (n, d) => push(s.events, [ n, d?.reason ?? d?.status ]);
	return s;
}

// a response from the P-CSCF to the request `req`
function resp(req, status, reason, hs, body)
{
	return SIP.response(req, status, reason, { to_tag: (status > 100) ? 'tt9' : null, headers: hs }, body);
}

let ANSWER = 'v=0\r\no=- 1 1 IN IP6 2a01::1\r\ns=-\r\nc=IN IP6 2a01::1\r\nt=0 0\r\nm=audio 30000 RTP/AVP 97 100\r\na=rtpmap:97 AMR-WB/16000/1\r\n';
let RR = [ [ 'Record-Route', '<sip:[2a01:8f0:400:953::5]:6000;lr>' ], [ 'Contact', '<sip:term@[2a01::9]:5060>' ] ];

// ---- answered call, PRACK, BYE ---------------------------------------------------

let s = setup();
s.call.dial('+4915550123456', s.ev);
let inv = s.out[0];
eq([ inv.msg.method, inv.msg.uri, inv.dst, inv.port, inv.src ], [ 'INVITE', 'tel:+4915550123456', PC, 6000, 5062 ],
	'INVITE: tel URI, from port_c to the protected server port');
eq(SIP.get(inv.msg, 'route'), '<sip:[2a01:8f0:400:953::5]:6000;lr>', 'INVITE: Route = P-CSCF without a Service-Route');
ok(index(SIP.get(inv.msg, 'via'), '[' + UE + ']:5064') >= 0, 'INVITE: Via carries the protected server port');
eq([ SIP.get(inv.msg, 'p-preferred-identity'), SIP.get(inv.msg, 'p-preferred-service') ],
	[ '<' + IMPU + '>', 'urn:urn-7:3gpp-service.ims.icsi.mmtel' ], 'INVITE: identity and MMTEL service');
ok(SIP.get(inv.msg, 'security-verify') != null && SIP.get(inv.msg, 'proxy-require') == 'sec-agree',
	'INVITE: Security-Verify and Proxy-Require sec-agree');
ok(index(inv.msg.body, 'AMR-WB/16000') >= 0, 'INVITE: SDP offer in the body');

s.clk.advance(500);
eq(length(s.out), 2, 'INVITE retransmitted after T1');
s.call.on_message(resp(inv.msg, 100, 'Trying'));
s.clk.advance(4000);
eq(length(s.out), 2, 'no retransmission after 100');

s.call.on_message(resp(inv.msg, 183, 'Session Progress', [ ...RR, [ 'Require', '100rel' ], [ 'RSeq', '1' ],
	[ 'Content-Type', 'application/sdp' ] ], ANSWER));
let pr = s.last();
eq([ pr.msg.method, pr.msg.uri, SIP.get(pr.msg, 'rack') ], [ 'PRACK', 'sip:term@[2a01::9]:5060', '1 1 INVITE' ],
	'183 with 100rel: PRACK to the remote target, RAck');
ok(index(SIP.get(pr.msg, 'to'), 'tag=tt9') >= 0, 'PRACK: in the early dialog (To tag)');
eq(s.call.state, 'early', 'state early');
s.call.on_message(resp(inv.msg, 183, 'Session Progress', [ ...RR, [ 'Require', '100rel' ], [ 'RSeq', '1' ] ], ANSWER));
eq(s.last(), pr, 'retransmitted 183 with the same RSeq: no second PRACK');
s.call.on_message(resp(pr.msg, 200, 'OK'));

s.call.on_message(resp(inv.msg, 180, 'Ringing', RR));
s.call.on_message(resp(inv.msg, 200, 'OK', RR, ANSWER));
let ack = s.last();
eq([ ack.msg.method, ack.msg.uri, SIP.cseq(ack.msg) ], [ 'ACK', 'sip:term@[2a01::9]:5060', { seq: 1, method: 'ACK' } ],
	'200: ACK end to end with the INVITE CSeq');
ok(SIP.param(SIP.get(ack.msg, 'via'), 'branch') != SIP.param(SIP.get(inv.msg, 'via'), 'branch'),
	'ACK for 2xx: a new branch');
eq(s.call.state, 'confirmed', 'state confirmed');
eq(s.call.answer, ANSWER, 'the SDP answer kept');
s.call.on_message(resp(inv.msg, 200, 'OK', RR, ANSWER));
eq(s.last().msg.method, 'ACK', 'a retransmitted 200 is ACKed again');
eq(length(filter(s.events, (e) => e[0] == 'answered')), 1, 'answered once');

let ended = null;
s.call.hangup((d) => { ended = d; });
let bye = s.last();
eq([ bye.msg.method, SIP.cseq(bye.msg).seq, SIP.get(bye.msg, 'route') ], [ 'BYE', 3, '<sip:[2a01:8f0:400:953::5]:6000;lr>' ],
	'hangup: BYE, next CSeq, Route from Record-Route');
s.call.on_message(resp(bye.msg, 200, 'OK'));
eq([ s.call.state, ended?.reason, ended?.status ], [ 'ended', 'local', 200 ], 'BYE answered: ended');
eq(map(s.events, (e) => e[0]), [ 'trying', 'progress', 'ringing', 'answered', 'ended' ], 'events in order');

// ---- the network hangs up; UPDATE in the dialog ----------------------------------------

s = setup();
s.call.dial('+4915550123456', s.ev);
inv = s.out[0];
s.call.on_message(resp(inv.msg, 200, 'OK', RR, ANSWER));
let upd = SIP.build('UPDATE sip:001010123456789@[' + UE + ']:5064 SIP/2.0', [
	[ 'Via', 'SIP/2.0/UDP [' + PC + ']:32838;branch=z9hG4bKu1' ], [ 'From', '<tel:+4915550123456>;tag=tt9' ],
	[ 'To', '<' + IMPU + '>;tag=ft1' ], [ 'Call-ID', 'cid1' ], [ 'CSeq', '5 UPDATE' ],
	[ 'Content-Type', 'application/sdp' ] ], ANSWER);
s.call.on_message(upd);
let r = s.last();
eq([ r.msg.status, r.port, r.src ], [ 200, 6000, 5062 ], 'UPDATE: 200 to the P-CSCF server port from port_c');
ok(index(r.msg.body, 'm=audio 40000') >= 0, 'UPDATE with an offer: answered with SDP');
s.call.on_message(replace(replace(upd, 'UPDATE sip', 'BYE sip'), '5 UPDATE', '6 BYE'));
eq([ s.last().msg.status, s.call.state, s.call.ended ], [ 200, 'ended', 'remote' ], 'BYE from the network: 200, ended');

// ---- CANCEL while ringing ------------------------------------------------------

s = setup();
s.call.dial('+4915550123456', s.ev);
inv = s.out[0];
eq(s.call.cancel(), false, 'no CANCEL before a provisional');
s.call.on_message(resp(inv.msg, 180, 'Ringing', RR));
ended = null;
s.call.hangup((d) => { ended = d; });
let can = s.last();
eq([ can.msg.method, can.msg.uri, SIP.cseq(can.msg) ], [ 'CANCEL', 'tel:+4915550123456', { seq: 1, method: 'CANCEL' } ],
	'hangup while early: CANCEL with the INVITE CSeq');
eq(SIP.param(SIP.get(can.msg, 'via'), 'branch'), SIP.param(SIP.get(inv.msg, 'via'), 'branch'), 'CANCEL: the INVITE branch');
ok(index(SIP.get(can.msg, 'to'), 'tag=') < 0, 'CANCEL: To without tag');
s.call.on_message(resp(can.msg, 200, 'OK'));
s.call.on_message(resp(inv.msg, 487, 'Request Terminated'));
let a2 = s.last();
eq([ a2.msg.method, SIP.param(SIP.get(a2.msg, 'via'), 'branch') ], [ 'ACK', SIP.param(SIP.get(inv.msg, 'via'), 'branch') ],
	'487: ACK hop by hop on the INVITE branch');
eq([ ended?.reason, ended?.status ], [ 'cancelled', 487 ], 'ended: cancelled');

// ---- rejected, refused, timeout -------------------------------------------------------

s = setup();
s.call.dial('+4915550123456', s.ev);
s.call.on_message(resp(s.out[0].msg, 486, 'Busy Here'));
eq([ s.last().msg.method, s.call.ended, s.call.status ], [ 'ACK', 'rejected', 486 ], '486: ACK, rejected');

s = setup();
s.call.dial('112', s.ev);
eq([ length(s.out), s.call.ended ], [ 0, 'refused' ], 'emergency number: nothing sent, refused');

s = setup();
s.call.dial('+4915550123456', s.ev);
for (let i = 0; i < 64; i++)
	s.clk.advance(500);
eq(s.call.ended, 'timeout', 'no answer at all: Timer B');
ok(length(s.out) >= 6, 'INVITE retransmitted until Timer B');

eq(s.call.on_message(SIP.build('SIP/2.0 200 OK', [ [ 'Call-ID', 'other' ], [ 'CSeq', '1 INVITE' ] ], '')), false,
	'another Call-ID is not ours');

// ---- CLIR: a withheld number -> anonymous From + Privacy: id -----------------------

s = setup();
s.call.dial('+4915550123456', s.ev, { privacy: true });
inv = s.out[0];
eq(SIP.get(inv.msg, 'from'), '"Anonymous" <sip:anonymous@anonymous.invalid>;tag=ft1',
	'CLIR INVITE: anonymous From, our tag kept');
eq(SIP.get(inv.msg, 'privacy'), 'id', 'CLIR INVITE: Privacy: id');
eq(SIP.get(inv.msg, 'p-preferred-identity'), '<' + IMPU + '>',
	'CLIR INVITE: P-Preferred-Identity still carries the real IMPU');
s.call.on_message(resp(inv.msg, 180, 'Ringing', RR));
s.call.hangup();
can = s.last();
eq([ can.msg.method, SIP.get(can.msg, 'from') ],
	[ 'CANCEL', '"Anonymous" <sip:anonymous@anonymous.invalid>;tag=ft1' ],
	'CLIR CANCEL: the same anonymous From so the dialog ids match');

// a normal dial is unchanged: From = IMPU, no Privacy header
s = setup();
s.call.dial('+4915550123456', s.ev);
inv = s.out[0];
eq(SIP.get(inv.msg, 'from'), '<' + IMPU + '>;tag=ft1', 'no CLIR: From = IMPU');
eq(SIP.get(inv.msg, 'privacy'), null, 'no CLIR: no Privacy header');

// ---- incoming (UAS) ------------------------------------------------------------------

// an offer as the network sends it: AMR-WB twice (be + octet-aligned), AMR, DTMF
let NET_OFFER = join('\r\n', [
	'v=0', 'o=- 1 1 IN IP6 2a01:8f0:400:954::d', 's=-', 'c=IN IP6 2a01:8f0:400:954::d', 't=0 0',
	'm=audio 21870 RTP/AVP 116 107 118 96 111 110',
	'a=rtpmap:116 AMR-WB/16000/1', 'a=fmtp:116 mode-change-capability=2;max-red=0',
	'a=rtpmap:107 AMR-WB/16000/1', 'a=fmtp:107 octet-align=1;mode-change-capability=2;max-red=0',
	'a=rtpmap:118 AMR/8000/1', 'a=rtpmap:96 AMR/8000/1',
	'a=rtpmap:111 telephone-event/16000', 'a=rtpmap:110 telephone-event/8000', 'a=sendrecv', '' ]);

let ans = CALL.sdp_answer(NET_OFFER, UE, 40000, 9);
ok(index(ans, 'm=audio 40000 RTP/AVP 116 111') >= 0 && index(ans, 'a=rtpmap:116 AMR-WB/16000/1') >= 0 &&
	index(ans, 'a=fmtp:116 mode-change-capability=2;max-red=0') >= 0 && index(ans, 'c=IN IP6 ' + UE) >= 0,
	'sdp_answer: the first AMR-WB with its pt and fmtp, the 16 kHz DTMF');
eq(CALL.sdp_answer(replace(NET_OFFER, /AMR-WB/g, 'EVS'), UE, 40000, 9) != null, true, 'sdp_answer: AMR when no AMR-WB');
eq(CALL.sdp_answer('v=0\r\nm=audio 1 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n', UE, 40000, 9), null,
	'sdp_answer: null without AMR');

let net_invite = (require) => SIP.build('INVITE sip:001010123456789@[' + UE + ']:5064 SIP/2.0', [
	[ 'Via', 'SIP/2.0/UDP [' + PC + ']:32838;branch=z9hG4bKin1' ],
	[ 'Record-Route', '<sip:[2a01:8f0:400:953::5]:32838;lr>' ],
	[ 'From', '<tel:+4915550123456>;tag=nt1' ], [ 'To', '<' + IMPU + '>' ],
	[ 'Call-ID', 'incall1' ], [ 'CSeq', '10 INVITE' ], [ 'Contact', '<sip:mo@[2a01::7]:5060>' ],
	[ 'Require', require ], [ 'Supported', '100rel, precondition' ],
	[ 'Content-Type', 'application/sdp' ] ], NET_OFFER);

ok(CALL.initial_invite(net_invite(null)) != null, 'initial_invite: an INVITE without To tag');
eq(CALL.initial_invite(replace(net_invite(null), 'To: <' + IMPU + '>', 'To: <' + IMPU + '>;tag=x')), null,
	'initial_invite: a re-INVITE (To tag) is not one');

s = setup();
let in_ev = [];
s.call.incoming(CALL.initial_invite(net_invite('100rel')), (n, d) => push(in_ev, n));
eq([ s.out[0].msg.status, s.out[0].port, s.out[0].src ], [ 100, 6000, 5062 ], 'incoming: 100 to P:port_s from port_c (as the P-CSCF answers ours)');
ok(index(SIP.get(s.out[0].msg, 'to'), 'tag=') < 0, 'incoming: no To tag on the 100');
let r180 = s.out[1];
eq([ r180.msg.status, SIP.get(r180.msg, 'rseq'), SIP.get(r180.msg, 'require') ], [ 180, '1', '100rel' ],
	'incoming with Require 100rel: reliable 180, RSeq 1');
ok(index(SIP.get(r180.msg, 'to'), 'tag=ft1') >= 0 && SIP.get(r180.msg, 'record-route') != null,
	'180: our To tag, Record-Route copied');
eq([ s.call.state, in_ev ], [ 'incoming', [ 'incoming' ] ], 'state incoming, event');
s.clk.advance(500);
eq(s.last().msg.status, 180, 'reliable 180 retransmitted until the PRACK');
let prack_in = replace(replace(net_invite(null), 'INVITE sip', 'PRACK sip'), '10 INVITE', '11 PRACK');
prack_in = replace(prack_in, 'To: <' + IMPU + '>', 'To: <' + IMPU + '>;tag=ft1');
s.call.on_message(prack_in);
eq(s.last().msg.status, 200, 'PRACK: 200');
let n_out = length(s.out);
s.clk.advance(4000);
eq(length(s.out), n_out, 'no 180 after the PRACK');

s.call.accept();
let r200 = s.last();
eq([ r200.msg.status, SIP.cseq(r200.msg) ], [ 200, { seq: 10, method: 'INVITE' } ], 'accept: 200 for the INVITE');
ok(index(r200.msg.body, 'RTP/AVP 116 111') >= 0, 'accept: the SDP answer');
s.clk.advance(500);
eq(s.last().msg.status, 200, '200 retransmitted until the ACK (Timer G)');
let ack_in = replace(replace(prack_in, 'PRACK sip', 'ACK sip'), '11 PRACK', '10 ACK');
s.call.on_message(ack_in);
eq([ s.call.state, in_ev ], [ 'confirmed', [ 'incoming', 'answered' ] ], 'ACK: confirmed, answered');
n_out = length(s.out);
s.clk.advance(8000);
eq(length(s.out), n_out, 'no 200 after the ACK');

s.call.hangup();
let bye_in = s.last();
eq([ bye_in.msg.method, bye_in.msg.uri, bye_in.port, bye_in.src ], [ 'BYE', 'sip:mo@[2a01::7]:5060', 6000, 5062 ],
	'UAS hangup: BYE to the caller Contact, U:port_c -> P:port_s');
ok(index(SIP.get(bye_in.msg, 'from'), IMPU) >= 0 && index(SIP.get(bye_in.msg, 'from'), 'tag=ft1') >= 0 &&
	SIP.get(bye_in.msg, 'to') == '<tel:+4915550123456>;tag=nt1', 'UAS BYE: From = INVITE To + our tag, To = INVITE From');
eq(SIP.get(bye_in.msg, 'route'), '<sip:[2a01:8f0:400:953::5]:32838;lr>', 'UAS BYE: Route = Record-Route in order');
s.call.on_message(resp(bye_in.msg, 200, 'OK'));
eq(s.call.state, 'ended', 'UAS BYE answered: ended');

// CANCEL while it rings; precondition required -> 420
s = setup();
s.call.incoming(CALL.initial_invite(net_invite(null)), s.ev);
eq(SIP.get(s.last().msg, 'rseq'), null, 'incoming without Require 100rel: plain 180');
s.call.on_message(replace(replace(net_invite(null), 'INVITE sip', 'CANCEL sip'), '10 INVITE', '10 CANCEL'));
let st = map(slice(s.out, -2), (x) => [ x.msg.status, SIP.cseq(x.msg).method ]);
eq(st, [ [ 200, 'CANCEL' ], [ 487, 'INVITE' ] ], 'CANCEL: 200 for it, 487 for the INVITE');
eq(s.call.ended, 'cancelled', 'ended: cancelled');

s = setup();
s.call.incoming(CALL.initial_invite(net_invite('precondition')), s.ev);
eq([ s.last().msg.status, SIP.get(s.last().msg, 'unsupported'), s.call.ended ], [ 420, 'precondition', 'rejected' ],
	'Require precondition: 420 Unsupported');

// paging OPTIONS from the P-CSCF before an incoming INVITE
let OPT = SIP.build('OPTIONS sip:001010123456789@[' + UE + ']:5064 SIP/2.0', [
	[ 'Via', 'SIP/2.0/UDP [' + PC + ']:6000;branch=z9hG4bKo1' ], [ 'From', '<sip:ims.mnc002.mcc262.3gppnetwork.org>;tag=19' ],
	[ 'To', '<sip:+4915550000001@ims.mnc002.mcc262.3gppnetwork.org;user=phone>' ],
	[ 'Call-ID', '1837@paging-options' ], [ 'CSeq', '1 OPTIONS' ], [ 'Accept', '*/*' ] ], '');
let oo = SIP.parse(CALL.options_ok(OPT, { ue_addr: UE, port_s: 5064, contact_user: '001010123456789',
	imei_urn: 'urn:gsma:imei:35345678-901234-0' }));
ok(oo.status == 200 && SIP.get(oo, 'call-id') == '1837@paging-options' && SIP.param(SIP.get(oo, 'to'), 'tag') != null &&
	index(SIP.get(oo, 'contact'), 'icsi-ref') >= 0, 'options_ok: 200 with a To tag and an MMTEL Contact');
eq(CALL.options_ok(replace(OPT, 'user=phone>', 'user=phone>;tag=d1'), { ue_addr: UE, port_s: 5064 }), null,
	'options_ok: an in-dialog OPTIONS is the call\'s');
eq(CALL.options_ok(net_invite(null), { ue_addr: UE, port_s: 5064 }), null, 'options_ok: not for an INVITE');

// ---- preconditions (RFC 3312) -------------------------------------------------------

let qo = CALL.sdp_offer(UE, 40000, 7, { local: false, remote: false }, 8);
ok(index(qo, 'a=curr:qos local none') >= 0 && index(qo, 'a=des:qos mandatory local sendrecv') >= 0 &&
	index(qo, 'a=des:qos optional remote sendrecv') >= 0 && index(qo, 'o=wwand-ims 7 8 ') >= 0,
	'sdp_offer with qos: curr none, des mandatory local / optional remote, version');
eq(CALL.qos_parse('a=curr:qos local sendrecv\r\na=curr:qos remote none\r\na=conf:qos remote sendrecv\r\n'),
	{ local: true, remote: false, conf: true, any: true }, 'qos_parse: curr and conf');
eq(CALL.qos_parse(ANSWER), null, 'qos_parse: none without preconditions');

// MO: offer with preconditions; the 183 answer says remote none; local ready -> UPDATE
let QANS = ANSWER + 'a=curr:qos local none\r\na=curr:qos remote none\r\na=des:qos mandatory local sendrecv\r\n' +
	'a=des:qos mandatory remote sendrecv\r\na=conf:qos remote sendrecv\r\n';
let qready = null;
s = setup();
s.call = CALL.create({
	ue_addr: UE, port_c: 5062, port_s: 5064, pcscf: { addr: PC, port_s: 6000, port_c: 32838 }, route: [],
	impu: IMPU, contact_user: '001010123456789', imei_urn: 'urn:gsma:imei:35345678-901234-0',
	sec_verify: 'x', rtp_port: 40000, timer: s.clk.timer, call_id: 'cidq', from_tag: 'ftq',
	qos_wait: (cb) => { qready = cb; },
	send: (buf, dst, port, src) => push(s.out, { msg: SIP.parse(buf), buf: buf, dst: dst, port: port, src: src }),
});
s.call.dial('+4915550123456', s.ev);
inv = s.out[0];
ok(index(SIP.get(inv.msg, 'supported'), 'precondition') >= 0 && index(inv.msg.body, 'a=curr:qos local none') >= 0,
	'MO preconditions: Supported precondition, curr local none in the offer');
s.call.on_message(resp(inv.msg, 183, 'Session Progress', [ ...RR, [ 'Require', '100rel' ], [ 'RSeq', '1' ],
	[ 'Content-Type', 'application/sdp' ] ], QANS));
pr = s.last();
eq(pr.msg.method, 'PRACK', 'MO: 183 PRACKed');
s.call.on_message(resp(pr.msg, 200, 'OK'));
let n0 = length(s.out);
s.clk.advance(1000);
eq(length(s.out), n0, 'MO: no UPDATE before our bearer is up');
qready();
let up = s.last();
eq([ up.msg.method, up.msg.uri ], [ 'UPDATE', 'sip:term@[2a01::9]:5060' ], 'MO: local ready -> UPDATE to the remote target');
ok(index(up.msg.body, 'a=curr:qos local sendrecv') >= 0 && index(up.msg.body, 'a=curr:qos remote none') >= 0,
	'MO UPDATE: curr local sendrecv, remote still none');
s.call.on_message(resp(up.msg, 200, 'OK', [ [ 'Content-Type', 'application/sdp' ] ],
	replace(replace(QANS, 'curr:qos local none', 'curr:qos local sendrecv'), 'curr:qos remote none', 'curr:qos remote sendrecv')));
eq([ s.call.pre.told_local, s.call.pre.remote ], [ true, true ], 'MO: UPDATE answered, both segments up');
s.call.on_message(resp(inv.msg, 180, 'Ringing', RR));
s.call.on_message(resp(inv.msg, 200, 'OK', RR, ''));
eq(s.call.state, 'confirmed', 'MO with preconditions: confirmed');

// MT: offer with preconditions (caller segment none) -> 183 with answer + conf; PRACK;
// caller UPDATE (its segment up); our bearer up -> our UPDATE; then 180
let QOFFER = NET_OFFER + 'a=curr:qos local none\r\na=curr:qos remote none\r\na=des:qos mandatory local sendrecv\r\n' +
	'a=des:qos optional remote sendrecv\r\n';
let qinv = replace(net_invite('100rel, precondition'), NET_OFFER, QOFFER);
qinv = replace(qinv, /Content-Length: [0-9]+/, 'Content-Length: ' + length(QOFFER));
qready = null;
s = setup();
s.call = CALL.create({
	ue_addr: UE, port_c: 5062, port_s: 5064, pcscf: { addr: PC, port_s: 6000, port_c: 32838 }, route: [],
	impu: IMPU, contact_user: '001010123456789', imei_urn: 'urn:gsma:imei:35345678-901234-0',
	sec_verify: 'x', rtp_port: 40000, timer: s.clk.timer, call_id: 'x', from_tag: 'ft1',
	qos_wait: (cb) => { qready = cb; },
	send: (buf, dst, port, src) => push(s.out, { msg: SIP.parse(buf), buf: buf, dst: dst, port: port, src: src }),
});
in_ev = [];
s.call.incoming(CALL.initial_invite(qinv), (n, d) => push(in_ev, n));
let r183 = s.last();
eq([ r183.msg.status, SIP.get(r183.msg, 'require'), SIP.get(r183.msg, 'rseq') ], [ 183, '100rel, precondition', '1' ],
	'MT preconditions: reliable 183, Require precondition (RFC 3312 11)');
ok(index(r183.msg.body, 'a=curr:qos local none') >= 0 && index(r183.msg.body, 'a=conf:qos remote sendrecv') >= 0 &&
	index(r183.msg.body, 'RTP/AVP 116 111') >= 0, 'MT 183: the answer, curr none, conf asked');
eq(in_ev, [], 'MT: no incoming event (no alerting) yet');
let qprack = replace(replace(qinv, 'INVITE sip', 'PRACK sip'), '10 INVITE', '11 PRACK');
qprack = replace(qprack, 'To: <' + IMPU + '>', 'To: <' + IMPU + '>;tag=ft1');
s.call.on_message(qprack);
eq(s.last().msg.status, 200, 'MT: PRACK 200');
let QUPD = replace(QOFFER, 'curr:qos local none', 'curr:qos local sendrecv');
let qupd = replace(replace(qprack, 'PRACK sip', 'UPDATE sip'), '11 PRACK', '12 UPDATE');
qupd = replace(qupd, QOFFER, QUPD);
s.call.on_message(qupd);
let ru = s.last();
ok(ru.msg.status == 200 && index(ru.msg.body, 'a=curr:qos local none') >= 0 && index(ru.msg.body, 'a=curr:qos remote sendrecv') >= 0,
	'MT: caller UPDATE answered with our segment still none, theirs sendrecv');
eq(in_ev, [], 'MT: still not alerting (our segment not up)');
qready();
let ou = s.last();
ok(ou.msg.method == 'UPDATE' && index(ou.msg.body, 'a=curr:qos local sendrecv') >= 0 &&
	SIP.get(ou.msg, 'to') == '<tel:+4915550123456>;tag=nt1', 'MT: our bearer up -> our UPDATE in the dialog');
s.call.on_message(resp(ou.msg, 200, 'OK', [ [ 'Content-Type', 'application/sdp' ] ], QUPD));
let r180q = s.last();
eq([ r180q.msg.status, SIP.get(r180q.msg, 'rseq') ], [ 180, '2' ], 'MT: both segments up -> reliable 180, RSeq 2');
eq(in_ev, [ 'incoming' ], 'MT: incoming event with the 180');
s.call.on_message(replace(qprack, '11 PRACK', '13 PRACK'));
s.call.accept();
let r200q = s.last();
eq([ r200q.msg.status, r200q.msg.body ], [ 200, '' ], 'MT accept with preconditions: 200 without SDP (offer/answer done)');

// MO: the network skips the 183 and sends 180 without SDP: no UPDATE (no answer yet)
qready = null;
s = setup();
s.call = CALL.create({
	ue_addr: UE, port_c: 5062, port_s: 5064, pcscf: { addr: PC, port_s: 6000, port_c: 32838 }, route: [],
	impu: IMPU, contact_user: '001010123456789', imei_urn: 'urn:gsma:imei:35345678-901234-0',
	sec_verify: 'x', rtp_port: 40000, timer: s.clk.timer, call_id: 'cidr', from_tag: 'ftr',
	qos_wait: (cb) => { qready = cb; },
	send: (buf, dst, port, src) => push(s.out, { msg: SIP.parse(buf), buf: buf, dst: dst, port: port, src: src }),
});
s.call.dial('+4915550123456', s.ev);
inv = s.out[0];
qready();
s.call.on_message(resp(inv.msg, 180, 'Ringing', [ ...RR, [ 'Require', '100rel' ], [ 'RSeq', '1' ] ]));
pr = s.last();
s.call.on_message(resp(pr.msg, 200, 'OK'));
eq(filter(s.out, (x) => x.msg.method == 'UPDATE'), [], 'MO: 180 without SDP, bearer up: no UPDATE before an answer');

// MT: preconditions offered with Supported only (as Vodafone does): used too
s = setup();
in_ev = [];
s.call.incoming(CALL.initial_invite(replace(qinv, 'Require: 100rel, precondition', 'Require: 100rel')), (n, d) => push(in_ev, n));
ok(s.last().msg.status == 183 && s.call.pre != null && length(in_ev) == 0,
	'MT: preconditions with Supported only -> reliable 183 with them, no alerting yet');

// MT without preconditions in the offer: the plain path
s = setup();
in_ev = [];
s.call.incoming(CALL.initial_invite(net_invite('100rel')), (n, d) => push(in_ev, n));
ok(s.last().msg.status == 180 && s.call.pre == null && in_ev[0] == 'incoming',
	'MT: no qos lines in the offer -> plain reliable 180 at once');

// MT with alert_delay: only the 100 until the delay is over, the phone is told at once
let mk_delayed = () => {
	let x = setup();
	x.call = CALL.create({
		ue_addr: UE, port_c: 5062, port_s: 5064, pcscf: { addr: PC, port_s: 6000, port_c: 32838 }, route: [],
		impu: IMPU, contact_user: '001010123456789', imei_urn: 'urn:gsma:imei:35345678-901234-0',
		sec_verify: 'x', rtp_port: 40000, timer: x.clk.timer, call_id: 'x', from_tag: 'ft1', alert_delay: 3000,
		send: (buf, dst, port, src) => push(x.out, { msg: SIP.parse(buf), buf: buf, dst: dst, port: port, src: src }),
	});
	return x;
};
s = mk_delayed();
in_ev = [];
s.call.incoming(CALL.initial_invite(net_invite(null)), (n, d) => push(in_ev, n));
eq([ map(s.out, (x) => x.msg.status), in_ev ], [ [ 100 ], [ 'incoming' ] ], 'alert_delay: 100 only, incoming at once');
s.clk.advance(2900);
eq(length(s.out), 1, 'alert_delay: no 180 before the delay');
s.clk.advance(100);
eq(map(s.out, (x) => x.msg.status), [ 100, 180 ], 'alert_delay: the 180 after it');
// answered within the delay: the 200, and no 180 after it
s = mk_delayed();
s.call.incoming(CALL.initial_invite(net_invite(null)), s.ev);
s.call.accept();
s.clk.advance(5000);
let dst = map(s.out, (x) => x.msg.status);
ok(dst[0] == 100 && dst[1] == 200 && index(dst, 180) < 0, 'alert_delay: answered within it -> 200, no late 180');
// cancelled within the delay: 487, and no 180 after it
s = mk_delayed();
s.call.incoming(CALL.initial_invite(net_invite(null)), s.ev);
s.call.on_message(replace(replace(net_invite(null), 'INVITE sip', 'CANCEL sip'), '10 INVITE', '10 CANCEL'));
s.clk.advance(5000);
dst = map(s.out, (x) => x.msg.status);
ok(index(dst, 487) > 0 && index(dst, 180) < 0, 'alert_delay: cancelled within it -> 487, no late 180');

// MT test mode rel183: answer in a reliable 183, 180 after the PRACK, 200 without SDP
s = setup();
s.call = CALL.create({
	ue_addr: UE, port_c: 5062, port_s: 5064, pcscf: { addr: PC, port_s: 6000, port_c: 32838 }, route: [],
	impu: IMPU, contact_user: '001010123456789', imei_urn: 'urn:gsma:imei:35345678-901234-0',
	sec_verify: 'x', rtp_port: 40000, timer: s.clk.timer, call_id: 'x', from_tag: 'ft1', mt_mode: 'rel183',
	send: (buf, dst, port, src) => push(s.out, { msg: SIP.parse(buf), buf: buf, dst: dst, port: port, src: src }),
});
in_ev = [];
s.call.incoming(CALL.initial_invite(net_invite(null)), (n, d) => push(in_ev, n));
ok(s.last().msg.status == 183 && SIP.get(s.last().msg, 'rseq') == '1' && index(s.last().msg.body, 'a=curr') < 0,
	'rel183: reliable 183 with the answer, no qos lines');
s.call.on_message(prack_in);
ok(s.out[length(s.out) - 1].msg.status == 180 && in_ev[0] == 'incoming', 'rel183: PRACK -> 180, incoming');
s.call.accept();
eq([ s.last().msg.status, s.last().msg.body ], [ 200, '' ], 'rel183: 200 without SDP');

// a CANCEL that crosses our final answer (the call already rejected): 200 for it
s = setup();
s.call.incoming(CALL.initial_invite(net_invite(null)), s.ev);
s.call.reject(480, 'Temporarily Unavailable');
let n_c = length(s.out);
eq(s.call.on_message(replace(replace(net_invite(null), 'INVITE sip', 'CANCEL sip'), '10 INVITE', '10 CANCEL')), true,
	'late CANCEL after reject: ours');
ok(length(s.out) == n_c + 1 && s.last().msg.status == 200 && SIP.cseq(s.last().msg).method == 'CANCEL',
	'late CANCEL after reject: 200 for the CANCEL, no second final');

eq(SIP.parse(CALL.no_transaction(replace(replace(net_invite(null), 'INVITE sip', 'BYE sip'), '10 INVITE', '11 BYE'))).status, 481,
	'no_transaction: a BYE of no call -> 481');
eq(CALL.no_transaction(replace(replace(net_invite(null), 'INVITE sip', 'ACK sip'), '10 INVITE', '10 ACK')), null,
	'no_transaction: an ACK gets nothing');
eq(CALL.no_transaction(net_invite(null)), null, 'no_transaction: an initial INVITE is not for it');

// hangup before any provisional: CANCEL waits for the first one
s = setup();
s.call.dial('+4915550123456', s.ev);
let n_h = length(s.out);
s.call.hangup();
eq([ length(s.out), s.call.state ], [ n_h, 'calling' ], 'hangup before any provisional: no CANCEL yet, no local end');
s.call.on_message(resp(s.out[0].msg, 100, 'Trying'));
eq(s.last().msg.method, 'CANCEL', 'hangup before any provisional: the CANCEL goes with the 100');
s.call.on_message(resp(s.out[0].msg, 487, 'Request Terminated'));
eq(s.call.ended, 'cancelled', 'hangup before any provisional: ended by the 487');

// MT with preconditions: no 200 before the 180
qready = null;
s = setup();
s.call = CALL.create({
	ue_addr: UE, port_c: 5062, port_s: 5064, pcscf: { addr: PC, port_s: 6000, port_c: 32838 }, route: [],
	impu: IMPU, contact_user: '262021234567890', imei_urn: 'urn:gsma:imei:86896506-000860-0',
	sec_verify: 'x', rtp_port: 40000, timer: s.clk.timer, call_id: 'x', from_tag: 'ft1',
	qos_wait: (cb) => { qready = cb; },
	send: (buf, dst, port, src) => push(s.out, { msg: SIP.parse(buf), buf: buf, dst: dst, port: port, src: src }),
});
s.call.incoming(CALL.initial_invite(qinv), s.ev);
eq(s.call.accept(), false, 'MT preconditions: accept before the 180 is refused (RFC 3262 3)');
ok(filter(s.out, (x) => x.msg.status == 200).length == null && length(filter(s.out, (x) => x.msg.status == 200)) == 0,
	'MT preconditions: no 200 went out');

done();
