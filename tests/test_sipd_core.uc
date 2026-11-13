// Host tests for sipd/core.uc: a simulated phone against the B2BUA, with
// the modem side (ims ops and events), media and timers faked.
'use strict';

import { eq, ok, done } from './lib/check.uc';

let S = require('sipd_sip');
let CORE = require('sipd_core');

let PHONE = { address: '192.168.1.50', port: 5062 };
let ap = (a) => ({ address: a?.address, port: a?.port });
let CRLF = (lines) => join('\r\n', lines);

// ---- the fake environment ---------------------------------------------------

let sent, ims_calls, ims_answer, media, timers, clock, rnd;

let reset = () => {
	sent = []; ims_calls = []; ims_answer = { dial: { id: 1 } }; media = []; timers = []; clock = 1000; rnd = 0;
};
reset();

let env = {
	cfg: { ip: '192.168.1.1', port: 5060, realm: 'wwand', modem: 'wwmodem0',
	       codecs: [ 'pcma', 'pcmu' ], users: { '100': { password: 'secret' } } },
	send: (text, addr) => push(sent, { msg: S.parse(text), text: text, addr: addr }),
	ims: (op, args, cb) => { push(ims_calls, [ op, args ]); cb(null, ims_answer[op] ?? {}); },
	media: {
		start: (c) => { push(media, 'start'); return 40000; },
		connect: (c) => push(media, sprintf('connect %s:%d %s', c.remote_rtp.address, c.remote_rtp.port, c.codec)),
		stop: (c) => push(media, 'stop'),
	},
	timer: (ms, fn) => {
		let t = { ms: ms, fn: fn, cancelled: false };
		t.cancel = () => { t.cancelled = true; };
		push(timers, t);
		return t;
	},
	now: () => clock,
	random: () => sprintf('%016x', ++rnd),
	log: () => null,
};

let last = () => sent[length(sent) - 1]?.msg;
let fire_timers = () => {
	let due = filter(timers, (t) => !t.cancelled);
	timers = [];
	for (let t in due)
		t.fn();
};

// Digest answer to a challenge, the way a phone computes it
let authorize = (chal, method, uri, user, pass) => {
	let realm = S.param(', ' + replace(chal, /^Digest /, ';'), 'realm');
	let nonce = match(chal, /nonce="([^"]*)"/)[1];
	let ha1 = S.md5(sprintf('%s:%s:%s', user, realm, pass));
	let ha2 = S.md5(sprintf('%s:%s', method, uri));
	let resp = S.md5(sprintf('%s:%s:00000001:abcd:auth:%s', ha1, nonce, ha2));

	return sprintf('Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", qop=auth, nc=00000001, cnonce="abcd"',
		user, realm, nonce, uri, resp);
};

let core = CORE.create(env);

// ---- REGISTER ---------------------------------------------------------------------

let register = (auth, cseq) => CRLF([
	'REGISTER sip:192.168.1.1 SIP/2.0',
	'Via: SIP/2.0/UDP 192.168.1.50:5062;branch=z9hG4bK-r' + cseq,
	'From: <sip:100@192.168.1.1>;tag=p1',
	'To: <sip:100@192.168.1.1>',
	'Call-ID: reg@phone',
	'CSeq: ' + cseq + ' REGISTER',
	'Contact: <sip:100@192.168.1.50:5062>',
	'Expires: 600',
	...(auth ? [ 'Authorization: ' + auth ] : []),
	'Content-Length: 0', '', '' ]);

core.on_packet(register(null, 1), PHONE);
eq(last().status, 401, 'register: unauthenticated gets 401');
let chal = S.get(last(), 'www-authenticate');
ok(match(chal, /^Digest realm="wwand", nonce="[^"]+", algorithm=MD5, qop="auth"$/), 'register: Digest challenge');
eq(ap(sent[0].addr), PHONE, 'register: answer to the source address');

core.on_packet(register(authorize(chal, 'REGISTER', 'sip:192.168.1.1', '100', 'wrong'), 2), PHONE);
eq(last().status, 401, 'register: wrong password challenged again');

core.on_packet(register(authorize(chal, 'REGISTER', 'sip:192.168.1.1', '100', 'secret'), 3), PHONE);
eq(last().status, 200, 'register: 200 OK with the right password');
eq(S.get(last(), 'contact'), '<sip:100@192.168.1.50:5062>;expires=600', 'register: binding echoed');
eq(ap(core.bindings()['100'].addr), PHONE, 'register: binding stored with the source address');

// ---- outgoing call: ringing, answer, ACK, BYE ----------------------------------------

let offer = CRLF([ 'v=0', 'o=- 1 1 IN IP4 192.168.1.50', 's=-', 'c=IN IP4 192.168.1.50', 't=0 0',
	'm=audio 11000 RTP/AVP 0 8 101', 'a=rtpmap:101 telephone-event/8000', '' ]);
let invite = (auth, cseq, number) => CRLF([
	sprintf('INVITE sip:%s@192.168.1.1 SIP/2.0', number ?? '+491701234567'),
	'Via: SIP/2.0/UDP 192.168.1.50:5062;branch=z9hG4bK-i' + cseq,
	'From: <sip:100@192.168.1.1>;tag=c1',
	'To: <sip:' + (number ?? '+491701234567') + '@192.168.1.1>',
	'Call-ID: call1@phone',
	'CSeq: ' + cseq + ' INVITE',
	'Contact: <sip:100@192.168.1.50:5062>',
	'Content-Type: application/sdp',
	...(auth ? [ 'Proxy-Authorization: ' + auth ] : []),
	'Content-Length: ' + length(offer), '', offer ]);
let ack = (method, cseq) => CRLF([
	sprintf('%s sip:wwand@192.168.1.1:5060 SIP/2.0', method),
	'Via: SIP/2.0/UDP 192.168.1.50:5062;branch=z9hG4bK-' + lc(method) + cseq,
	'From: <sip:100@192.168.1.1>;tag=c1',
	'To: <sip:+491701234567@192.168.1.1>;tag=X',
	'Call-ID: call1@phone',
	'CSeq: ' + cseq + ' ' + method,
	'Content-Length: 0', '', '' ]);

reset();
core.on_packet(invite(null, 1), PHONE);
eq(last().status, 407, 'invite: unauthenticated gets 407');
let pchal = S.get(last(), 'proxy-authenticate');

ims_answer.dial = { id: 1 };
core.on_packet(invite(authorize(pchal, 'INVITE', 'sip:+491701234567@192.168.1.1', '100', 'secret'), 2), PHONE);
eq(last().status, 100, 'invite: 100 Trying');
eq(ims_calls, [ [ 'dial', { number: '+491701234567' } ] ], 'invite: the plugin dials the number');
eq(media, [ 'start' ], 'invite: media port allocated');

core.on_call_event({ modem: 'wwmodem0', calls: [ { id: 1, state: 'alerting', direction: 'mo', mode: 'lte' } ] });
eq(last().status, 180, 'event alerting: 180 Ringing');
let to_tag = S.param(S.get(last(), 'to'), 'tag');
ok(to_tag, 'ringing: To tag set');

core.on_call_event({ modem: 'wwmodem0', calls: [ { id: 1, state: 'conversation', direction: 'mo', mode: 'lte' } ] });
eq(last().status, 200, 'event conversation: 200 OK');
eq(S.param(S.get(last(), 'to'), 'tag'), to_tag, '200 OK: same To tag as the 180');
let ans = S.sdp_parse(last().body);
eq([ ans.ip, ans.port, ans.pts ], [ '192.168.1.1', 40000, [ 8, 101 ] ], '200 OK: SDP answer with the chosen codec');
eq(media[1], 'connect 192.168.1.50:11000 pcma', 'answer: media connected to the phone RTP');

let before = length(sent);
fire_timers();
eq(length(sent), before + 1, '200 OK retransmitted until the ACK');
core.on_packet(ack('ACK', 2), PHONE);
fire_timers();
eq(length(sent), before + 1, 'ACK stops the retransmission');

core.on_packet(ack('BYE', 3), PHONE);
eq(last().status, 200, 'phone BYE: 200 OK');
eq(ims_calls[length(ims_calls) - 1], [ 'hangup', { id: 1 } ], 'phone BYE: the modem call is hung up');
eq(core.call(), null, 'phone BYE: call gone');
eq(media[length(media) - 1], 'stop', 'phone BYE: media stopped');

// ---- outgoing call refused by the network -----------------------------------------------

let auth2 = () => authorize(S.get(last(), 'proxy-authenticate'), 'INVITE', 'sip:+491701234567@192.168.1.1', '100', 'secret');
reset();
core.on_packet(invite(null, 5), PHONE);
core.on_packet(invite(auth2(), 6), PHONE);
core.on_call_event({ modem: 'wwmodem0', calls: [ { id: 1, state: 'alerting', direction: 'mo', mode: 'lte' } ] });
core.on_call_event({ modem: 'wwmodem0', calls: [ { id: 1, state: 'end', direction: 'mo', mode: 'lte', end_reason: 392 } ] });
eq(last().status, 480, 'network ends the call before answer: 480 to the phone');
eq(S.get(last(), 'reason'), 'Q.850;cause=16;text="modem end reason 392"', '480 carries the modem end reason');
eq(core.call(), null, 'refused call gone');

// ---- the phone cancels while it rings ----------------------------------------------------

reset();
core.on_packet(invite(null, 7), PHONE);
core.on_packet(invite(auth2(), 8), PHONE);
core.on_call_event({ modem: 'wwmodem0', calls: [ { id: 1, state: 'alerting', direction: 'mo', mode: 'lte' } ] });
core.on_packet(replace(ack('CANCEL', 8), 'branch=z9hG4bK-cancel8', 'branch=z9hG4bK-i8'), PHONE);
let statuses = map(slice(sent, -2), (s) => s.msg.status);
eq(statuses, [ 200, 487 ], 'CANCEL: 200 to the CANCEL, 487 to the INVITE');
eq(ims_calls[length(ims_calls) - 1], [ 'hangup', { id: 1 } ], 'CANCEL: modem call hung up');

// ---- a dial the plugin refuses -------------------------------------------------------------

reset();
ims_answer.dial = {};
core.on_packet(invite(null, 11), PHONE);
core.on_packet(invite(auth2(), 12), PHONE);
eq(last().status, 503, 'dial refused by the plugin: 503 to the phone');
eq(core.call(), null, 'dial refused: call gone');

// ---- a number that is not a number, and busy -------------------------------------------------

reset();
core.on_packet(invite(null, 9, 'alice'), PHONE);
core.on_packet(invite(authorize(S.get(last(), 'proxy-authenticate'), 'INVITE', 'sip:alice@192.168.1.1', '100', 'secret'), 10, 'alice'), PHONE);
eq(last().status, 484, 'invite to a non-number: 484');

// ---- incoming call: modem -> phone ----------------------------------------------------------

reset();
core.on_call_event({ modem: 'wwmodem0', calls: [ { id: 2, state: 'incoming', direction: 'mt', mode: 'lte', number: '+4930123' } ] });
let inv = last();
eq(inv.method, 'INVITE', 'incoming: INVITE to the registered phone');
eq(inv.uri, 'sip:100@192.168.1.50:5062', 'incoming: Request-URI is the binding');
eq(ap(sent[0].addr), PHONE, 'incoming: sent to the registered source address');
eq(S.uri_of(S.get(inv, 'from')), 'sip:+4930123@192.168.1.1', 'incoming: caller number in From');
eq(S.sdp_parse(inv.body).pts, [ 8, 0, 101 ], 'incoming: SDP offer with our codecs');

let resp = (status, reason, body) => {
	let hs = map(filter(inv.headers, (h) => h[0] in { via: 1, from: 1, to: 1, 'call-id': 1, cseq: 1 }), (h) => [ h[0], h[1] ]);
	hs = map(hs, (h) => (h[0] == 'to') ? [ 'To', h[1] + ';tag=ph1' ] : h);
	push(hs, [ 'Contact', '<sip:100@192.168.1.50:5062>' ]);
	if (body)
		push(hs, [ 'Content-Type', 'application/sdp' ]);
	return S.build(sprintf('SIP/2.0 %d %s', status, reason), hs, body ?? '');
};

before = length(sent);
fire_timers();
eq(length(sent), before + 1, 'incoming: INVITE retransmitted without a response');
core.on_packet(resp(180, 'Ringing'), PHONE);
before = length(sent);
fire_timers();
eq(length(sent), before, 'incoming: a 180 stops the retransmission');

let phone_sdp = CRLF([ 'v=0', 'o=- 2 2 IN IP4 192.168.1.50', 's=-', 'c=IN IP4 192.168.1.50', 't=0 0',
	'm=audio 12000 RTP/AVP 8', '' ]);
core.on_packet(resp(200, 'OK', phone_sdp), PHONE);
eq(last().method, 'ACK', 'incoming 200: ACK sent');
eq(ims_calls, [ [ 'answer', { id: 2 } ] ], 'incoming 200: the plugin answers the modem call');
eq(media[length(media) - 1], 'connect 192.168.1.50:12000 pcma', 'incoming 200: media connected');

core.on_call_event({ modem: 'wwmodem0', calls: [ { id: 2, state: 'end', direction: 'mt', mode: 'lte' } ] });
eq(last().method, 'BYE', 'remote party hangs up: BYE to the phone');
eq(core.call(), null, 'incoming call gone');

// ---- incoming call the phone declines ---------------------------------------------------------

reset();
core.on_call_event({ modem: 'wwmodem0', calls: [ { id: 3, state: 'incoming', direction: 'mt', mode: 'lte', number: '+4930999' } ] });
inv = last();
core.on_packet(resp(486, 'Busy Here'), PHONE);
eq(last().method, 'ACK', 'declined: ACK for the 486');
eq(ims_calls, [ [ 'hangup', { id: 3 } ] ], 'declined: modem call hung up');

// ---- incoming call ended by the caller while ringing --------------------------------------------

reset();
core.on_call_event({ modem: 'wwmodem0', calls: [ { id: 4, state: 'incoming', direction: 'mt', mode: 'lte' } ] });
core.on_call_event({ modem: 'wwmodem0', calls: [] });
eq(last().method, 'CANCEL', 'caller gives up: CANCEL to the phone');

// ---- a phone on TCP: requests go back over its connection, no retransmits ----------------

let TCP = { address: '192.168.1.60', port: 40000, transport: 'TCP', conn: 7 };
reset();
core.on_packet(replace(register(null, 20), '192.168.1.50:5062', '192.168.1.60:40000'), TCP);
let tchal = S.get(last(), 'www-authenticate');
eq(sent[0].addr.conn, 7, 'tcp register: challenge on the same connection');
core.on_packet(replace(register(authorize(tchal, 'REGISTER', 'sip:192.168.1.1', '100', 'secret'), 21),
	'192.168.1.50:5062', '192.168.1.60:40000'), TCP);
eq(last().status, 200, 'tcp register: 200 OK');

reset();
core.on_call_event({ modem: 'wwmodem0', calls: [ { id: 5, state: 'incoming', direction: 'mt', mode: 'lte' } ] });
eq(sent[0].addr.conn, 7, 'tcp: incoming INVITE over the registering connection');
ok(match(S.get(last(), 'via'), /^SIP\/2\.0\/TCP /), 'tcp: Via names TCP');
ok(match(S.get(last(), 'contact'), /;transport=tcp>$/), 'tcp: Contact asks for TCP');
fire_timers();
eq(length(sent), 1, 'tcp: no INVITE retransmission');
core.on_call_event({ modem: 'wwmodem0', calls: [] });

// ---- events of another modem are ignored ----------------------------------------------------------

reset();
core.on_call_event({ modem: 'wwmodem9', calls: [ { id: 1, state: 'incoming', direction: 'mt' } ] });
eq(length(sent), 0, 'events of another modem are ignored');

done();
