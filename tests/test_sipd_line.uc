// Host tests for sipd/core.uc with the router's own IMS UE as the line
// (env.line / env.relay, sipd/line_ue.uc and sipd/relay.uc faked): a PBX
// trunk registers, calls go out and come in, the SDP is relayed with its
// payload types.
'use strict';

import { eq, ok, done } from './lib/check.uc';
import * as CALL from 'ue_call';

let S = require('sipd_sip');
let CORE = require('sipd_core');

let PBX = { address: '10.0.248.22', port: 6060 };
let UE = '2a00:20:1::5';
let CRLF = (lines) => join('\r\n', lines);

let sent, timers, clock, rnd, dials, relays, lcs;
let reset = () => { sent = []; timers = []; clock = 1000; rnd = 0; dials = []; relays = []; lcs = []; };
reset();

let line_ready = true;

// a fake ue/call.uc call: what sipd calls on it is recorded
let fake_lc = (o) => {
	let lc = { state: 'calling', did: [], answer: o?.answer, offer: o?.offer, accept_ok: o?.accept_ok ?? true };
	lc.hangup = () => { push(lc.did, 'hangup'); lc.state = 'ended'; return true; };
	lc.accept = () => { push(lc.did, 'accept'); return lc.accept_ok; };
	lc.reject = (st, r) => { push(lc.did, sprintf('reject %d', st)); lc.state = 'ended'; return true; };
	push(lcs, lc);
	return lc;
};

let env = {
	cfg: { ip: '192.168.203.245', port: 5060, realm: 'wwand', modem: 'wwmodem0',
	       codecs: [ 'pcma' ], users: { 'asterisk': { password: 'secret' } } },
	send: (text, addr) => push(sent, { msg: S.parse(text), text: text, addr: addr }),
	ims: () => die('the QMI backend must not be used with a line'),
	media: { start: () => die('no media.start'), connect: () => null, stop: () => null },
	line: {
		ready: () => line_ready,
		ue_addr: () => UE,
		dial: (number, ev, opts) => {
			let lc = fake_lc();
			push(dials, { number: number, ev: ev, opts: opts, lc: lc });
			return lc;
		},
	},
	relay: {
		alloc: () => { let m = { id: length(relays) + 1, lan_port: 40000, ims_port: 40100, did: [] }; push(relays, m); return m; },
		connect: (m, far) => push(m.did, sprintf('connect lan %s:%d ims %s:%d pt %d', far.lan?.address, far.lan?.port,
			far.ims?.address, far.ims?.port, far.ims_pt)),
		update: (m, far) => push(m.did, sprintf('update ims %s:%d', far.ims?.address, far.ims?.port)),
		stop: (m) => push(m.did, 'stop'),
		watch: (m, cb) => { m.dead = cb; },
	},
	sdp: { relay: CALL.sdp_relay, media: CALL.sdp_media },
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
let core = CORE.create(env);

let authorize = (chal, method, uri, user, pass) => {
	let realm = match(chal, /realm="([^"]*)"/)[1];
	let nonce = match(chal, /nonce="([^"]*)"/)[1];
	let ha1 = S.md5(sprintf('%s:%s:%s', user, realm, pass));
	let ha2 = S.md5(sprintf('%s:%s', method, uri));
	let resp = S.md5(sprintf('%s:%s:00000001:abcd:auth:%s', ha1, nonce, ha2));
	return sprintf('Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", qop=auth, nc=00000001, cnonce="abcd"',
		user, realm, nonce, uri, resp);
};

// ---- the PBX registers (as Asterisk does with a type=registration) --------------

let register = (auth, cseq) => CRLF([
	'REGISTER sip:192.168.203.245 SIP/2.0',
	'Via: SIP/2.0/UDP 10.0.248.22:6060;branch=z9hG4bK-r' + cseq,
	'From: <sip:asterisk@192.168.203.245>;tag=p1', 'To: <sip:asterisk@192.168.203.245>',
	'Call-ID: reg@pbx', 'CSeq: ' + cseq + ' REGISTER', 'Contact: <sip:asterisk@10.0.248.22:6060>',
	'Expires: 600', ...(auth ? [ 'Authorization: ' + auth ] : []), 'Content-Length: 0', '', '' ]);
core.on_packet(register(null, 1), PBX);
let chal = S.get(last(), 'www-authenticate');
core.on_packet(register(authorize(chal, 'REGISTER', 'sip:192.168.203.245', 'asterisk', 'secret'), 2), PBX);
eq(last().status, 200, 'PBX registered');

// ---- outgoing: PBX -> IMS -----------------------------------------------------------

let PBX_OFFER = CRLF([ 'v=0', 'o=- 1 1 IN IP4 10.0.248.22', 's=Asterisk', 'c=IN IP4 10.0.248.22', 't=0 0',
	'm=audio 12000 RTP/AVP 96 97 8 101', 'a=rtpmap:96 AMR-WB/16000', 'a=fmtp:96 octet-align=0',
	'a=rtpmap:97 AMR/8000', 'a=rtpmap:8 PCMA/8000', 'a=rtpmap:101 telephone-event/8000', 'a=fmtp:101 0-16',
	'a=sendrecv', '' ]);

let invite = (auth, cseq, body, cid) => CRLF([
	'INVITE sip:+4915550123456@192.168.203.245 SIP/2.0',
	'Via: SIP/2.0/UDP 10.0.248.22:6060;branch=z9hG4bK-i' + cseq,
	'From: <sip:4952640@10.0.248.22>;tag=a1', 'To: <sip:+4915550123456@192.168.203.245>',
	'Call-ID: ' + (cid ?? 'out1@pbx'), 'CSeq: ' + cseq + ' INVITE', 'Contact: <sip:asterisk@10.0.248.22:6060>',
	...(auth ? [ 'Proxy-Authorization: ' + auth ] : []), 'Content-Type: application/sdp',
	'Content-Length: ' + length(body), '', body ]);

let dial_out = (body, cid) => {
	core.on_packet(invite(null, 1, body, cid), PBX);
	let pc = S.get(last(), 'proxy-authenticate');
	core.on_packet(invite(authorize(pc, 'INVITE', 'sip:+4915550123456@192.168.203.245', 'asterisk', 'secret'), 2, body, cid), PBX);
};

dial_out(PBX_OFFER);
eq(last().status, 100, 'out: 100 Trying');
eq(dials[0]?.number, '+4915550123456', 'out: the line dials the number');
let ims_offer = dials[0].opts.offer(null, 7);
ok(index(ims_offer, 'c=IN IP6 ' + UE) >= 0 && index(ims_offer, 'm=audio 40100 RTP/AVP 96 97 101') >= 0 &&
	index(ims_offer, 'PCMA') < 0 && index(ims_offer, 'a=fmtp:96 octet-align=0') >= 0,
	'out: IMS offer = the PBX audio minus PCMA, payload types and fmtp kept, our IMS address/port');
ok(index(dials[0].opts.offer({ local: false, remote: false }, 8), 'a=curr:qos local none') >= 0,
	'out: the offer carries preconditions when the UE asks for them');

dials[0].ev('ringing', { status: 180 });
eq(last().status, 180, 'out: 180 to the PBX');

let IMS_ANSWER = CRLF([ 'v=0', 'o=- 1 1 IN IP6 2a01:8f0:400:954::12', 's=-', 'c=IN IP6 2a01:8f0:400:954::12', 't=0 0',
	'm=audio 21870 RTP/AVP 96 101', 'a=rtpmap:96 AMR-WB/16000', 'a=fmtp:96 octet-align=0',
	'a=rtpmap:101 telephone-event/8000', '' ]);
dials[0].ev('answered', { status: 200, body: IMS_ANSWER });
let ok200 = last();
eq(ok200.status, 200, 'out: 200 to the PBX');
ok(index(ok200.body, 'c=IN IP4 192.168.203.245') >= 0 && index(ok200.body, 'm=audio 40000 RTP/AVP 96 101') >= 0,
	'out: PBX answer = the IMS answer on our LAN address and port, payload types kept');
eq(relays[0].did, [ 'connect lan 10.0.248.22:12000 ims 2a01:8f0:400:954::12:21870 pt 96' ],
	'out: the relay connects the PBX media and the IMS far end, keepalive on pt 96');

let bye = CRLF([ 'BYE sip:wwand@192.168.203.245 SIP/2.0', 'Via: SIP/2.0/UDP 10.0.248.22:6060;branch=z9hG4bK-b1',
	'From: <sip:4952640@10.0.248.22>;tag=a1', 'To: <sip:+4915550123456@192.168.203.245>;tag=' + S.param(S.get(ok200, 'to'), 'tag'),
	'Call-ID: out1@pbx', 'CSeq: 3 BYE', 'Content-Length: 0', '', '' ]);
core.on_packet(bye, PBX);
eq([ last().status, lcs[0].did, relays[0].did[1] ], [ 200, [ 'hangup' ], 'stop' ], 'out: PBX BYE -> 200, IMS hangup, relay stop');
eq(core.call(), null, 'out: no call left');

// the IMS side refuses: the status goes to the PBX
dial_out(PBX_OFFER, 'out2@pbx');
dials[1].ev('ended', { status: 486, phrase: 'Busy Here', reason: 'rejected' });
eq([ last().status, core.call() ], [ 486, null ], 'out: IMS 486 -> 486 to the PBX');

dial_out(PBX_OFFER, 'out3@pbx');
dials[2].ev('ended', { status: 503, phrase: 'Service Unavailable', reason: 'rejected', warning: '399 x "ASR"' });
eq([ last().status, S.get(last(), 'warning') ], [ 503, '399 x "ASR"' ], 'out: the network status and Warning pass through');

// early media: a 183 with SDP from the IMS side
dial_out(PBX_OFFER, 'out4@pbx');
dials[3].ev('progress', { status: 183, body: IMS_ANSWER });
ok(last().status == 183 && index(last().body, 'm=audio 40000') >= 0, 'out: IMS 183 with SDP -> 183 with SDP (early media)');
// ... and the 200 from another media gateway moves the relay's IMS far end
dials[3].ev('answered', { status: 200, body: replace(IMS_ANSWER, /954::12/g, '954::99') });
eq(relays[length(relays) - 1].did[1], 'update ims 2a01:8f0:400:954::99:21870', 'out: a 200 after early media updates the relay');
dials[3].ev('ended', { status: 487, reason: 'cancelled' });

// an offer without AMR: refused before the line is asked
let n_dials = length(dials);
dial_out(replace(replace(PBX_OFFER, 'RTP/AVP 96 97 8 101', 'RTP/AVP 8 101'), /a=rtpmap:9[67][^\r]*\r\n/g, ''), 'out5@pbx');
eq([ last().status, length(dials) ], [ 488, n_dials ], 'out: no AMR in the offer -> 488, nothing dialled');

line_ready = false;
dial_out(PBX_OFFER, 'out6@pbx');
eq(last().status, 503, 'out: IMS not registered -> 503');
line_ready = true;

// ---- incoming: IMS -> PBX ---------------------------------------------------------------

let NET_OFFER = CRLF([ 'v=0', 'o=- 1 1 IN IP6 2a01:8f0:400:954::16', 's=-', 'c=IN IP6 2a01:8f0:400:954::16', 't=0 0',
	'm=audio 16546 RTP/AVP 126 104 96', 'a=rtpmap:126 EVS/16000', 'a=rtpmap:104 AMR-WB/16000/1',
	'a=fmtp:104 mode-change-capability=2; max-red=0', 'a=rtpmap:96 telephone-event/16000', '' ]);
let OUR_IMS_ANSWER = CALL.sdp_answer(NET_OFFER, UE, 40100, 5, null, 5);

let incoming = (accept_ok) => {
	let events = null;
	let lc = fake_lc({ answer: OUR_IMS_ANSWER, offer: NET_OFFER, accept_ok: accept_ok });
	let m = env.relay.alloc();
	core.on_line_incoming({ call: lc, media: m, number: '+491622000000', called: '+4915550000001', set: (ev) => { events = ev; } });
	return { lc: lc, m: m, ev: (n, d) => events(n, d) };
};

sent = [];
let i1 = incoming(true);
let inv = last();
eq([ inv.method, inv.uri ], [ 'INVITE', 'sip:asterisk@10.0.248.22:6060' ], 'in: INVITE to the PBX contact');
ok(index(inv.body, 'c=IN IP4 192.168.203.245') >= 0 && index(inv.body, 'm=audio 40000 RTP/AVP 104 96') >= 0 &&
	index(inv.body, 'a=fmtp:104 mode-change-capability=2; max-red=0') >= 0 && index(inv.body, 'EVS') < 0,
	'in: PBX offer = the codec our UE answered the network with, pt and fmtp kept');
ok(index(S.get(inv, 'from'), '+491622000000') >= 0, 'in: the caller number in From');
eq(S.get(inv, 'to'), '<sip:+4915550000001@192.168.203.245>', 'in: the called number in To, for the PBX to route on');

let pbx_resp = (status, body) => S.response(inv, status, status == 200 ? 'OK' : 'x',
	{ to_tag: 'pb1', headers: [ [ 'Contact', '<sip:asterisk@10.0.248.22:6060>' ], [ 'Content-Type', 'application/sdp' ] ] }, body ?? '');
let PBX_ANSWER = CRLF([ 'v=0', 'o=- 2 2 IN IP4 10.0.248.22', 's=Asterisk', 'c=IN IP4 10.0.248.22', 't=0 0',
	'm=audio 13000 RTP/AVP 104 96', 'a=rtpmap:104 AMR-WB/16000', 'a=rtpmap:96 telephone-event/16000', '' ]);
core.on_packet(pbx_resp(180), PBX);
core.on_packet(pbx_resp(200, PBX_ANSWER), PBX);
eq(last().method, 'ACK', 'in: the PBX 200 is ACKed');
eq([ i1.lc.did, i1.m.did ], [ [ 'accept' ], [ 'connect lan 10.0.248.22:13000 ims 2a01:8f0:400:954::16:16546 pt 104' ] ],
	'in: PBX answer -> the UE accepts, the relay connects PBX and the network media');
i1.ev('ended', { reason: 'remote' });
eq([ last().method, i1.m.did[1] ], [ 'BYE', 'stop' ], 'in: the network hangs up -> BYE to the PBX, relay stop');

// the PBX answers before the preconditions let the UE alert: accept on 'incoming'
let i2 = incoming(false);
inv = last();
core.on_packet(pbx_resp(200, PBX_ANSWER), PBX);
eq(i2.lc.did, [ 'accept' ], 'in: accept refused while preconditions run');
i2.ev('incoming', {});
eq(i2.lc.did, [ 'accept', 'accept' ], 'in: accepted again once the UE alerts');
i2.ev('ended', { reason: 'remote' });

// the PBX declines
let i3 = incoming(true);
inv = last();
core.on_packet(pbx_resp(486), PBX);
eq(i3.lc.did, [ 'reject 486' ], 'in: PBX 486 -> the UE rejects with 486');

// the network cancels while the PBX rings
let i4 = incoming(true);
inv = last();
core.on_packet(pbx_resp(180), PBX);
i4.ev('ended', { reason: 'cancelled' });
eq(last().method, 'CANCEL', 'in: the network cancels -> CANCEL to the PBX');
core.on_packet(pbx_resp(487), PBX);

// a second call while one runs: busy
let i5 = incoming(true);
let i6 = incoming(true);
eq(i6.lc.did, [ 'reject 486' ], 'in: a second incoming call while one runs -> 486');
i5.ev('ended', { reason: 'remote' });

// registrations survive a restart: persisted on change, restored if not expired
let persisted = null;
env.bindings_changed = (b) => { persisted = json(sprintf('%J', b)); };
core.on_packet(register(null, 9), PBX);
chal = S.get(last(), 'www-authenticate');
core.on_packet(register(authorize(chal, 'REGISTER', 'sip:192.168.203.245', 'asterisk', 'secret'), 10), PBX);
ok(persisted?.asterisk?.contact == 'sip:asterisk@10.0.248.22:6060', 'restart: the binding is handed out to be saved');
let core2 = CORE.create(env);
eq(core2.restore(persisted), 1, 'restart: the saved binding comes back');
eq(core2.restore({ asterisk: { ...persisted.asterisk, expires: clock - 1 } }), 1, 'restart: an expired one is not taken (the old one stays)');
let core3 = CORE.create(env);
eq(core3.restore({ asterisk: { ...persisted.asterisk, expires: clock - 1 }, nobody: persisted.asterisk }), 0,
	'restart: expired and unknown users are dropped');

// ---- CLIR detection: a withheld caller number -> opts.privacy ----------------------
let inv_clir = (auth, cseq, cid, from, extra) => CRLF([
	'INVITE sip:+4915550123456@192.168.203.245 SIP/2.0',
	'Via: SIP/2.0/UDP 10.0.248.22:6060;branch=z9hG4bK-c' + cseq,
	'From: ' + from, 'To: <sip:+4915550123456@192.168.203.245>',
	...(extra ?? []),
	'Call-ID: ' + cid, 'CSeq: ' + cseq + ' INVITE', 'Contact: <sip:asterisk@10.0.248.22:6060>',
	...(auth ? [ 'Proxy-Authorization: ' + auth ] : []), 'Content-Type: application/sdp',
	'Content-Length: ' + length(PBX_OFFER), '', PBX_OFFER ]);
let clir_dial = (cid, from, extra) => {
	core.on_packet(inv_clir(null, 1, cid, from, extra), PBX);
	let pc = S.get(last(), 'proxy-authenticate');
	core.on_packet(inv_clir(authorize(pc, 'INVITE', 'sip:+4915550123456@192.168.203.245', 'asterisk', 'secret'),
		2, cid, from, extra), PBX);
	let d = dials[length(dials) - 1];
	d.ev('ended', { status: 486, phrase: 'Busy Here', reason: 'rejected' });   // free the call
	return d;
};
eq(clir_dial('clir1@pbx', '<sip:4952640@10.0.248.22>;tag=a1', [ 'Privacy: id' ]).opts.privacy, true,
	'CLIR: Privacy: id from the PBX -> opts.privacy');
eq(clir_dial('clir2@pbx', '"Anonymous" <sip:anonymous@anonymous.invalid>;tag=a2').opts.privacy, true,
	'CLIR: an anonymous From -> opts.privacy');
eq(clir_dial('clir3@pbx', '<sip:4952640@10.0.248.22>;tag=a3', [ 'Privacy: none' ]).opts.privacy, false,
	'no CLIR: Privacy: none and a normal From -> no privacy');

// ---- the relay's watchdog: a call whose media died ------------------------------------
let wd_call = (cid) => {
	dial_out(PBX_OFFER, cid);
	let d = dials[length(dials) - 1];
	d.ev('answered', { status: 200, body: IMS_ANSWER });
	return { d: d, m: relays[length(relays) - 1] };
};
let wd = wd_call('wd1@pbx');
ok(type(wd.m.dead) == 'function', 'media: the watchdog is armed when the call is up');
let n_sent = length(sent);
wd.m.dead('ims', 'rtp');
eq([ sent[n_sent]?.msg?.method, length(sent) - n_sent ], [ 'BYE', 1 ], 'media dead: one BYE to the PBX');
eq(wd.d.lc.did, [ 'hangup' ], 'media dead: the IMS side is hung up');
eq(wd.m.did[length(wd.m.did) - 1], 'stop', 'media dead: the relay is stopped');
wd.m.dead('lan', 'rtp');
eq(length(sent) - n_sent, 1, 'media dead: a late report for an ended call does nothing');
// the line is free again
let wd2 = wd_call('wd2@pbx');
eq(last().status, 200, 'media dead: the next call goes through');
wd2.d.ev('ended', { reason: 'bye' });

done();
