// Host tests for sipd/sip.uc: parsing what phones send, building responses,
// SDP offer/answer and Digest.
'use strict';

import { eq, ok, done } from './lib/check.uc';

let S = require('sipd_sip');

let CRLF = (lines) => join('\r\n', lines);

// ---- parse ---------------------------------------------------------------------

let reg = S.parse(CRLF([
	'REGISTER sip:192.168.1.1 SIP/2.0',
	'Via: SIP/2.0/UDP 192.168.1.50:5060;branch=z9hG4bK-1;rport',
	'Max-Forwards: 70',
	'From: "Desk" <sip:100@192.168.1.1>;tag=a1',
	'To: <sip:100@192.168.1.1>',
	'i: reg-1@192.168.1.50',
	'CSeq: 1 REGISTER',
	'm: <sip:100@192.168.1.50:5060;transport=udp>;expires=3600',
	'Content-Length: 0',
	'', '' ]));
eq(reg.method, 'REGISTER', 'parse: request method');
eq(S.get(reg, 'call-id'), 'reg-1@192.168.1.50', 'parse: compact i: is Call-ID');
eq(S.uri_of(S.get(reg, 'contact')), 'sip:100@192.168.1.50:5060;transport=udp', 'parse: compact m: is Contact');
eq(S.param(S.get(reg, 'contact'), 'expires'), '3600', 'param: expires after the name-addr');
eq(S.param(S.get(reg, 'from'), 'tag'), 'a1', 'param: from tag');
eq(S.param(S.get(reg, 'to'), 'tag'), null, 'param: absent tag is null');
eq(S.param(S.get(reg, 'via'), 'rport'), '', 'param: a flag without value is ""');
eq(S.cseq(reg), { seq: 1, method: 'REGISTER' }, 'cseq');
eq(S.parse_uri('sip:100@192.168.1.50:5060;transport=udp'),
	{ scheme: 'sip', user: '100', host: '192.168.1.50', port: 5060, params: ';transport=udp' }, 'parse_uri');
eq(S.parse_uri('sip:+491701234567@gw;user=phone').user, '+491701234567', 'parse_uri: E.164 user');

// header folding and comma lists with commas inside quotes
let folded = S.parse(CRLF([
	'SIP/2.0 180 Ringing',
	'Via: SIP/2.0/UDP a:5060;branch=z9hG4bK-x,',
	' SIP/2.0/UDP b:5060;branch=z9hG4bK-y',
	'Contact: "Smith, J" <sip:j@c>',
	'Content-Length: 0', '', '' ]));
eq(folded.status, 180, 'parse: status line');
eq(S.all(folded, 'via'), [ 'SIP/2.0/UDP a:5060;branch=z9hG4bK-x', 'SIP/2.0/UDP b:5060;branch=z9hG4bK-y' ],
	'all: a folded, comma-separated Via splits in two');
eq(S.all(folded, 'contact'), [ '"Smith, J" <sip:j@c>' ], 'all: a comma inside quotes does not split');
eq(S.parse('GET / HTTP/1.1\r\n\r\n'), null, 'parse: not SIP');

// the body is cut at Content-Length
let withbody = S.parse('MESSAGE sip:a SIP/2.0\r\nContent-Length: 3\r\n\r\nabcdef');
eq(withbody.body, 'abc', 'parse: body cut at Content-Length');

// ---- response ---------------------------------------------------------------------

let r = S.parse(S.response(reg, 200, 'OK', { to_tag: 'srv1', headers: [ [ 'Expires', '3600' ] ] }));
eq(r.status, 200, 'response: status');
eq(S.get(r, 'via'), 'SIP/2.0/UDP 192.168.1.50:5060;branch=z9hG4bK-1;rport', 'response: Via copied');
eq(S.param(S.get(r, 'to'), 'tag'), 'srv1', 'response: To tag added');
eq(S.get(r, 'call-id'), 'reg-1@192.168.1.50', 'response: Call-ID copied');
eq(S.get(r, 'cseq'), '1 REGISTER', 'response: CSeq copied');
eq(S.get(r, 'expires'), '3600', 'response: extra header');
eq(S.get(r, 'content-length'), '0', 'response: Content-Length 0');

// ---- SDP --------------------------------------------------------------------------

let offer = S.sdp({ ip: '192.168.1.1', port: 40000, session: 7, codecs: [ 'pcma', 'pcmu' ] });
let po = S.sdp_parse(offer);
eq([ po.ip, po.port, po.pts, po.dtmf_pt ], [ '192.168.1.1', 40000, [ 8, 0, 101 ], 101 ], 'sdp: our offer parses back');

// a phone answer without rtpmap for static types, with a video line after audio
let phone = S.sdp_parse(CRLF([
	'v=0', 'o=- 1 1 IN IP4 192.168.1.50', 's=-', 'c=IN IP4 192.168.1.50', 't=0 0',
	'm=audio 11000 RTP/AVP 0 8 96', 'a=rtpmap:96 telephone-event/8000', 'a=sendrecv',
	'm=video 0 RTP/AVP 97', 'a=rtpmap:97 H264/90000', '' ]));
eq([ phone.ip, phone.port, phone.dtmf_pt ], [ '192.168.1.50', 11000, 96 ], 'sdp: phone audio line');
eq(S.sdp_pick(phone, [ 'pcma', 'pcmu' ]), 'pcma', 'sdp_pick: our first preference the peer has');
eq(S.sdp_pick(phone, [ 'g722' ]), null, 'sdp_pick: nothing in common');

// ---- Digest -----------------------------------------------------------------------

// RFC 1321 A.5 test suite, through the built-in implementation
eq(S.md5_pure(''), 'd41d8cd98f00b204e9800998ecf8427e', 'md5: empty');
eq(S.md5_pure('abc'), '900150983cd24fb0d6963f7d28e17f72', 'md5: abc');
eq(S.md5_pure('12345678901234567890123456789012345678901234567890123456789012345678901234567890'),
	'57edf4a22be3c955ac49da2e2107b67a', 'md5: 80 digits (two blocks)');

// RFC 2617 3.5: the example exchange
let a = S.auth_parse('Digest username="Mufasa", realm="testrealm@host.com", ' +
	'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/dir/index.html", qop=auth, ' +
	'nc=00000001, cnonce="0a4f113b", response="6629fae49393a05397450978507c4ef1", ' +
	'opaque="5ccc069c403ebaf9f0171e9517f40e41"');
eq(a.username, 'Mufasa', 'auth_parse: username');
eq(a.qop, 'auth', 'auth_parse: unquoted qop');
ok(S.auth_check(a, 'GET', 'Circle Of Life'), 'auth_check: RFC 2617 3.5 vector');
ok(!S.auth_check(a, 'GET', 'wrong'), 'auth_check: wrong password refused');
ok(!S.auth_check(a, 'POST', 'Circle Of Life'), 'auth_check: other method refused');

// ---- History-Info -> Diversion ---------------------------------------------------------
// two diversions: the landline unconditionally to an office number, that one
// busy to the mobile (RFC 7044 indexes, RFC 4458 cause); made-up numbers
let hi = S.history_info([
	'<sip:+495215550100@ims.example.net;user=phone?Privacy=none>;index=1, <sip:+495215550200@ims.example.net;user=phone;cause=302>;index=1.1;mp=1',
	'<tel:+4915550000001;cause=486>;index=1.1.1;mp=1.1' ]);
eq(map(hi, (e) => [ e.user, e.index, e.cause ]), [ [ '+495215550100', '1', null ], [ '+495215550200', '1.1', '302' ],
	[ '+4915550000001', '1.1.1', '486' ] ], 'history_info: entries over several headers, user, index, cause');
let dv = S.diversions(hi);
eq(dv, [ { user: '+495215550200', reason: 'user-busy', cause: '486' }, { user: '+495215550100', reason: 'unconditional', cause: '302' } ],
	'diversions: the latest first, the diverting user is the parent entry');
eq(S.diversion_headers(dv, '192.0.2.1'), [ '<sip:+495215550200@192.0.2.1>;reason=user-busy;counter=1',
	'<sip:+495215550100@192.0.2.1>;reason=unconditional;counter=1' ], 'diversion_headers');
eq(S.diversions(S.history_info([ '<sip:+495215550100@ims.example.net>;index=1' ])), [], 'diversions: none without a cause');
eq(S.diversions(S.history_info([ '<sip:+4915550000001@x;cause=408>' ])), [], 'diversions: no diverting entry, none');
eq(S.diversions(S.history_info([ '<sip:+495215550100@x>, <sip:+4915550000001@x;cause=480>' ]))[0],
	{ user: '+495215550100', reason: 'deflection', cause: '480' }, 'diversions: without indexes the entry before');

done();
