// Host tests for ue/regevent.uc: the reginfo documents an S-CSCF sends, what
// they mean for our own binding, and the SUBSCRIBE / NOTIFY exchange against
// a stand-in. All identifiers are made-up example values.
'use strict';

import { eq, ok, done } from './lib/check.uc';
import * as RE from 'ue_regevent';

let SIP = require('sipd_sip');

let UE = '2001:db8::5', PC = '2001:db8:ff::10';
let IMPU = 'sip:262991234567890@ims.mnc099.mcc262.3gppnetwork.org';
let HP = '[2001:db8::5]:5064';
let CRLF = (lines) => join('\r\n', lines);

// ---- reginfo ------------------------------------------------------------------------

let contact = (id, state, event, uri, extra) =>
	sprintf('<contact id="%s" state="%s" event="%s"%s>\n<uri>%s</uri>\n</contact>\n', id, state, event, extra ?? '', uri);
let reginfo = (version, state, regs) =>
	sprintf('<?xml version="1.0"?>\n<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="%d" state="%s">\n%s</reginfo>\n',
		version, state, join('', regs));
let registration = (aor, state, contacts) =>
	sprintf('<registration aor="%s" id="r1" state="%s">\n%s</registration>\n', aor, state, join('', contacts ?? []));

let OURS = 'sip:262991234567890@[2001:db8::5]:5064';
let OTHER = 'sip:262991234567890@[2001:db8::77]:5080';

let full = RE.parse_reginfo(reginfo(0, 'full', [
	registration(IMPU, 'active', [ contact('c1', 'active', 'registered', OURS, ' expires="3600"'),
	                               contact('c2', 'active', 'registered', OTHER) ]),
	registration('tel:+4915550100', 'active', [ contact('c3', 'active', 'created', OURS) ]) ]));
eq([ full.state, full.version, length(full.registrations) ], [ 'full', 0, 2 ], 'reginfo: state, version, registrations');
eq(full.registrations[0].aor, IMPU, 'reginfo: aor');
eq(full.registrations[0].contacts[0], { state: 'active', event: 'registered', expires: 3600, uri: OURS },
	'reginfo: a contact with its uri and expiry');
eq(full.registrations[0].contacts[1].expires, null, 'reginfo: no expires attribute');
eq(full.registrations[1].contacts[0].event, 'created', 'reginfo: the second registration\'s contact');
eq(RE.fate(full, HP, IMPU), null, 'fate: all active, nothing to do');

eq(RE.parse_reginfo('<html>no</html>'), null, 'not reginfo');
eq(RE.parse_reginfo(null), null, 'no body');

// namespace prefixes, single quotes, an escaped ampersand in the URI
let pre = RE.parse_reginfo("<ri:reginfo xmlns:ri='urn:ietf:params:xml:ns:reginfo' version='4' state='partial'>" +
	"<ri:registration aor='" + IMPU + "' id='a' state='active'><ri:contact id='b' state='terminated' event='rejected'>" +
	"<ri:uri>sip:u@[2001:db8::5]:5064;a=1&amp;b=2</ri:uri></ri:contact></ri:registration></ri:reginfo>");
eq([ pre.version, pre.state ], [ 4, 'partial' ], 'reginfo: prefixed elements, single quotes');
eq(pre.registrations[0].contacts[0].uri, 'sip:u@[2001:db8::5]:5064;a=1&b=2', 'reginfo: entities in the uri');
eq(RE.fate(pre, HP, IMPU), { what: 'terminated', event: 'rejected' }, 'fate: our contact rejected');

let term = (event, uri) => RE.parse_reginfo(reginfo(1, 'partial', [
	registration(IMPU, 'active', [ contact('c1', 'terminated', event, uri) ]) ]));
eq(RE.fate(term('deactivated', OURS), HP, IMPU), { what: 'terminated', event: 'deactivated' }, 'fate: deactivated');
eq(RE.fate(term('unregistered', OTHER), HP, IMPU), null, 'fate: another device\'s contact going is not ours');
eq(RE.fate(term('deactivated', 'sip:262991234567890@[2001:DB8::5]:5064'), HP, IMPU)?.what, 'terminated',
	'fate: the address compared without case');
eq(RE.fate(term('deactivated', 'sip:262991234567890@[2001:db8::5]:5074'), HP, IMPU), null,
	'fate: our other port pair (the registration a refresh replaced) is not this one');

let short = RE.parse_reginfo(reginfo(2, 'partial', [
	registration(IMPU, 'active', [ contact('c1', 'active', 'shortened', OURS, ' expires="120"') ]) ]));
eq(RE.fate(short, HP, IMPU), { what: 'shortened', expires: 120 }, 'fate: shortened, with the new expiry');

eq(RE.fate(RE.parse_reginfo(reginfo(3, 'full', [ registration(IMPU, 'terminated'), registration('tel:+4915550100', 'terminated') ])),
	HP, IMPU), { what: 'terminated', event: null }, 'fate: everything terminated, no contacts listed');
eq(RE.fate(RE.parse_reginfo(reginfo(3, 'partial', [ registration('tel:+4915550100', 'terminated') ])), HP, IMPU), null,
	'fate: a partial document about another identity only');
eq(RE.fate(RE.parse_reginfo(reginfo(3, 'partial', [ registration(IMPU, 'terminated') ])), HP, IMPU)?.what, 'terminated',
	'fate: a partial document ending the identity we subscribed for');

// ---- the subscription ---------------------------------------------------------------

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

function setup(extra)
{
	let x = { c: clock(), sent: [], events: [] };
	x.sub = RE.create({
		ue_addr: UE, port_c: 5062, port_s: 5064, pcscf: { addr: PC, port_s: 7101, port_c: 7100 },
		route: [ '<sip:orig@scscf.example.net;lr>' ], impu: IMPU, contact_user: '262991234567890',
		imei_urn: 'urn:gsma:imei:35345678-901234-0', pani: '3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=262991A2B1234567',
		sec_verify: 'ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=4001;spi-s=4002;port-c=7100;port-s=7101',
		timer: x.c.timer, call_id: 'sub1@test', from_tag: 'ft1',
		send: (buf, dst, port, src) => push(x.sent, { msg: SIP.parse(buf), dst: dst, port: port, src: src }),
		on_event: (what, d) => push(x.events, [ what, d ]),
		...(extra ?? {}),
	});
	x.last = () => x.sent[length(x.sent) - 1];
	x.answer = (status, hs) => x.sub.on_message(SIP.response(x.last().msg, status, status == 200 ? 'OK' : 'No',
		{ to_tag: 'nt1', headers: hs ?? [] }));
	x.notify = (cseq, substate, body) => x.sub.on_message(CRLF([
		'NOTIFY sip:262991234567890@[2001:db8::5]:5064 SIP/2.0',
		'Via: SIP/2.0/UDP [2001:db8:ff::10]:7100;branch=z9hG4bKn' + cseq,
		'From: <' + IMPU + '>;tag=nt1', 'To: <' + IMPU + '>;tag=ft1', 'Call-ID: sub1@test',
		'CSeq: ' + cseq + ' NOTIFY', 'Event: reg', 'Subscription-State: ' + substate,
		'Content-Type: application/reginfo+xml', 'Content-Length: ' + length(body), '', body ]));
	return x;
}

let s = setup();
s.sub.start();
let sm = s.last().msg;
eq([ sm.method, sm.uri ], [ 'SUBSCRIBE', IMPU ], 'SUBSCRIBE to our own public identity');
eq([ s.last().dst, s.last().port, s.last().src ], [ PC, 7101, 5062 ], 'inside the SAs: port_c -> the P-CSCF\'s port_s');
eq([ SIP.get(sm, 'event'), SIP.get(sm, 'accept'), SIP.get(sm, 'expires') ], [ 'reg', 'application/reginfo+xml', '600000' ],
	'Event: reg, reginfo accepted, 600000 s asked');
eq(SIP.get(sm, 'route'), '<sip:orig@scscf.example.net;lr>', 'the Service-Route as Route');
ok(SIP.get(sm, 'security-verify') != null && SIP.get(sm, 'p-preferred-identity') == '<' + IMPU + '>' &&
	index(SIP.get(sm, 'contact'), HP) >= 0, 'Security-Verify, P-Preferred-Identity, our protected contact');
eq(s.sub.state, 'subscribing', 'state: subscribing');

// retransmission over UDP until answered
s.c.advance(500);
eq(length(s.sent), 2, 'retransmitted after T1');
eq(s.answer(200, [ [ 'Expires', '3600' ], [ 'Contact', '<sip:scscf.example.net:5060>' ] ]), true, 'the 200 is ours');
eq([ s.sub.state, s.sub.expires, s.sub.to_tag ], [ 'active', 3600, 'nt1' ], 'active, the granted expiry, the dialog');
s.c.advance(60000);
eq(length(s.sent), 2, 'no retransmission after the answer');

// the first NOTIFY: the full state, all well
eq(s.notify(1, 'active;expires=3600', reginfo(0, 'full', [
	registration(IMPU, 'active', [ contact('c1', 'active', 'registered', OURS) ]) ])), true, 'the NOTIFY is ours');
eq([ s.last().msg.status, s.last().port, s.last().src ], [ 200, 7101, 5062 ], 'NOTIFY answered 200, on our responses\' way');
eq(s.events, [], 'nothing to report');

// shortened, then a retransmission of the same document
let short_doc = reginfo(1, 'partial', [ registration(IMPU, 'active', [ contact('c1', 'active', 'shortened', OURS, ' expires="120"') ]) ]);
s.notify(2, 'active;expires=3500', short_doc);
eq(s.events, [ [ 'shortened', { what: 'shortened', expires: 120 } ] ], 'shortened reported');
s.notify(2, 'active;expires=3500', short_doc);
eq(length(s.events), 1, 'the same version again: answered, not reported twice');
eq(s.last().msg.status, 200, '... but answered');

// the network ends the registration
s.notify(3, 'terminated;reason=noresource', reginfo(2, 'partial', [
	registration(IMPU, 'terminated', [ contact('c1', 'terminated', 'deactivated', OURS) ]) ]));
eq(s.events[1], [ 'terminated', { what: 'terminated', event: 'deactivated' } ], 'terminated (deactivated) reported');
let n_sent = length(s.sent);
s.c.advance(120000);
eq(length(s.sent), n_sent, 'no new SUBSCRIBE: the registration is gone with it');

// messages that are not ours
eq(s.sub.on_message('SIP/2.0 200 OK\r\nCSeq: 1 SUBSCRIBE\r\nCall-ID: other\r\nContent-Length: 0\r\n\r\n'), false,
	'another Call-ID');
eq(s.sub.on_message('garbage'), false, 'not SIP');

// the refresh, inside the dialog
let r = setup();
r.sub.start();
r.answer(200, [ [ 'Expires', '3600' ], [ 'Contact', '<sip:scscf.example.net:5060>' ],
	[ 'Record-Route', '<sip:[2001:db8:ff::10]:7101;lr>' ] ]);
r.c.advance(2999000);
eq(length(r.sent), 1, 'refresh: not before expiry - 600 s');
r.c.advance(1000);
let rm = r.last().msg;
eq([ rm.method, rm.uri, SIP.cseq(rm).seq ], [ 'SUBSCRIBE', 'sip:scscf.example.net:5060', 2 ],
	'refresh: SUBSCRIBE to the notifier\'s Contact, next CSeq');
ok(index(SIP.get(rm, 'to'), 'tag=nt1') >= 0 && SIP.get(rm, 'route') == '<sip:[2001:db8:ff::10]:7101;lr>',
	'refresh: the dialog\'s To tag and route set');
r.answer(200, [ [ 'Expires', '3600' ] ]);
eq(r.sub.state, 'active', 'refresh: still active');

// the notifier ends the subscription, the registration stands: a new one, later
r.notify(1, 'terminated;reason=timeout', reginfo(0, 'full', [
	registration(IMPU, 'active', [ contact('c1', 'active', 'registered', OURS) ]) ]));
eq(r.events, [], 'subscription ended: nothing about the registration');
let before = length(r.sent);
r.c.advance(29000);
eq(length(r.sent), before, 'new subscription: not at once');
r.c.advance(1000);
let nm = r.last().msg;
ok(nm.method == 'SUBSCRIBE' && nm.uri == IMPU && SIP.param(SIP.get(nm, 'to'), 'tag') == null &&
	SIP.param(SIP.get(nm, 'from'), 'tag') != 'ft1', 'new subscription: a new dialog after 30 s');

// refused, and unanswered: reported as failed, the registration is not touched
let f = setup({ t1: 2000, t2: 16000 });
f.sub.start();
f.answer(403);
eq([ f.sub.state, f.events[0][0], f.events[0][1].status ], [ 'failed', 'failed', 403 ], '403: failed');
let t = setup({ t1: 2000, t2: 16000 });
t.sub.start();
t.c.advance(127000);
eq(t.sub.state, 'subscribing', 'the profile\'s T1: still trying before 64*T1');
t.c.advance(1000);
eq([ t.sub.state, t.events[0][1].error ], [ 'failed', 'timeout' ], 'Timer F: failed');

// closed: silent
let c = setup();
c.sub.start();
c.sub.close();
c.c.advance(64000);
eq([ length(c.sent), c.events, c.sub.state ], [ 1, [], 'closed' ], 'close: no retransmission, no event');
eq(c.answer(200), false, 'close: later messages are not taken');

done();
