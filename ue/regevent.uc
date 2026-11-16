// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// The UE's subscription to its own registration state (RFC 3680, 3GPP
// TS 24.229 5.1.1.3): SUBSCRIBE with Event: reg inside the SAs, and the
// NOTIFYs the S-CSCF sends with application/reginfo+xml. This is how the UE
// learns that the network ended the registration (the subscriber was
// deactivated, the S-CSCF wants a new authentication) or shortened it;
// without it the UE finds out at the next refresh, or when a call fails.
//
//   let s = REGEVENT.create({ ue_addr, port_c, port_s, pcscf: { addr, port_s },
//                             route, impu, contact_user, imei_urn, pani, sec_verify,
//                             timer, send, log, t1, t2, user_agent, expires,
//                             on_event(what, data) })
//   s.start()
//   s.on_message(buf) -> true when the message was this subscription's
//   s.close()
//
// on_event: 'terminated' { event }   our binding is gone; register again
//           'shortened'  { expires } re-authenticate before `expires` seconds
//           'failed'     { ... }     no subscription (the registration stands)
//
// No sockets and no timers of its own, as in ue/reg.uc. A subscription lives
// and dies with its registration: nothing is sent on close().

'use strict';

import * as fs from 'fs';
import { hostport } from 'ue_reg';

let SIP = require('sipd_sip');

const MMTEL = 'urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel';

function rnd_hex(n)
{
	let f = fs.open('/dev/urandom', 'r');
	let b = f ? f.read(n) : null;
	if (f)
		f.close();
	return hexenc(b ?? sprintf('%016x', time()));
}

// ---- reginfo (RFC 3680 5) -------------------------------------------------------

function attr(head, name)
{
	let m = match(head, regexp('(^|[ \t\r\n])' + name + '[ \t\r\n]*=[ \t\r\n]*["\']([^"\']*)["\']'));
	return m ? m[2] : null;
}

function unescape(s)
{
	s = replace(s, /&lt;/g, '<');
	s = replace(s, /&gt;/g, '>');
	s = replace(s, /&quot;/g, '"');
	s = replace(s, /&apos;/g, "'");
	return replace(s, /&amp;/g, '&');
}

// the element `chunk` begins in (what split() left after "<name "): its
// attributes up to the first '>', and its content up to the closing tag
function element(chunk, name)
{
	let end = index(chunk, '</' + name + '>');
	if (end >= 0)
		chunk = substr(chunk, 0, end);
	let gt = index(chunk, '>');
	return { head: (gt >= 0) ? substr(chunk, 0, gt) : chunk, body: (gt >= 0) ? substr(chunk, gt + 1) : '' };
}

// a reginfo document -> { state: 'full' | 'partial', version, registrations:
// [ { aor, state, contacts: [ { state, event, expires, uri } ] } ] }, or null
// when it is not one. Enough of XML for what S-CSCFs send; namespace prefixes
// on the elements are dropped.
export function parse_reginfo(xml)
{
	xml = replace(xml ?? '', /<(\/?)[A-Za-z0-9_.-]+:/g, '<$1');
	let top = match(xml, /<reginfo([^>]*)>/);
	if (!top)
		return null;

	let ver = attr(top[1], 'version');
	let out = { state: attr(top[1], 'state'), version: (ver != null) ? +ver : null, registrations: [] };
	let regs = split(xml, /<registration[ \t\r\n]+/);

	for (let i = 1; i < length(regs); i++) {
		let re = element(regs[i], 'registration');
		let r = { aor: unescape(attr(re.head, 'aor') ?? ''), state: attr(re.head, 'state'), contacts: [] };
		let cs = split(re.body, /<contact[ \t\r\n]+/);

		for (let j = 1; j < length(cs); j++) {
			let ce = element(cs[j], 'contact');
			let u = match(ce.body, /<uri[^>]*>([^<]*)<\/uri>/);
			let exp = attr(ce.head, 'expires');
			push(r.contacts, { state: attr(ce.head, 'state'), event: attr(ce.head, 'event'),
				expires: (exp != null) ? +exp : null, uri: u ? unescape(trim(u[1])) : null });
		}
		push(out.registrations, r);
	}
	return out;
}

// What a reginfo document says about OUR binding: `hp` is our contact's
// host:port as registered ("[2001:db8::5]:5064"), `impu` the identity we
// subscribed for. -> { what: 'terminated', event } | { what: 'shortened',
// expires } | null (nothing that concerns us, or all is well).
// Another contact of the same subscriber (the modem's own IMS, a second
// device) going away is not ours to act on.
export function fate(info, hp, impu)
{
	let regs = info?.registrations ?? [];
	let want = lc(hp ?? '');

	for (let r in regs)
		for (let c in r.contacts)
			if (length(want) && index(lc(c.uri ?? ''), want) >= 0) {
				if (c.state == 'terminated')
					return { what: 'terminated', event: c.event };
				if (c.event == 'shortened')
					return { what: 'shortened', expires: c.expires };
			}

	// a registration ended without its contacts being listed: ours when it
	// is the identity we subscribed for, or when a full document has none left
	let all_gone = length(regs) > 0;
	for (let r in regs)
		if (r.state != 'terminated')
			all_gone = false;
	for (let r in regs)
		if (r.state == 'terminated' && !length(r.contacts) &&
		    (r.aor == impu || (info.state == 'full' && all_gone)))
			return { what: 'terminated', event: null };
	return null;
}

// ---- the subscription -------------------------------------------------------------

export function create(o)
{
	let self = {
		state: 'idle',       // idle | subscribing | active | failed | closed
		call_id: o.call_id ?? (rnd_hex(12) + '@' + hostport(o.ue_addr)),
		from_tag: o.from_tag ?? rnd_hex(6),
		to_tag: null,
		remote: null,        // the notifier's Contact
		route_set: null,     // from Record-Route, reversed
		cseq: 0,
		expires: null,       // as granted
		version: null,       // the last reginfo version acted on
	};

	let log = o.log ?? (() => null);
	let timer = o.timer;
	let t1 = o.t1 ?? 500, t2 = o.t2 ?? 4000;
	let pending = null, refresh = null;
	let default_route = length(o.route ?? []) ? o.route : [ sprintf('<sip:%s;lr>', hostport(o.pcscf.addr, o.pcscf.port_s)) ];
	let contact = sprintf('<sip:%s@%s>;+sip.instance="<%s>";+g.3gpp.icsi-ref="%s"',
		o.contact_user, hostport(o.ue_addr, o.port_s), o.imei_urn, MMTEL);
	let our_hp = hostport(o.ue_addr, o.port_s);

	let stop_pending = () => {
		if (pending) {
			pending.handle?.cancel();
			pending.timer_f?.cancel();
		}
		pending = null;
	};

	let fail = (err) => {
		stop_pending();
		refresh?.cancel();
		refresh = null;
		if (self.state == 'closed')
			return;
		self.state = 'failed';
		log('warn', sprintf('reg-event: no subscription: %J', err));
		o.on_event?.('failed', err);
	};

	// one client transaction over UDP (RFC 3261 17.1.2.2), as in ue/reg.uc
	let transmit = (buf) => {
		stop_pending();
		let p = { buf: buf, wait: t1 };
		pending = p;
		p.timer_f = timer(64 * t1, () => {
			if (pending === p)
				fail({ error: 'timeout' });
		});
		let tick;
		tick = () => {
			if (pending !== p)
				return;
			o.send(p.buf, o.pcscf.addr, o.pcscf.port_s, o.port_c);
			p.handle = timer(p.wait, tick);
			p.wait = (p.wait * 2 > t2) ? t2 : p.wait * 2;
		};
		tick();
	};

	// the initial SUBSCRIBE, or (with a dialog) its refresh
	let subscribe = () => {
		self.cseq++;
		let hs = [
			[ 'Via', sprintf('SIP/2.0/UDP %s;branch=z9hG4bK%s;rport', hostport(o.ue_addr, o.port_s), rnd_hex(8)) ],
			[ 'Max-Forwards', '70' ],
		];
		for (let r in self.route_set ?? default_route)
			push(hs, [ 'Route', r ]);
		push(hs, [ 'From', sprintf('<%s>;tag=%s', o.impu, self.from_tag) ]);
		push(hs, [ 'To', sprintf('<%s>%s', o.impu, self.to_tag ? ';tag=' + self.to_tag : '') ]);
		push(hs, [ 'Call-ID', self.call_id ]);
		push(hs, [ 'CSeq', sprintf('%d SUBSCRIBE', self.cseq) ]);
		push(hs, [ 'Contact', contact ]);
		push(hs, [ 'Event', 'reg' ]);
		push(hs, [ 'Accept', 'application/reginfo+xml' ]);
		// TS 24.229 5.1.1.3: 600 000 s, the network grants what it likes
		push(hs, [ 'Expires', sprintf('%d', o.expires ?? 600000) ]);
		push(hs, [ 'P-Preferred-Identity', sprintf('<%s>', o.impu) ]);
		push(hs, [ 'Security-Verify', o.sec_verify ]);
		push(hs, [ 'Require', 'sec-agree' ]);
		push(hs, [ 'Proxy-Require', 'sec-agree' ]);
		push(hs, [ 'P-Access-Network-Info', o.pani ]);
		push(hs, [ 'User-Agent', o.user_agent ?? 'wwand-ims' ]);

		if (self.state != 'active')
			self.state = 'subscribing';
		transmit(SIP.build(sprintf('SUBSCRIBE %s SIP/2.0', self.remote ?? o.impu), hs, ''));
	};

	let schedule = (exp) => {
		refresh?.cancel();
		refresh = null;
		if (!exp)
			return;
		// well before it runs out; a registration refresh replaces the
		// subscription long before that on most networks
		let at_s = (exp > 1200) ? exp - 600 : int(exp / 2);
		refresh = timer(at_s * 1000, () => {
			refresh = null;
			if (self.state == 'active')
				subscribe();
		});
	};

	// a subscription the notifier ended while the registration stands: a new
	// one (a new dialog), not at once
	let again = () => {
		refresh?.cancel();
		refresh = timer(30000, () => {
			refresh = null;
			if (self.state == 'closed')
				return;
			self.to_tag = null;
			self.remote = null;
			self.route_set = null;
			self.from_tag = rnd_hex(6);
			self.state = 'idle';
			subscribe();
		});
	};

	let on_response = (msg) => {
		let cs = SIP.cseq(msg);
		if (cs?.method != 'SUBSCRIBE' || cs.seq != self.cseq || !pending || msg.status < 200)
			return;
		stop_pending();
		if (msg.status >= 300)
			return fail({ error: 'status', status: msg.status, reason: msg.reason });

		let tag = SIP.param(SIP.get(msg, 'to'), 'tag');
		if (tag != null)
			self.to_tag = tag;
		let c = SIP.get(msg, 'contact');
		if (c)
			self.remote = SIP.uri_of(c);
		let rr = SIP.all(msg, 'record-route');
		if (length(rr))
			self.route_set = reverse(rr);
		let exp = SIP.get(msg, 'expires');
		self.expires = (exp != null) ? +exp : null;
		if (self.state != 'active')
			log('info', sprintf('reg-event: subscribed, expires %s s', self.expires ?? '?'));
		self.state = 'active';
		schedule(self.expires);
	};

	let on_notify = (msg) => {
		// answered first, and on the way our responses take (U:port_c -> P:port_s)
		o.send(SIP.response(msg, 200, 'OK'), o.pcscf.addr, o.pcscf.port_s, o.port_c);

		let ss = lc(SIP.get(msg, 'subscription-state') ?? '');
		let info = parse_reginfo(msg.body);
		let f = null;

		if (info) {
			// a retransmitted or late document says nothing new (RFC 3680 5.1)
			if (info.version != null && self.version != null && info.version <= self.version &&
			    substr(ss, 0, 10) != 'terminated')
				return;
			if (info.version != null)
				self.version = info.version;
			f = fate(info, our_hp, o.impu);
		}
		else if (length(msg.body ?? ''))
			log('debug', 'reg-event: a NOTIFY body that is not reginfo');

		if (f) {
			log('info', sprintf('reg-event: our registration %s%s', f.what,
				f.event ? ' (' + f.event + ')' : ''));
			o.on_event?.(f.what, f);
		}
		if (substr(ss, 0, 10) == 'terminated' && self.state != 'closed') {
			stop_pending();
			if (f?.what == 'terminated') {
				// the registration goes with it; whoever registers anew subscribes anew
				refresh?.cancel();
				refresh = null;
				self.state = 'failed';
				return;
			}
			log('info', sprintf('reg-event: the subscription ended (%s); subscribing again in 30 s', ss));
			self.state = 'failed';
			again();
		}
	};

	self.start = function() {
		if (self.state == 'idle')
			subscribe();
	};

	self.on_message = function(buf) {
		let msg = SIP.parse(buf);
		if (!msg || self.state == 'closed' || SIP.get(msg, 'call-id') != self.call_id)
			return false;
		if (msg.status != null) {
			on_response(msg);
			return true;
		}
		if (msg.method != 'NOTIFY')
			return false;
		on_notify(msg);
		return true;
	};

	self.close = function() {
		stop_pending();
		refresh?.cancel();
		refresh = null;
		self.state = 'closed';
	};

	return self;
}
