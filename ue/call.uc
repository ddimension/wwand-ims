// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// One outgoing IMS call on the UE side (RFC 3261 UAC, RFC 3262 PRACK, TS
// 24.229 5.1.2A / 5.1.3), inside the SAs of a registration (ue/reg.uc):
//
//   INVITE  U:port_c -> P:port_s, Via = our protected server port, Route =
//           the Service-Route (or the P-CSCF), Security-Verify as registered;
//   18x     early dialog; Require: 100rel -> PRACK (RAck);
//   2xx     ACK (end to end, new branch), confirmed; BYE ends it;
//   >= 300  ACK (hop by hop, the INVITE's branch), failed;
//   cancel  CANCEL once a provisional came (RFC 3261 9.1), then 487 -> ACK.
//
// Requests from the network (BYE, UPDATE, re-INVITE, OPTIONS, NOTIFY in the
// dialog) arrive P:port_c -> U:port_s. They are answered as the P-CSCF
// answers ours: to the port in its Via (its protected server port), from our
// client port, i.e. U:port_c -> P:port_s, the SA every request of ours uses.
// Vodafone DE (Nokia/ALU) sends its responses to our Via port the same way
// and drops ours when they come back on the U:port_s -> P:port_c pair:
// the OPTIONS / BYE were retransmitted as if never answered (HW, 2026-11-14).
// No preconditions yet (offered without; IR.92 lets the network do without).
// No sockets here, as in ue/reg.uc: send(buf, dst, port, src), timer(ms, fn).
// Emergency numbers are refused before anything is sent: this UE does not
// do emergency calls yet (TS 24.229 5.1.6 would need an emergency PDN and
// registration).

'use strict';

import * as fs from 'fs';

let SIP = require('sipd_sip');

const MMTEL_URN = 'urn:urn-7:3gpp-service.ims.icsi.mmtel';
const MMTEL = 'urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel';
const ALLOW = 'INVITE, ACK, CANCEL, BYE, UPDATE, PRACK, MESSAGE, OPTIONS, NOTIFY, REFER, INFO';

// dialled as is or national; the short codes and their +49 forms
const EMERGENCY = [ '112', '110', '911', '999', '000', '08', '118', '+49110', '+49112' ];

export function is_emergency(number)
{
	let n = replace(number ?? '', /[- \/().]/g, '');
	return index(EMERGENCY, n) >= 0 || match(n, /^(\+|00)[0-9]{1,3}11[02]$/) != null;
}

// an E.164 number as a tel URI (RFC 3966); anything else is refused
export function tel_uri(number)
{
	let n = replace(number ?? '', /[- \/().]/g, '');
	return match(n, /^\+[1-9][0-9]{4,14}$/) ? 'tel:' + n : null;
}

function hostport(addr, port)
{
	let h = index(addr, ':') >= 0 ? '[' + addr + ']' : addr;
	return port ? h + ':' + port : h;
}

function rnd_hex(n)
{
	let f = fs.open('/dev/urandom', 'r');
	let b = f ? f.read(n) : null;
	if (f)
		f.close();
	return hexenc(b ?? sprintf('%016x', time()));
}

// the offer: AMR-WB and AMR (bandwidth-efficient), DTMF for both clocks,
// as GSMA IR.92 2.4 wants them. Media is passed through 1:1 later, so the
// offer lists what the LAN side can take; for now only what the network does.
// ---- preconditions (RFC 3312, segmented, TS 24.229 6.1.2) -------------------
//
// qos = { local: bool, remote: bool, conf: bool }: whether our segment
// (local) and the peer's (remote) have their resources (the QCI 1 bearer),
// and whether we ask the peer to confirm when its segment is ready. Both
// desired strengths are mandatory sendrecv (the remote one optional in an
// offer, as 24.229 lets the answerer raise it).
export function qos_lines(qos, offer)
{
	let l = [
		sprintf('a=curr:qos local %s', qos.local ? 'sendrecv' : 'none'),
		sprintf('a=curr:qos remote %s', qos.remote ? 'sendrecv' : 'none'),
		'a=des:qos mandatory local sendrecv',
		sprintf('a=des:qos %s remote sendrecv', offer ? 'optional' : 'mandatory'),
	];
	if (qos.conf)
		push(l, 'a=conf:qos remote sendrecv');
	return l;
}

// the precondition state a peer SDP reports, from the peer's view: `local`
// is its own segment (our remote), `remote` its view of ours, `conf` whether
// it wants us to confirm ours. null when the SDP has no qos preconditions.
export function qos_parse(sdp)
{
	let r = { local: false, remote: false, conf: false, any: false };
	for (let l in split(replace(sdp ?? '', /\r/g, ''), '\n')) {
		let m = match(l, /^a=(curr|des|conf):qos (\S+ )?(local|remote) (none|send|recv|sendrecv)$/);
		if (!m)
			continue;
		r.any = true;
		if (m[1] == 'curr')
			r[m[3]] = (m[4] == 'sendrecv');
		else if (m[1] == 'conf' && m[3] == 'remote' && m[4] != 'none')
			r.conf = true;
	}
	return r.any ? r : null;
}

export function sdp_offer(addr, port, session, qos, version)
{
	let fam = index(addr, ':') >= 0 ? 'IP6' : 'IP4';
	let s = [
		'v=0',
		sprintf('o=wwand-ims %d %d IN %s %s', session, version ?? session, fam, addr),
		's=-',
		sprintf('c=IN %s %s', fam, addr),
		'b=AS:41',
		't=0 0',
		sprintf('m=audio %d RTP/AVP 97 98 100 101', port),
		'b=AS:41',
		'a=rtpmap:97 AMR-WB/16000/1',
		'a=fmtp:97 mode-change-capability=2;max-red=0',
		'a=rtpmap:98 AMR/8000/1',
		'a=fmtp:98 mode-change-capability=2;max-red=0',
		'a=rtpmap:100 telephone-event/16000',
		'a=fmtp:100 0-15',
		'a=rtpmap:101 telephone-event/8000',
		'a=fmtp:101 0-15',
		'a=ptime:20',
		'a=maxptime:240',
		'a=sendrecv',
	];
	if (qos)
		push(s, ...qos_lines(qos, true));
	return join('\r\n', s) + '\r\n';
}

// the answer to a network offer: the first of AMR-WB, AMR it carries, with
// the offer's payload type and fmtp (octet-align, mode-set stay as offered:
// the media is passed through, not re-encoded), plus its telephone-event of
// the same clock. null when neither codec is offered.
export function sdp_answer(offer, addr, port, session, qos, version)
{
	let pts = null, rtpmap = {}, fmtp = {};
	let in_audio = false;
	for (let l in split(replace(offer ?? '', /\r/g, ''), '\n')) {
		let m;
		if ((m = match(l, /^m=(\S+) [0-9]+ RTP\/AVP (.*)$/))) {
			in_audio = (m[1] == 'audio');
			if (in_audio && pts == null)
				pts = split(trim(m[2]), /\s+/);
		}
		else if (in_audio && (m = match(l, /^a=rtpmap:([0-9]+) (.+)$/)))
			rtpmap[m[1]] = trim(m[2]);
		else if (in_audio && (m = match(l, /^a=fmtp:([0-9]+) (.+)$/)))
			fmtp[m[1]] = trim(m[2]);
	}
	let pick = (re) => filter(pts ?? [], (p) => match(rtpmap[p] ?? '', re))[0];
	let codec = pick(/^AMR-WB\/16000/i), rate = 16000;
	if (codec == null) {
		codec = pick(/^AMR\/8000/i);
		rate = 8000;
	}
	if (codec == null)
		return null;
	let dtmf = pick(rate == 16000 ? /^telephone-event\/16000/i : /^telephone-event\/8000/i);

	let fam = index(addr, ':') >= 0 ? 'IP6' : 'IP4';
	let s = [
		'v=0',
		sprintf('o=wwand-ims %d %d IN %s %s', session, version ?? session, fam, addr),
		's=-',
		sprintf('c=IN %s %s', fam, addr),
		't=0 0',
		sprintf('m=audio %d RTP/AVP %s', port, dtmf != null ? codec + ' ' + dtmf : codec),
		'b=AS:41',
		sprintf('a=rtpmap:%s %s', codec, rtpmap[codec]),
	];
	if (fmtp[codec])
		push(s, sprintf('a=fmtp:%s %s', codec, fmtp[codec]));
	if (dtmf != null) {
		push(s, sprintf('a=rtpmap:%s %s', dtmf, rtpmap[dtmf]));
		push(s, sprintf('a=fmtp:%s 0-15', dtmf));
	}
	push(s, 'a=ptime:20', 'a=maxptime:240', 'a=sendrecv');
	if (qos)
		push(s, ...qos_lines(qos, false));
	return join('\r\n', s) + '\r\n';
}

// The audio of `src` (an SDP from the other leg of a B2BUA) for this leg:
// only AMR-WB, AMR and telephone-event, with their payload types, rtpmap
// and fmtp unchanged, so the RTP can be relayed 1:1 (no transcoding, no
// payload type rewrite); address and port are ours. null when src carries
// neither AMR-WB nor AMR.
export function sdp_relay(src, addr, port, session, qos, version)
{
	let pts = null, rtpmap = {}, fmtp = {};
	let in_audio = false;
	for (let l in split(replace(src ?? '', /\r/g, ''), '\n')) {
		let m;
		if ((m = match(l, /^m=(\S+) [0-9]+ RTP\/AVP (.*)$/))) {
			in_audio = (m[1] == 'audio');
			if (in_audio && pts == null)
				pts = split(trim(m[2]), /\s+/);
		}
		else if (in_audio && (m = match(l, /^a=rtpmap:([0-9]+) (.+)$/)))
			rtpmap[m[1]] = trim(m[2]);
		else if (in_audio && (m = match(l, /^a=fmtp:([0-9]+) (.+)$/)))
			fmtp[m[1]] = trim(m[2]);
	}
	let keep = filter(pts ?? [], (p) => match(rtpmap[p] ?? '', /^(AMR-WB|AMR|telephone-event)\//i));
	if (!length(filter(keep, (p) => match(rtpmap[p], /^AMR/i))))
		return null;

	let fam = index(addr, ':') >= 0 ? 'IP6' : 'IP4';
	let s = [
		'v=0',
		sprintf('o=wwand-ims %d %d IN %s %s', session, version ?? session, fam, addr),
		's=-',
		sprintf('c=IN %s %s', fam, addr),
		't=0 0',
		sprintf('m=audio %d RTP/AVP %s', port, join(' ', keep)),
		'b=AS:41',
	];
	for (let p in keep) {
		push(s, sprintf('a=rtpmap:%s %s', p, rtpmap[p]));
		if (fmtp[p])
			push(s, sprintf('a=fmtp:%s %s', p, fmtp[p]));
	}
	push(s, 'a=ptime:20', 'a=maxptime:240', 'a=sendrecv');
	if (qos)
		push(s, ...qos_lines(qos, true));
	return join('\r\n', s) + '\r\n';
}

// the far end's RTP address in an SDP: { address, port } or null
export function sdp_media(sdp)
{
	let c = match(sdp ?? '', /(^|\n)c=IN IP[46] ([^\r\n ]+)/);
	let m = match(sdp ?? '', /(^|\n)m=audio ([0-9]+) /);
	return (c && m) ? { address: c[2], port: +m[2] } : null;
}

// o: { ue_addr, port_c, port_s, pcscf: { addr, port_s, port_c }, route: [ ... ],
//      impu, contact_user, imei_urn, pani, sec_verify, rtp_port, timer, send,
//      log, t1, user_agent, call_id, from_tag, preconditions, qos_wait, mt_mode,
//      alert_delay }
//
// preconditions (default true): offer them on dial(), and use them on an
// incoming call whose offer carries them. qos_wait(cb) is called once per
// call that uses them and calls cb() when our own segment is ready (the QCI 1
// bearer on the IMS PDN); without it our segment counts as ready at once.
export function create(o)
{
	let self = {
		role: 'uac',       // uac (dial) | uas (incoming)
		uas: null,         // { invite, local, peer, rr, rseq, answer_buf, ... } while incoming
		state: 'idle',     // idle | calling | early | incoming | answering | confirmed | cancelling | terminating | ended
		call_id: o.call_id ?? (rnd_hex(12) + '@' + hostport(o.ue_addr)),
		from_tag: o.from_tag ?? rnd_hex(6),
		to_tag: null,
		target: null,      // the Request-URI of the INVITE
		remote: null,      // the remote target (Contact of the answer)
		route_set: null,   // from Record-Route, reversed (RFC 3261 12.1.2)
		cseq: 0,
		invite: null,      // { branch, cseq, buf }
		answer: null,      // the SDP answer
		prack_done: {},    // RSeq -> true
		status: null,      // the INVITE's final status
		ended: null,       // why
		pre: null,         // preconditions: { local, remote, told_local, prack_ok, update_sent, rung }
	};

	let log = o.log ?? (() => null);
	let timer = o.timer;
	let t1 = o.t1 ?? 500, t2 = o.t2 ?? 4000;
	let txs = {};          // branch -> { method, timers, cb }
	let ev = () => null;
	let session = time();
	let version = session;
	let next_ver = () => ++version;
	let on_local_ready = null;     // set below, per role
	let offer_fn = null;           // MO: builds our offer (dial opts.offer)

	// our segment: the hook (or at once), then on_local_ready()
	let qos_start = () => {
		let done = false;
		let go = () => {
			if (done || self.state == 'ended' || !self.pre)
				return;
			done = true;
			self.pre.local = true;
			log('info', 'call: local QoS ready');
			on_local_ready?.();
		};
		if (o.qos_wait)
			o.qos_wait(go);
		else
			timer(0, go);
	};

	let default_route = length(o.route ?? []) ? o.route : [ sprintf('<sip:%s;lr>', hostport(o.pcscf.addr, o.pcscf.port_s)) ];
	let contact = sprintf('<sip:%s@%s>;+sip.instance="<%s>";+g.3gpp.icsi-ref="%s"',
		o.contact_user, hostport(o.ue_addr, o.port_s), o.imei_urn, MMTEL);

	let emit = (name, data) => {
		log('info', sprintf('call: %s%s', name, data != null ? sprintf(' %J', data) : ''));
		ev(name, data);
	};

	let tx_stop = (branch) => {
		let t = txs[branch];
		if (!t)
			return;
		t.retx?.cancel();
		t.timeout?.cancel();
		delete txs[branch];
	};

	// one client transaction (RFC 3261 17.1): Timer A/E from T1 doubling (E
	// capped at T2), Timer B/F = 64*T1. An INVITE stops retransmitting on the
	// first provisional and lives on until its final response.
	let tx_start = (method, branch, buf, cb) => {
		let t = { method: method, wait: t1, cb: cb, buf: buf };
		txs[branch] = t;
		t.timeout = timer(64 * t1, () => {
			if (txs[branch] !== t)
				return;
			tx_stop(branch);
			cb(null);      // timeout
		});
		let tick;
		tick = () => {
			if (txs[branch] !== t)
				return;
			o.send(t.buf, o.pcscf.addr, o.pcscf.port_s, o.port_c);
			t.retx = timer(t.wait, tick);
			t.wait = (method == 'INVITE' || t.wait * 2 <= t2) ? t.wait * 2 : t2;
		};
		tick();
	};

	let via = (branch) => sprintf('SIP/2.0/UDP %s;branch=%s;rport', hostport(o.ue_addr, o.port_s), branch);

	let common = (hs) => {
		push(hs, [ 'Security-Verify', o.sec_verify ]);
		push(hs, [ 'Require', 'sec-agree' ]);
		push(hs, [ 'Proxy-Require', 'sec-agree' ]);
		push(hs, [ 'P-Access-Network-Info', o.pani ]);
		push(hs, [ 'User-Agent', o.user_agent ?? 'wwand-ims' ]);
		return hs;
	};

	let to_hdr = () => sprintf('<%s>%s', self.target, self.to_tag ? ';tag=' + self.to_tag : '');

	// the MO From: anonymous when the caller withholds the number (self.anon,
	// from dial()'s opts.privacy), else our IMPU. The same value goes on the
	// INVITE, CANCEL, ACK and every in-dialog request so the dialog ids match.
	// P-Preferred-Identity still carries the real IMPU and Privacy: id asks the
	// network to withhold it from the callee (RFC 3323/3325, TS 24.229 5.1.3).
	let mo_from = () => sprintf('%s;tag=%s',
		self.anon ? '"Anonymous" <sip:anonymous@anonymous.invalid>' : sprintf('<%s>', o.impu),
		self.from_tag);

	// a request inside the dialog (PRACK, BYE, ACK for 2xx). As UAS our From
	// is the INVITE's To with our tag, our To its From (RFC 3261 12.2.1.1)
	let in_dialog = (method, branch, cseq, extra, body) => {
		let hs = [ [ 'Via', via(branch) ], [ 'Max-Forwards', '70' ] ];
		for (let r in self.route_set ?? default_route)
			push(hs, [ 'Route', r ]);
		if (self.role == 'uas') {
			push(hs, [ 'From', self.uas.local ]);
			push(hs, [ 'To', self.uas.peer ]);
		}
		else {
			push(hs, [ 'From', mo_from() ]);
			push(hs, [ 'To', to_hdr() ]);
		}
		push(hs, [ 'Call-ID', self.call_id ]);
		push(hs, [ 'CSeq', sprintf('%d %s', cseq, method) ]);
		for (let h in extra ?? [])
			push(hs, h);
		common(hs);
		return SIP.build(sprintf('%s %s SIP/2.0', method, self.remote ?? self.target), hs, body);
	};

	let finish = (why, data) => {
		if (self.state == 'ended')
			return;
		self.state = 'ended';
		self.ended = why;
		for (let b in keys(txs))
			tx_stop(b);
		emit('ended', { ...(data ?? {}), reason: why });
	};

	// ACK for a final non-2xx: hop by hop, the INVITE's branch and Route
	let ack_error = (msg) => {
		let hs = [ [ 'Via', via(self.invite.branch) ], [ 'Max-Forwards', '70' ] ];
		for (let r in default_route)
			push(hs, [ 'Route', r ]);
		push(hs, [ 'From', mo_from() ]);
		push(hs, [ 'To', SIP.get(msg, 'to') ]);
		push(hs, [ 'Call-ID', self.call_id ]);
		push(hs, [ 'CSeq', sprintf('%d ACK', self.invite.cseq) ]);
		o.send(SIP.build(sprintf('ACK %s SIP/2.0', self.target), common(hs), ''),
			o.pcscf.addr, o.pcscf.port_s, o.port_c);
	};

	let ack_2xx = () => {
		o.send(in_dialog('ACK', 'z9hG4bK' + rnd_hex(8), self.invite.cseq), o.pcscf.addr, o.pcscf.port_s, o.port_c);
	};

	// the dialog state a response with a To tag carries (RFC 3261 12.1.2)
	let learn_dialog = (msg) => {
		let tag = SIP.param(SIP.get(msg, 'to'), 'tag');
		if (tag != null)
			self.to_tag = tag;
		let c = SIP.get(msg, 'contact');
		if (c)
			self.remote = SIP.uri_of(c);
		let rr = SIP.all(msg, 'record-route');
		if (length(rr))
			self.route_set = reverse(rr);
	};

	// an UPDATE in the dialog with an SDP offer; cb(response or null)
	let send_update = (body, cb) => {
		let branch = 'z9hG4bK' + rnd_hex(8);
		let buf = in_dialog('UPDATE', branch, ++self.cseq,
			[ [ 'Contact', contact ], [ 'Content-Type', 'application/sdp' ] ], body);
		tx_start('UPDATE', branch, buf, cb);
	};

	// MO: tell the far end our segment is up (RFC 3312 5.1), once the early
	// dialog has its answer and the PRACK went through
	let mo_update = () => {
		let p = self.pre;
		// an UPDATE offer is only allowed once the INVITE offer has its answer
		// (RFC 3311 5): a 180 without SDP (Vodafone skips the 183) is not one
		if (!p || !p.local || p.told_local || p.update_sent || !p.prack_ok || !p.answered || self.state != 'early')
			return;
		p.update_sent = true;
		send_update(offer_fn({ local: true, remote: p.remote }, next_ver()), (r) => {
			if (!r || r.status >= 300)
				return log('warn', sprintf('call: UPDATE %s', r ? r.status : 'timed out'));
			p.told_local = true;
			let q = qos_parse(r.body);
			if (q)
				p.remote = q.local;
		});
	};

	// false for a retransmitted reliable provisional (RFC 3262 4: same RSeq)
	let prack = (msg) => {
		let rseq = SIP.get(msg, 'rseq');
		if (rseq == null)
			return true;
		if (self.prack_done[rseq])
			return false;
		self.prack_done[rseq] = true;
		let branch = 'z9hG4bK' + rnd_hex(8);
		let buf = in_dialog('PRACK', branch, ++self.cseq,
			[ [ 'RAck', sprintf('%s %d INVITE', rseq, self.invite.cseq) ] ]);
		tx_start('PRACK', branch, buf, (r) => {
			if (!r)
				return log('warn', 'call: PRACK timed out');
			if (self.pre) {
				self.pre.prack_ok = true;
				mo_update();
			}
		});
		return true;
	};

	let on_invite_response = (msg) => {
		let t = txs[self.invite.branch];

		if (msg.status < 200) {
			if (t) {
				t.retx?.cancel();
				t.retx = null;
				t.timeout?.cancel();
				t.timeout = null;
			}
			if (msg.status == 100) {
				self.got_1xx = true;
				emit('trying');
				// a hangup before any provisional: the CANCEL may go now (RFC 3261 9.1)
				if (self.cancel_pending)
					self.cancel();
				return;
			}
			learn_dialog(msg);
			self.got_1xx = true;
			if (self.state == 'calling')
				self.state = 'early';
			if (self.cancel_pending)
				return self.cancel();
			if (length(msg.body ?? '')) {
				self.answer = msg.body;
				if (self.pre) {
					let q = qos_parse(msg.body);
					if (!q) {
						log('info', 'call: the answer has no preconditions; going on without');
						self.pre = null;
					}
					else {
						self.pre.remote = q.local;
						self.pre.answered = true;
					}
				}
			}
			let req = lc(SIP.get(msg, 'require') ?? '');
			if (index(req, '100rel') >= 0) {
				if (!prack(msg))
					return;
			}
			else if (self.pre) {
				self.pre.prack_ok = true;
				mo_update();
			}
			emit(msg.status == 180 ? 'ringing' : 'progress', { status: msg.status, phrase: msg.reason,
				sdp: length(msg.body ?? '') > 0, body: length(msg.body ?? '') ? msg.body : null });
			return;
		}

		self.status = msg.status;

		if (msg.status < 300) {
			let first = (self.state != 'confirmed' && self.state != 'terminating');
			tx_stop(self.invite.branch);
			learn_dialog(msg);
			if (length(msg.body ?? ''))
				self.answer = msg.body;
			ack_2xx();
			if (first) {
				let cancelled = (self.state == 'cancelling');
				self.state = 'confirmed';
				emit('answered', { status: msg.status, body: self.answer });
				if (cancelled)    // the answer crossed our CANCEL: end it properly
					self.hangup();
			}
			return;
		}

		// a retransmitted final is ACKed again; the transaction is gone by then
		ack_error(msg);
		if (self.state == 'ended')
			return;
		tx_stop(self.invite.branch);
		finish(self.state == 'cancelling' && msg.status == 487 ? 'cancelled' : 'rejected',
			{ status: msg.status, phrase: msg.reason, warning: SIP.get(msg, 'warning') });
	};

	// dial(number, cb(event, data)); events: trying, progress, ringing,
	// answered, ended { reason, status? }
	// opts.offer(qos, version): the SDP offer to send (a B2BUA's other leg,
	// see sdp_relay); default our own AMR-WB/AMR offer
	self.dial = function(number, cb, opts) {
		ev = cb ?? ev;
		if (is_emergency(number))
			return finish('refused', { detail: 'emergency calls are not supported yet' });
		let uri = tel_uri(number);
		if (!uri)
			return finish('refused', { detail: 'not an E.164 number: ' + number });

		self.target = uri;
		self.state = 'calling';
		self.anon = !!opts?.privacy;	// CLIR: withhold our number from the callee
		let branch = 'z9hG4bK' + rnd_hex(8);
		if (o.preconditions !== false)
			self.pre = { local: false, remote: false };
		offer_fn = opts?.offer ?? ((qos, ver) => sdp_offer(o.ue_addr, o.rtp_port, session, qos, ver));
		let body = offer_fn(self.pre ? { local: false, remote: false } : null, version);
		let hs = [ [ 'Via', via(branch) ], [ 'Max-Forwards', '70' ] ];
		for (let r in default_route)
			push(hs, [ 'Route', r ]);
		push(hs, [ 'From', mo_from() ]);
		push(hs, [ 'To', sprintf('<%s>', uri) ]);
		push(hs, [ 'Call-ID', self.call_id ]);
		push(hs, [ 'CSeq', sprintf('%d INVITE', ++self.cseq) ]);
		push(hs, [ 'Contact', contact ]);
		push(hs, [ 'P-Preferred-Identity', sprintf('<%s>', o.impu) ]);
		if (self.anon)
			push(hs, [ 'Privacy', 'id' ]);
		push(hs, [ 'P-Preferred-Service', MMTEL_URN ]);
		push(hs, [ 'Accept-Contact', sprintf('*;+g.3gpp.icsi-ref="%s"', MMTEL) ]);
		push(hs, [ 'Supported', self.pre ? '100rel, precondition, timer, replaces' : '100rel, timer, replaces' ]);
		push(hs, [ 'Allow', ALLOW ]);
		push(hs, [ 'Content-Type', 'application/sdp' ]);
		common(hs);

		on_local_ready = mo_update;
		if (self.pre)
			qos_start();
		let buf = SIP.build(sprintf('INVITE %s SIP/2.0', uri), hs, body);
		self.invite = { branch: branch, cseq: self.cseq, buf: buf, route: default_route };
		tx_start('INVITE', branch, buf, (r) => {
			if (!r)
				finish('timeout', { state: self.state });
		});
	};

	// CANCEL before the answer (only after a provisional, RFC 3261 9.1)
	self.cancel = function() {
		if (self.state != 'early' && !(self.state == 'calling' && self.got_1xx))
			return false;
		self.cancel_pending = false;
		self.state = 'cancelling';
		let hs = [ [ 'Via', via(self.invite.branch) ], [ 'Max-Forwards', '70' ] ];
		for (let r in default_route)
			push(hs, [ 'Route', r ]);
		push(hs, [ 'From', mo_from() ]);
		push(hs, [ 'To', sprintf('<%s>', self.target) ]);
		push(hs, [ 'Call-ID', self.call_id ]);
		push(hs, [ 'CSeq', sprintf('%d CANCEL', self.invite.cseq) ]);
		let buf = SIP.build(sprintf('CANCEL %s SIP/2.0', self.target), common(hs), '');
		// the CANCEL has the INVITE's branch; keyed apart so both live
		tx_start('CANCEL', self.invite.branch + '/cancel', buf, (r) => {
			if (!r)
				finish('timeout', { state: 'cancelling' });
		});
		return true;
	};

	// BYE once confirmed; CANCEL while early. cb() once it is over.
	self.hangup = function(cb) {
		if (cb)
			ev = ((prev) => (n, d) => { prev(n, d); if (n == 'ended') cb(d); })(ev);
		if (self.state == 'early' || (self.state == 'calling' && self.got_1xx))
			return self.cancel();
		// before any provisional a CANCEL may not go yet (RFC 3261 9.1): it
		// goes with the first one; the call ends with the 487 then
		if (self.state == 'calling') {
			self.cancel_pending = true;
			return true;
		}
		if (self.state == 'incoming')
			return self.reject(603, 'Decline');
		if (self.state == 'answering') {
			self.uas.bye_after_ack = true;    // the dialog is not confirmed yet
			return true;
		}
		if (self.state != 'confirmed') {
			if (self.state != 'ended' && self.state != 'terminating')
				finish('local', null);
			return false;
		}
		self.state = 'terminating';
		let branch = 'z9hG4bK' + rnd_hex(8);
		tx_start('BYE', branch, in_dialog('BYE', branch, ++self.cseq), (r) => {
			finish('local', r ? { status: r.status } : { detail: 'BYE timed out' });
		});
		return true;
	};

	// answer a request from the network (it came P:port_c -> U:port_s; the
	// answer goes U:port_c -> P:port_s, see the top of the file)
	let reply = (req, status, reason, extra, body) => {
		o.send(SIP.response(req, status, reason, { headers: extra }, body), o.pcscf.addr, o.pcscf.port_s, o.port_c);
	};

	// ---- incoming (UAS, RFC 3261 13.3 / 17.2.1, RFC 3262 3) --------------------
	//
	// INVITE   -> 100, then 180 (reliable with RSeq when the INVITE requires
	//             100rel; retransmitted until the PRACK); `incoming` event;
	// accept() -> 200 with the SDP answer, retransmitted (Timer G) until the
	//             ACK, which confirms the dialog (`answered`); no ACK within
	//             64*T1 (Timer H) -> BYE;
	// reject() -> a final error; CANCEL from the network -> 200 + 487.
	// Responses go U:port_c -> P:port_s, as reply() (see the top of the file).

	let uas_send = (buf) => o.send(buf, o.pcscf.addr, o.pcscf.port_s, o.port_c);

	// a response to the INVITE: with our To tag (not on 100) and, for one that
	// makes the dialog, its Record-Route copied (RFC 3261 12.1.1)
	let uas_resp = (status, reason, extra, body) => {
		let u = self.uas;
		let hs = [];
		if (status > 100)
			for (let r in u.rr)
				push(hs, [ 'Record-Route', r ]);
		for (let h in extra ?? [])
			push(hs, h);
		return SIP.response(u.invite, status, reason, { to_tag: status > 100 ? self.from_tag : null, headers: hs }, body);
	};

	let uas_stop = () => {
		let u = self.uas;
		u.retx?.cancel();
		u.retx = null;
		u.timeout?.cancel();
		u.timeout = null;
	};

	// send buf now and again at T1, 2*T1, ... capped at T2, until stopped;
	// on_timeout after 64*T1
	let uas_repeat = (buf, on_timeout) => {
		let u = self.uas;
		uas_stop();
		u.last = buf;
		let wait = t1;
		let tick;
		tick = () => {
			if (u.last !== buf)
				return;
			uas_send(buf);
			u.retx = timer(wait, tick);
			wait = (wait * 2 <= t2) ? wait * 2 : t2;
		};
		tick();
		u.timeout = timer(64 * t1, () => {
			if (u.last !== buf)
				return;
			uas_stop();
			on_timeout();
		});
	};

	let uas_final_error = (status, reason, why, extra) => {
		let buf = uas_resp(status, reason, extra);
		uas_stop();
		self.uas.last = buf;
		uas_send(buf);        // the network ACKs it hop by hop; nothing waits
		finish(why, { status: status, phrase: reason });
	};

	// MT with preconditions: once the 183 is PRACKed, tell the caller when our
	// segment is up (UPDATE, unless an answer of ours already said so), and
	// alert (180) when both segments are (RFC 3312 5.1; 24.229 6.1.2)
	let mt_ring = () => {
		let p = self.pre, u = self.uas;
		if (!p.local || !p.remote || !p.told_local || p.rung || u.hold || self.state != 'incoming')
			return;
		p.rung = true;
		// reliable like the 183 before it (the INVITE supports 100rel: we used it)
		uas_repeat(uas_resp(180, 'Ringing', [ [ 'Contact', contact ], [ 'Allow', ALLOW ],
			[ 'Require', '100rel' ], [ 'RSeq', sprintf('%d', ++u.rseq) ] ]),
			() => log('warn', 'call: no PRACK for the 180'));
		emit('incoming', { from: u.peer, offer: true, preconditions: true });
	};

	let mt_check = () => {
		let p = self.pre;
		if (!p || self.state != 'incoming')
			return;
		if (p.local && !p.told_local && p.prack_ok && !p.update_sent) {
			p.update_sent = true;
			let body = sdp_answer(self.offer, o.ue_addr, o.rtp_port, session, { local: true, remote: p.remote }, next_ver());
			send_update(body, (r) => {
				if (!r || r.status >= 300)
					return log('warn', sprintf('call: UPDATE %s', r ? r.status : 'timed out'));
				p.told_local = true;
				let q = qos_parse(r.body);
				if (q)
					p.remote = q.local;
				mt_ring();
			});
			return;
		}
		mt_ring();
	};

	// incoming(msg, cb(event, data)): msg is the parsed initial INVITE.
	// Events: incoming { from, offer }, answered, ended { reason, ... }
	self.incoming = function(msg, cb) {
		ev = cb ?? ev;
		self.role = 'uas';
		self.state = 'incoming';
		self.call_id = SIP.get(msg, 'call-id');
		let req = lc(SIP.get(msg, 'require') ?? '');
		self.uas = {
			invite: msg,
			branch: SIP.param(SIP.all(msg, 'via')[0], 'branch'),
			rr: SIP.all(msg, 'record-route'),
			local: SIP.get(msg, 'to') + ';tag=' + self.from_tag,
			peer: SIP.get(msg, 'from'),
			reliable: index(req, '100rel') >= 0,
			rseq: 0,
		};
		self.route_set = length(self.uas.rr) ? self.uas.rr : null;    // UAS: in order
		self.remote = SIP.uri_of(SIP.get(msg, 'contact') ?? '');
		self.target = self.remote;
		self.offer = msg.body;

		uas_send(uas_resp(100, 'Trying'));

		// preconditions (RFC 3312): when the offer carries them and the
		// INVITE supports or requires the extension (and we may use them)
		let q = qos_parse(msg.body);
		let ext = index(req, 'precondition') >= 0 || index(lc(SIP.get(msg, 'supported') ?? ''), 'precondition') >= 0;
		if (index(req, 'precondition') >= 0 && (!q || o.preconditions === false))
			return uas_final_error(420, 'Bad Extension', 'rejected', [ [ 'Unsupported', 'precondition' ] ]);
		// used whenever the offer has them and the INVITE supports or requires
		// the extension, as a phone does. (On Vodafone DE they looked broken
		// until the 18x also went on the U:port_c -> P:port_s pair; see
		// tools/ims-register.uc send(). HW 2026-11-14 mt15: 183, PRACK,
		// QCI 1, UPDATE, 180, ringback, 200, ACK.)
		let want = true;
		if (q && ext && want && o.preconditions !== false)
			self.pre = { local: false, remote: q.local, told_local: false };

		self.answer = sdp_answer(msg.body, o.ue_addr, o.rtp_port, session,
			self.pre ? { local: false, remote: self.pre.remote, conf: !self.pre.remote } : null, version);
		if (!self.answer)
			return uas_final_error(488, 'Not Acceptable Here', 'rejected');

		if (self.pre) {
			// o.alert_delay holds the 180 back here too: at the earliest that
			// long after the INVITE, and once both segments are up
			if (o.alert_delay > 0) {
				self.uas.hold = true;
				timer(o.alert_delay, () => {
					self.uas.hold = false;
					mt_ring();
				});
			}
			// 183 with the answer (reliable, RFC 3312 requires it); the 180
			// waits until both segments are up (mt_check)
			// Require: precondition, as RFC 3312 11 wants on the response
			// with an answer that uses them
			on_local_ready = mt_check;
			uas_repeat(uas_resp(183, 'Session Progress', [ [ 'Contact', contact ], [ 'Allow', ALLOW ],
				[ 'Require', '100rel, precondition' ], [ 'RSeq', sprintf('%d', ++self.uas.rseq) ],
				[ 'Content-Type', 'application/sdp' ] ], self.answer),
				() => log('warn', 'call: no PRACK for the 183'));
			qos_start();
			return;
		}

		// o.mt_mode 'rel183' (a test mode): the answer in a reliable 183 first,
		// the 180 once it is PRACKed (early answer without preconditions)
		if (o.mt_mode == 'rel183') {
			self.uas.ring_after_prack = true;
			self.uas.early_answer = true;
			uas_repeat(uas_resp(183, 'Session Progress', [ [ 'Contact', contact ], [ 'Allow', ALLOW ],
				[ 'Require', '100rel' ], [ 'RSeq', sprintf('%d', ++self.uas.rseq) ],
				[ 'Content-Type', 'application/sdp' ] ], self.answer),
				() => log('warn', 'call: no PRACK for the reliable 183'));
			return;
		}

		let ring = () => {
			if (self.state != 'incoming')
				return;    // answered, rejected or cancelled meanwhile
			let ex = [ [ 'Contact', contact ], [ 'Allow', ALLOW ] ];
			if (self.uas.reliable) {
				push(ex, [ 'Require', '100rel' ], [ 'RSeq', sprintf('%d', ++self.uas.rseq) ]);
				uas_repeat(uas_resp(180, 'Ringing', ex), () => log('warn', 'call: no PRACK for the 180'));
			}
			else
				uas_send(uas_resp(180, 'Ringing', ex));
		};
		// o.alert_delay (ms): the 180 that late, only the 100 before it. When
		// the network rings several devices of one number (MultiSIM), our
		// at-once 180 may decide things before a device in idle has been
		// paged. The phone or PBX is offered the call at once all the same.
		if (o.alert_delay > 0)
			timer(o.alert_delay, ring);
		else
			ring();
		emit('incoming', { from: self.uas.peer, offer: length(msg.body ?? '') > 0 });
	};

	// false while preconditions still run (before our 180): a 200 then would
	// come before the 183's PRACK (RFC 3262 3) and before our QoS is up; the
	// caller accepts again on the 'incoming' event
	self.accept = function() {
		if (self.role != 'uas' || self.state != 'incoming')
			return false;
		if (self.pre && !self.pre.rung)
			return false;
		self.state = 'answering';
		let hs = [ [ 'Contact', contact ], [ 'Allow', ALLOW ], [ 'Supported', '100rel, precondition, timer, replaces' ] ];
		let sdp_done = self.pre || self.uas.early_answer;   // offer/answer done in a reliable 183
		if (!sdp_done)
			push(hs, [ 'Content-Type', 'application/sdp' ]);
		let buf = uas_resp(200, 'OK', hs, sdp_done ? '' : self.answer);
		uas_repeat(buf, () => {
			// Timer H: no ACK. The dialog is up on the other side; end it
			log('warn', 'call: no ACK for the 200, sending BYE');
			self.state = 'confirmed';
			self.hangup();
		});
		return true;
	};

	self.reject = function(status, reason) {
		if (self.role != 'uas' || self.state != 'incoming')
			return false;
		uas_final_error(status ?? 603, reason ?? 'Decline', 'rejected');
		return true;
	};

	// the requests of an incoming call that are not in-dialog ones; true when handled
	let uas_request = (msg) => {
		let m = msg.method, u = self.uas;
		let branch = SIP.param(SIP.all(msg, 'via')[0], 'branch');
		if (m == 'INVITE' && branch == u.branch) {
			if (u.last)       // a retransmission: repeat our latest answer
				uas_send(u.last);
			return true;
		}
		if (m == 'CANCEL') {
			uas_send(SIP.response(msg, 200, 'OK', { to_tag: self.from_tag }));
			if (self.state == 'incoming')
				uas_final_error(487, 'Request Terminated', 'cancelled');
			return true;
		}
		if (m == 'PRACK') {
			reply(msg, 200, 'OK');
			if (self.state == 'incoming') {
				uas_stop();
				if (u.ring_after_prack) {
					u.ring_after_prack = false;
					uas_send(uas_resp(180, 'Ringing', [ [ 'Contact', contact ], [ 'Allow', ALLOW ] ]));
					emit('incoming', { from: u.peer, offer: true, early_answer: true });
				}
				if (self.pre) {
					self.pre.prack_ok = true;
					mt_check();
				}
			}
			return true;
		}
		if (m == 'UPDATE' && self.pre && self.state == 'incoming') {
			// the caller reports its segment; we answer with ours as it is now
			let q = qos_parse(msg.body);
			if (q)
				self.pre.remote = q.local;
			let has = length(msg.body ?? '') > 0;
			let ans = has ? sdp_answer(msg.body, o.ue_addr, o.rtp_port, session,
				{ local: self.pre.local, remote: self.pre.remote }, next_ver()) : '';
			let ex = [ [ 'Contact', contact ] ];
			if (has)
				push(ex, [ 'Content-Type', 'application/sdp' ]);
			reply(msg, 200, 'OK', ex, ans ?? '');
			if (has && self.pre.local)
				self.pre.told_local = true;
			mt_check();
			return true;
		}
		if (m == 'ACK' && self.state == 'answering') {
			uas_stop();
			u.last = null;
			self.state = 'confirmed';
			emit('answered', { status: 200 });
			if (u.bye_after_ack)
				self.hangup();
			return true;
		}
		return false;
	};

	let on_request = (msg) => {
		let m = msg.method;
		if (self.role == 'uas' && uas_request(msg))
			return true;
		if (m == 'ACK')
			return true;
		if (m == 'BYE') {
			reply(msg, 200, 'OK');
			let rs = SIP.all(msg, 'reason');
			finish('remote', length(rs) ? { cause: join(', ', rs) } : null);
			return true;
		}
		if (m == 'UPDATE' || m == 'INVITE') {
			// a session refresh or an offer: answer with what we offered
			let has = length(msg.body ?? '') > 0;
			let ex = [ [ 'Contact', contact ] ];
			if (has)
				push(ex, [ 'Content-Type', 'application/sdp' ]);
			let c = SIP.get(msg, 'contact');
			if (c)
				self.remote = SIP.uri_of(c);
			let q = has ? qos_parse(msg.body) : null;
			if (self.pre && q) {
				self.pre.remote = q.local;
				if (self.pre.local)
					self.pre.told_local = true;
			}
			let qos = (self.pre && q) ? { local: self.pre.local, remote: self.pre.remote } : null;
			reply(msg, 200, 'OK', ex, has ? (sdp_answer(msg.body, o.ue_addr, o.rtp_port, session, qos, next_ver()) ??
				sdp_offer(o.ue_addr, o.rtp_port, session, qos, next_ver())) : '');
			return true;
		}
		if (m == 'OPTIONS' || m == 'NOTIFY' || m == 'INFO') {
			reply(msg, 200, 'OK');
			return true;
		}
		reply(msg, 405, 'Method Not Allowed', [ [ 'Allow', ALLOW ] ]);
		return true;
	};

	// a received SIP message; false when it is not this call's
	self.on_message = function(buf) {
		let msg = SIP.parse(buf);
		if (!msg || SIP.get(msg, 'call-id') != self.call_id)
			return false;

		if (msg.method)
			return on_request(msg);

		let cs = SIP.cseq(msg);
		let branch = SIP.param(SIP.all(msg, 'via')[0], 'branch');
		if (!cs)
			return true;

		if (cs.method == 'INVITE' && branch == self.invite?.branch)
			on_invite_response(msg);
		else if (cs.method == 'CANCEL') {
			if (msg.status >= 200)
				tx_stop(self.invite.branch + '/cancel');
		}
		else {
			let t = txs[branch];
			if (t && msg.status >= 200) {
				tx_stop(branch);
				t.cb(msg);
			}
		}
		return true;
	};

	return self;
}

// the 200 for an OPTIONS outside a dialog, or null when buf is not one. The
// Nokia/ALU P-CSCF pages the UE with one (Call-ID ...@paging-options) before
// it delivers an incoming INVITE: unanswered, the call goes to the mailbox.
// o: { ue_addr, port_s, contact_user, imei_urn }
export function options_ok(buf, o)
{
	let msg = SIP.parse(buf);
	if (!msg || msg.method != 'OPTIONS' || SIP.param(SIP.get(msg, 'to'), 'tag') != null)
		return null;
	return SIP.response(msg, 200, 'OK', { to_tag: rnd_hex(6), headers: [
		[ 'Contact', sprintf('<sip:%s@%s>;+sip.instance="<%s>";+g.3gpp.icsi-ref="%s"',
			o.contact_user, hostport(o.ue_addr, o.port_s), o.imei_urn, MMTEL) ],
		[ 'Allow', ALLOW ], [ 'Accept', 'application/sdp' ], [ 'Supported', '100rel, timer, replaces' ],
	] }, '');
}

// 481 for a request that belongs to no call we know (a CANCEL or BYE that
// comes after the call was forgotten), or null (an ACK, a response, or
// something else that needs no answer)
export function no_transaction(buf)
{
	let msg = SIP.parse(buf);
	if (!msg?.method || msg.method == 'ACK')
		return null;
	if (msg.method == 'INVITE' && SIP.param(SIP.get(msg, 'to'), 'tag') == null)
		return null;
	return SIP.response(msg, 481, 'Call/Transaction Does Not Exist', { to_tag: rnd_hex(6) }, '');
}

// the parsed message when buf is an initial INVITE (no To tag), else null:
// the caller then makes a call object for it and calls incoming()
export function initial_invite(buf)
{
	let msg = SIP.parse(buf);
	if (!msg || msg.method != 'INVITE' || SIP.param(SIP.get(msg, 'to'), 'tag') != null)
		return null;
	return msg;
}
