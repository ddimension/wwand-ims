// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// sipd core: a registrar and back-to-back user agent between SIP phones on
// the LAN and the modem's IMS calls (the ims plugin's ops and events).
//
// Everything outside is injected (env), so the logic runs in host tests:
//   env.send(text, addr)             addr = { address, port }
//   env.ims(op, args, cb)            the ims plugin op on env.cfg.modem
//   env.media.start(call) -> port    a local RTP port for the call
//   env.media.connect(call)          call.remote_rtp and call.codec are set
//   env.media.stop(call)
//   env.timer(ms, fn) -> { cancel }
//   env.now() -> seconds, env.random() -> hex string, env.log(level, msg)
//   env.cfg = { ip, port, realm, modem, codecs, users: { name: { password } } }
//   env.bindings_changed(bindings)   optional: persist them (sipd.uc, /var/run)
//
// One call per modem: the modem has one voice line. A second INVITE while a
// call runs gets 486 Busy Here.
//
// The other backend, the router's own IMS UE (sipd/line_ue.uc), comes as
//   env.line   { ready(), ue_addr(), dial(number, ev, { offer, ims_port }) -> call }
//              plus core.on_line_incoming(inc) for the calls it receives
//   env.relay  { alloc() -> media, connect(media, far), update(media, far), stop(media) } (sipd/relay.uc)
//   env.sdp    { relay: ue/call.uc sdp_relay, media: sdp_media } (an ES module,
//              so the entry imports it and hands it in)
// With it the SDP is relayed: the AMR-WB/AMR and telephone-event lines go
// from one leg to the other with their payload types, only address and
// port change (ue/call.uc sdp_relay), and the RTP is moved 1:1.

'use strict';

let S = require('sipd_sip');

const T1 = 500, T2 = 4000, TIMER_B = 64 * T1;	// RFC 3261 17.1.1.1/17.1.2.2
const NONCE_TTL = 300;
const HISTORY = 10;

function create(env)
{
	let cfg = env.cfg;
	let log = env.log;
	let U = { sdp_relay: env.sdp?.relay, sdp_media: env.sdp?.media };
	let bindings = {};		// user -> { contact, addr, expires }
	let nonces = {};		// nonce -> issued at
	let call = null;		// the one call
	let history = [];		// the last HISTORY calls, newest first

	let me = () => sprintf('%s:%d', cfg.ip, cfg.port);
	let tag = () => substr(env.random(), 0, 10);
	let branch = () => 'z9hG4bK' + substr(env.random(), 0, 16);

	let send = (text, addr) => env.send(text, addr);

	// where a request came from: rport/received (RFC 3581) means the source
	// address, which is also right without NAT on a LAN
	// ... and the transport it came over: a TCP request is answered on its
	// connection, and a phone registered over TCP gets its INVITE there
	let source = (from) => ({ address: from.address, port: from.port,
	                          transport: from.transport ?? 'UDP', conn: from.conn });
	let tp = (addr) => addr?.transport ?? 'UDP';

	// ---- authentication -----------------------------------------------------

	let new_nonce = () => {
		let n = env.random();
		let t = env.now();

		for (let k, at in nonces)
			if (t - at > NONCE_TTL)
				delete nonces[k];
		nonces[n] = t;
		return n;
	};

	// the authenticated user, or null after sending the challenge
	let authenticate = (req, from, header, status, reason, challenge_header) => {
		let a = S.auth_parse(S.get(req, header));
		let user = a ? cfg.users[a.username] : null;

		if (a && user && nonces[a.nonce] != null && a.realm == cfg.realm &&
		    S.auth_check(a, req.method, user.password))
			return a.username;

		send(S.response(req, status, reason, { to_tag: tag(), headers: [
			[ challenge_header, S.challenge(cfg.realm, new_nonce()) ] ] }), source(from));
		return null;
	};

	// ---- registrar ----------------------------------------------------------

	let on_register = (req, from) => {
		let user = authenticate(req, from, 'authorization', 401, 'Unauthorized', 'WWW-Authenticate');

		if (!user)
			return;

		let contact = S.get(req, 'contact');
		let exp = +(S.param(contact, 'expires') ?? S.get(req, 'expires') ?? 3600);

		if (contact == '*' || exp == 0) {
			delete bindings[user];
			env.bindings_changed?.(bindings);
			log('info', sprintf('sipd: %s unregistered', user));
			return send(S.response(req, 200, 'OK', { to_tag: tag() }), source(from));
		}

		exp = min(max(exp, 60), 3600);
		bindings[user] = { contact: S.uri_of(contact), addr: source(from), expires: env.now() + exp };
		env.bindings_changed?.(bindings);
		log('info', sprintf('sipd: %s registered at %s:%d', user, from.address, from.port));
		send(S.response(req, 200, 'OK', { to_tag: tag(), headers: [
			[ 'Contact', sprintf('<%s>;expires=%d', S.uri_of(contact), exp) ] ] }), source(from));
	};

	let registered = () => {
		let t = env.now();

		for (let u, b in bindings)
			if (b.expires > t)
				return u;
		return null;
	};

	// ---- dialog helpers -------------------------------------------------------

	let our_contact = (addr) => (tp(addr) == 'TCP')
		? sprintf('<sip:wwand@%s;transport=tcp>', me()) : sprintf('<sip:wwand@%s>', me());

	let stop_retx = (c) => {
		c.retx?.cancel();
		c.retx = null;
	};

	// resend `text` with RFC 3261 doubling (T1, capped at T2) until stopped or
	// TIMER_B ran out; then give_up(). Over TCP only the timeout: a reliable
	// transport is not retransmitted on (RFC 3261 17.1.1.2).
	let retransmit = (c, text, addr, give_up) => {
		stop_retx(c);
		if (tp(addr) == 'TCP') {
			send(text, addr);
			c.retx = env.timer(TIMER_B, () => { c.retx = null; give_up?.(); });
			return;
		}
		let wait = T1, spent = 0;
		let tick;

		tick = () => {
			spent += wait;
			if (spent >= TIMER_B) {
				c.retx = null;
				return give_up?.();
			}
			send(text, addr);
			wait = min(wait * 2, T2);
			c.retx = env.timer(wait, tick);
		};
		send(text, addr);
		c.retx = env.timer(wait, tick);
	};

	// incoming calls that are over: the phone's final answer to our INVITE
	// may still come or come again — a 487 after our CANCEL, or a 200 whose
	// ACK got lost — and each needs its ACK, or the phone repeats it for 32 s
	// (RFC 3261 13.3.1.4, 17.2.1)
	let ended_in = {};

	// one call into the history (env.history_changed persists it)
	let record = (r) => {
		unshift(history, r);
		if (length(history) > HISTORY)
			history = slice(history, 0, HISTORY);
		env.history_changed?.(history);
	};

	// what became of a call, from how it ended
	let outcome = (c, why) => {
		if (c.answered)
			return 'answered';
		if (c.dir == 'in')
			return match(why ?? '', /^phone (486|600|603)/) ? 'declined' : 'missed';
		return match(why ?? '', /cancel|hung up/) ? 'cancelled' : 'failed';
	};

	let end_call = (c, why) => {
		if (!c)
			return;
		stop_retx(c);
		if (!c.recorded) {
			c.recorded = true;
			let now = env.now();
			record({ start: c.started ?? now, answered: c.answered, end: now, dir: c.dir,
			         number: c.number, extension: c.ext, result: outcome(c, why), reason: why,
			         codec: c.codec_name ?? c.codec, backend: c.lc || c.media ? 'ue' : 'qmi',
			         packets: c.media ? env.relay.stats?.(c.media) : null });
		}
		if (c.dir == 'in' && !ended_in[c.call_id]) {
			let id = c.call_id;
			c.was_up = (c.state == 'up');
			ended_in[id] = c;
			env.timer(32000, () => { delete ended_in[id]; });
		}
		if (c.media)
			env.relay.stop(c.media);
		else
			env.media.stop(c);
		log('info', sprintf('sipd: call %s ended (%s)', c.call_id, why));
		if (call === c)
			call = null;
	};

	let hangup_modem = (c) => {
		if (c.lc) {
			if (c.lc.state != 'ended')
				c.lc.hangup();
			return;
		}
		if (c.mid != null && !c.modem_gone)
			env.ims('hangup', { id: c.mid }, () => null);
	};

	// ---- the UE line: SDP and media ---------------------------------------------------

	// the AMR(-WB) payload type and clock in an SDP, for the relay's keepalive
	// the AMR(-WB) payload type, clock and framing of the first AMR in an SDP
	let amr_of = (sdp) => {
		let m = match(sdp ?? '', /a=rtpmap:([0-9]+) (AMR-WB|AMR)\//i);
		if (!m)
			return null;
		let f = match(sdp, regexp('a=fmtp:' + m[1] + ' ([^\r\n]*)'));
		return { pt: +m[1], rate: lc(m[2]) == 'amr-wb' ? 16000 : 8000,
		         octet: f != null && match(f[1], /octet-align *= *1/) != null };
	};

	// lan_sdp: what the phone sent (offer or answer); ims_sdp: what the far
	// end on the IMS side sent (its answer or its offer)
	// connected once; a later SDP (the 200 after a 183 with early media, from
	// another media gateway) moves the far ends
	// pt_sdp: where the negotiated AMR comes from, when not ims_sdp (MT: our
	// answer to the network, not its offer with every codec)
	let line_connect = (c, lan_sdp, ims_sdp, pt_sdp) => {
		let a = amr_of(pt_sdp ?? ims_sdp);
		let far = { lan: U.sdp_media(lan_sdp), ims: U.sdp_media(ims_sdp), ims_pt: a?.pt, ims_rate: a?.rate,
		            ims_octet: a?.octet };
		if (a)
			c.codec_name = (a.rate == 16000) ? 'AMR-WB' : 'AMR';
		if (c.connected)
			return env.relay.update(c.media, far);
		c.connected = true;
		env.relay.connect(c.media, far);
	};

	let lan_sdp_for = (c, ims_sdp) => U.sdp_relay(ims_sdp, cfg.ip, c.media.lan_port, c.session, null, ++c.sdp_ver);

	let answer_sdp = (c) => S.sdp({ ip: cfg.ip, port: c.rtp_port, session: c.session, codecs: [ c.codec ] });

	// a request to the phone inside the dialog (BYE, CANCEL, ACK)
	let to_phone = (c, method, opts) => {
		let target = c.remote_contact ?? c.target;
		let hs = [
			[ 'Via', sprintf('SIP/2.0/%s %s;branch=%s;rport', tp(c.addr), me(), opts?.branch ?? branch()) ],
			[ 'Max-Forwards', '70' ],
			[ 'From', c.local ],
			[ 'To', c.remote ],
			[ 'Call-ID', c.call_id ],
			[ 'CSeq', sprintf('%d %s', opts?.cseq ?? ++c.cseq, method) ],
		];

		return S.build(sprintf('%s %s SIP/2.0', method, target), hs, '');
	};

	// the relay heard nothing from one side for too long: the call is dead
	// for both, whatever SIP still believes
	let media_dead = (c, side, kind) => {
		if (call !== c)
			return;
		log('warn', sprintf('sipd: call %s: no %s from the %s side, ending it', c.call_id, uc(kind), uc(side)));
		if (!c.bye_sent) {
			c.bye_sent = true;
			send(to_phone(c, 'BYE'), c.addr);
		}
		// the call first: the line's 'ended' must not send a second BYE
		end_call(c, sprintf('no %s from the %s side', uc(kind), uc(side)));
		hangup_modem(c);
	};
	let media_watch = (c) => env.relay.watch?.(c.media, (side, kind) => media_dead(c, side, kind));

	// ---- outgoing over the UE line ------------------------------------------------

	let line_out_event, out_line;

	line_out_event = (c, ev, d) => {
		if (call !== c)
			return;
		if ((ev == 'ringing' || ev == 'progress') && c.state != 'up') {
			if (d?.body) {
				// early media (ringback, announcements): 183 with the relayed SDP
				line_connect(c, c.req.body, d.body);
				c.state = 'early';
				c.last = S.response(c.req, 183, 'Session Progress', { to_tag: c.local_tag, headers: [
					[ 'Contact', our_contact(c.addr) ], [ 'Content-Type', 'application/sdp' ] ] }, lan_sdp_for(c, d.body));
				send(c.last, c.addr);
			}
			else if (ev == 'ringing' && c.state == 'trying') {
				c.state = 'ringing';
				c.last = S.response(c.req, 180, 'Ringing', { to_tag: c.local_tag,
					headers: [ [ 'Contact', our_contact(c.addr) ] ] });
				send(c.last, c.addr);
			}
			return;
		}
		if (ev == 'answered' && c.state != 'up') {
			c.state = 'up';
			c.answered ??= env.now();
			line_connect(c, c.req.body, d?.body);
			media_watch(c);
			c.last = S.response(c.req, 200, 'OK', { to_tag: c.local_tag, headers: [
				[ 'Contact', our_contact(c.addr) ], [ 'Content-Type', 'application/sdp' ] ] }, lan_sdp_for(c, d?.body));
			retransmit(c, c.last, c.addr, () => {
				hangup_modem(c);
				end_call(c, 'no ACK');
			});
			return;
		}
		if (ev == 'ended') {
			if (c.state != 'up') {
				let st = d?.status;
				// the network's final status for the phone; an auth challenge or
				// a server error of the IMS side means "not now" to it
				if (st == null || st < 400 || st == 401 || st == 407)
					st = 480;
				c.last = S.response(c.req, st, d?.phrase ?? 'Temporarily Unavailable', { to_tag: c.local_tag,
					headers: d?.warning ? [ [ 'Warning', d.warning ] ] : [] });
				send(c.last, c.addr);
			}
			else if (!c.bye_sent) {
				c.bye_sent = true;
				send(to_phone(c, 'BYE'), c.addr);
			}
			end_call(c, 'IMS side ended (' + (d?.reason ?? '?') + ')');
		}
	};

	out_line = (req, from, number, who) => {
		if (!env.line.ready())
			return send(S.response(req, 503, 'Service Unavailable', { to_tag: tag(), headers: [
				[ 'Warning', '399 wwand-ims "IMS not registered"' ] ] }), source(from));
		if (!U.sdp_relay(req.body, '::1', 1, 1))
			return send(S.response(req, 488, 'Not Acceptable Here', { to_tag: tag(), headers: [
				[ 'Warning', '305 wwand-ims "offer AMR-WB or AMR"' ] ] }), source(from));
		let m = env.relay.alloc();
		if (!m)
			return send(S.response(req, 503, 'Service Unavailable', { to_tag: tag() }), source(from));

		let c = {
			dir: 'out', req: req, addr: source(from), call_id: S.get(req, 'call-id'),
			local_tag: tag(), number: number, session: 1 + (env.now() % 100000), sdp_ver: 0,
			cseq: 0, state: 'trying', remote_contact: S.uri_of(S.get(req, 'contact')), media: m,
		};
		c.local = S.get(req, 'to') + ';tag=' + c.local_tag;
		c.remote = S.get(req, 'from');
		call = c;
		c.started = env.now();
		c.ext = who;
		send(S.response(req, 100, 'Trying'), c.addr);

		// CLIR: the PBX/Asterisk withholds the caller's number either with a
		// Privacy header (id/user/header per RFC 3323) or an anonymous From.
		// Pass that on so the IMS UE sends Privacy: id and an anonymous From
		// while P-Preferred-Identity still carries our real IMPU (ue/call.uc).
		let privacy = false;
		let priv = S.get(req, 'privacy');
		if (priv)
			for (let tok in split(priv, ';'))
				if (index([ 'id', 'user', 'header' ], lc(trim(tok))) >= 0)
					privacy = true;
		if (!privacy) {
			let fu = S.parse_uri(S.uri_of(S.get(req, 'from') ?? ''))?.user;
			privacy = lc(fu ?? '') == 'anonymous';
		}
		log('info', sprintf('sipd: outgoing call to %s over the IMS UE%s', number, privacy ? ' (CLIR)' : ''));

		let ims_session = 1 + (env.now() % 100000);
		c.lc = env.line.dial(number, (ev, d) => line_out_event(c, ev, d), {
			ims_port: m.ims_port, privacy: privacy,
			offer: (qos, ver) => U.sdp_relay(req.body, env.line.ue_addr(), m.ims_port, ims_session, qos, ver),
		});
		if (!c.lc) {
			c.last = S.response(req, 503, 'Service Unavailable', { to_tag: c.local_tag });
			send(c.last, c.addr);
			end_call(c, 'dial failed');
		}
	};

	// ---- incoming over the UE line -----------------------------------------------------

	let on_line_incoming = (inc) => {
		let user = registered();
		let lc = inc.call;

		if (!user || call) {
			log('warn', sprintf('sipd: incoming call from %s: %s', inc.number ?? '?', user ? 'busy' : 'no phone registered'));
			let now = env.now();
			record({ start: now, end: now, dir: 'in', number: inc.number, extension: user, result: 'missed',
			         reason: user ? 'busy' : 'no phone registered', backend: 'ue' });
			lc.reject(user ? 486 : 480, user ? 'Busy Here' : 'Temporarily Unavailable');
			env.relay.stop(inc.media);
			return;
		}

		let b = bindings[user];
		let c = {
			dir: 'in', lc: lc, media: inc.media, call_id: env.random() + '@' + cfg.ip, local_tag: tag(),
			addr: b.addr, target: b.contact, cseq: 1, state: 'calling',
			session: 1 + (env.now() % 100000), sdp_ver: 0, branch: branch(), number: inc.number,
		};
		let caller = inc.number ?? 'anonymous';

		// To: the number the network called (P-Called-Party-ID), so a PBX can
		// route on it; the Request-URI is the registered contact
		c.local = sprintf('<sip:%s@%s>;tag=%s', caller, cfg.ip, c.local_tag);
		c.remote = sprintf('<sip:%s@%s>', inc.called ?? user, cfg.ip);
		call = c;
		c.started = env.now();
		c.ext = user;

		inc.set((ev, d) => {
			if (call !== c)
				return;
			// the IMS side is ready to alert only now with preconditions:
			// an answer the phone gave meanwhile goes out at this point
			if (ev == 'incoming' && c.want_accept)
				lc.accept();
			if (ev == 'ended') {
				if (c.state != 'up')
					send(to_phone(c, 'CANCEL', { cseq: 1, branch: c.branch }), c.addr);
				else if (!c.bye_sent) {
					c.bye_sent = true;
					send(to_phone(c, 'BYE'), c.addr);
				}
				end_call(c, 'IMS side ended (' + (d?.reason ?? '?') + ')');
			}
		});

		// a forwarded call (e.g. a landline diverted to this number): the
		// network's History-Info as it came, and Diversion headers from it
		// (or the network's own Diversion), so the phone or PBX sees who
		// forwarded and why (Asterisk: REDIRECTING(from-num), (reason))
		let redir = [];
		if (cfg.redirect_info !== false) {
			let divs = length(inc.diversion ?? []) ? inc.diversion
				: S.diversion_headers(S.diversions(S.history_info(inc.history)), cfg.ip);
			for (let d in divs)
				push(redir, [ 'Diversion', d ]);
			for (let h in inc.history ?? [])
				push(redir, [ 'History-Info', h ]);
			if (length(divs))
				log('info', sprintf('sipd: call from %s diverted: %s', caller, join(', ', divs)));
		}

		let offer = lan_sdp_for(c, lc.answer);
		c.invite = S.build(sprintf('INVITE %s SIP/2.0', c.target), [
			[ 'Via', sprintf('SIP/2.0/%s %s;branch=%s;rport', tp(c.addr), me(), c.branch) ],
			[ 'Max-Forwards', '70' ],
			[ 'From', c.local ],
			[ 'To', c.remote ],
			[ 'Call-ID', c.call_id ],
			[ 'CSeq', '1 INVITE' ],
			[ 'Contact', our_contact(c.addr) ],
			...redir,
			[ 'Content-Type', 'application/sdp' ],
		], offer);

		log('info', sprintf('sipd: incoming call from %s to %s over the IMS UE', caller, user));
		retransmit(c, c.invite, c.addr, () => {
			end_call(c, 'phone did not answer the INVITE');
			// "not reachable", not the 603 Decline a hangup would send
			if (lc.state == 'incoming')
				lc.reject(480, 'Temporarily Unavailable');
			else
				lc.hangup();
		});
	};

	// the phone's final answer to an incoming call over the UE line
	let line_in_answer = (c, res, from) => {
		if (res.status >= 300) {
			log('info', sprintf('sipd: phone declined with %d', res.status));
			let st = (res.status == 486 || res.status == 600 || res.status == 603) ? res.status : 480;
			c.lc.reject(st, res.reason);
			return end_call(c, sprintf('phone %d', res.status));
		}
		if (!U.sdp_relay(res.body, '::1', 1, 1)) {
			send(to_phone(c, 'BYE'), c.addr);
			hangup_modem(c);
			return end_call(c, 'no AMR in the phone\'s answer');
		}
		c.state = 'up';
		c.answered ??= env.now();
		line_connect(c, res.body, c.lc.offer, c.lc.answer);
		media_watch(c);
		if (!c.lc.accept())
			c.want_accept = true;    // preconditions still running: on 'incoming'
	};

	// ---- outgoing: phone -> modem ----------------------------------------------

	let on_invite = (req, from) => {
		// a retransmission of the INVITE we are handling: repeat our answer
		if (call?.dir == 'out' && call.call_id == S.get(req, 'call-id')) {
			if (call.last)
				send(call.last, call.addr);
			return;
		}

		let who = authenticate(req, from, 'proxy-authorization', 407, 'Proxy Authentication Required',
		                       'Proxy-Authenticate');
		if (!who)
			return;

		let ruri = S.parse_uri(req.uri);
		let number = ruri?.user;

		if (!number || !match(number, /^\+?[0-9*#]{3,32}$/))
			return send(S.response(req, 484, 'Address Incomplete', { to_tag: tag() }), source(from));
		if (call)
			return send(S.response(req, 486, 'Busy Here', { to_tag: tag() }), source(from));

		if (env.line)
			return out_line(req, from, number, who);

		let offer = S.sdp_parse(req.body);
		let codec = S.sdp_pick(offer, cfg.codecs);

		if (!codec)
			return send(S.response(req, 488, 'Not Acceptable Here', { to_tag: tag() }), source(from));

		let c = {
			dir: 'out', req: req, addr: source(from), call_id: S.get(req, 'call-id'),
			local_tag: tag(), number: number, codec: codec, session: 1 + (env.now() % 100000),
			remote_rtp: { address: offer.ip ?? from.address, port: offer.port },
			dtmf_pt: offer.dtmf_pt, cseq: 0, state: 'trying',
			remote_contact: S.uri_of(S.get(req, 'contact')),
		};
		c.local = S.get(req, 'to') + ';tag=' + c.local_tag;
		c.remote = S.get(req, 'from');
		call = c;
		c.started = env.now();
		c.ext = who;

		c.rtp_port = env.media.start(c);
		send(S.response(req, 100, 'Trying'), c.addr);
		log('info', sprintf('sipd: outgoing call to %s (%s)', number, codec));

		env.ims('dial', { number: number }, (err, res) => {
			if (call !== c)
				return;
			if (err || res?.id == null) {
				c.last = S.response(req, 503, 'Service Unavailable', { to_tag: c.local_tag });
				send(c.last, c.addr);
				return end_call(c, 'dial failed');
			}
			c.mid = res.id;
		});
	};

	let out_event = (c, mc) => {
		if (mc.state == 'alerting' && c.state == 'trying') {
			c.state = 'ringing';
			c.last = S.response(c.req, 180, 'Ringing', { to_tag: c.local_tag,
				headers: [ [ 'Contact', our_contact(c.addr) ] ] });
			send(c.last, c.addr);
		}
		else if (mc.state == 'conversation' && (c.state == 'trying' || c.state == 'ringing')) {
			c.state = 'up';
			c.answered ??= env.now();
			env.media.connect(c);
			c.last = S.response(c.req, 200, 'OK', { to_tag: c.local_tag, headers: [
				[ 'Contact', our_contact(c.addr) ], [ 'Content-Type', 'application/sdp' ] ] }, answer_sdp(c));
			// until the ACK (RFC 3261 13.3.1.4); without one, end the call
			retransmit(c, c.last, c.addr, () => {
				hangup_modem(c);
				end_call(c, 'no ACK');
			});
		}
	};

	// ---- incoming: modem -> phone -------------------------------------------------

	let in_start = (mc) => {
		let user = registered();

		if (!user) {
			log('warn', sprintf('sipd: incoming call from %s, no phone registered', mc.number ?? '?'));
			let now = env.now();
			record({ start: now, end: now, dir: 'in', number: mc.number, result: 'missed',
			         reason: 'no phone registered', backend: 'qmi' });
			return;
		}

		let b = bindings[user];
		let c = {
			dir: 'in', mid: mc.id, call_id: env.random() + '@' + cfg.ip, local_tag: tag(),
			addr: b.addr, target: b.contact, cseq: 1, state: 'calling', codec: null,
			session: 1 + (env.now() % 100000), branch: branch(), number: mc.number,
		};
		let caller = mc.number ?? 'anonymous';

		c.local = sprintf('<sip:%s@%s>;tag=%s', caller, cfg.ip, c.local_tag);
		c.remote = sprintf('<sip:%s@%s>', user, cfg.ip);
		call = c;
		c.started = env.now();
		c.ext = user;
		c.rtp_port = env.media.start(c);

		let offer = S.sdp({ ip: cfg.ip, port: c.rtp_port, session: c.session, codecs: cfg.codecs });
		c.invite = S.build(sprintf('INVITE %s SIP/2.0', c.target), [
			[ 'Via', sprintf('SIP/2.0/%s %s;branch=%s;rport', tp(c.addr), me(), c.branch) ],
			[ 'Max-Forwards', '70' ],
			[ 'From', c.local ],
			[ 'To', c.remote ],
			[ 'Call-ID', c.call_id ],
			[ 'CSeq', '1 INVITE' ],
			[ 'Contact', our_contact(c.addr) ],
			[ 'Content-Type', 'application/sdp' ],
		], offer);

		log('info', sprintf('sipd: incoming call from %s to %s', caller, user));
		// Timer A/B (RFC 3261 17.1.1.2): resend until a response
		retransmit(c, c.invite, c.addr, () => {
			hangup_modem(c);
			end_call(c, 'phone did not answer the INVITE');
		});
	};

	// the phone's final answer to the INVITE of a call that is over already
	let late_final = (c, res) => {
		c.remote = S.get(res, 'to');
		if (S.get(res, 'contact'))
			c.remote_contact = S.uri_of(S.get(res, 'contact'));
		send(to_phone(c, 'ACK', { cseq: 1, branch: (res.status >= 300) ? c.branch : null }), c.addr);
		// it answered while our CANCEL was on the way: that dialog ends at
		// once (a 200 of a call that was up is only a retransmission)
		if (res.status < 300 && !c.was_up && !c.bye_sent) {
			c.bye_sent = true;
			send(to_phone(c, 'BYE'), c.addr);
		}
	};

	let on_response = (res, from) => {
		let c = call;
		let cs = S.cseq(res);
		let id = S.get(res, 'call-id') ?? '';
		// the running call first; an ended one only for what is not its
		let late = (c?.call_id != id) ? ended_in[id] : null;

		if (late && late !== c && cs?.method == 'INVITE' && res.status >= 200)
			return late_final(late, res);
		if (!c || c.dir != 'in' || S.get(res, 'call-id') != c.call_id || cs?.method != 'INVITE')
			return;

		stop_retx(c);
		c.remote = S.get(res, 'to');
		if (S.get(res, 'contact'))
			c.remote_contact = S.uri_of(S.get(res, 'contact'));

		if (res.status < 200)
			return;

		// ACK every final response (2xx: new transaction, RFC 3261 13.2.2.4;
		// others: the same branch, 17.1.1.3)
		let ack = to_phone(c, 'ACK', { cseq: 1, branch: (res.status >= 300) ? c.branch : null });

		send(ack, c.addr);
		if (c.state == 'up')
			return;	// a retransmitted 200 OK

		if (c.lc)
			return line_in_answer(c, res, from);

		if (res.status >= 300) {
			log('info', sprintf('sipd: phone declined with %d', res.status));
			hangup_modem(c);
			return end_call(c, sprintf('phone %d', res.status));
		}

		let ans = S.sdp_parse(res.body);
		c.codec = S.sdp_pick(ans, cfg.codecs);
		if (!c.codec) {
			send(to_phone(c, 'BYE'), c.addr);
			hangup_modem(c);
			return end_call(c, 'no common codec');
		}

		c.remote_rtp = { address: ans.ip ?? from.address, port: ans.port };
		c.dtmf_pt = ans.dtmf_pt;
		c.state = 'up';
		c.answered ??= env.now();
		env.media.connect(c);
		env.ims('answer', { id: c.mid }, (err) => {
			if (err && call === c) {
				send(to_phone(c, 'BYE'), c.addr);
				end_call(c, 'answer failed');
			}
		});
	};

	// ---- requests inside a call ------------------------------------------------------

	let in_dialog = (req) => call && S.get(req, 'call-id') == call.call_id;

	let on_cancel = (req, from) => {
		let c = call;

		if (!in_dialog(req) || c.dir != 'out') {
			return send(S.response(req, 481, 'Call/Transaction Does Not Exist'), source(from));
		}
		send(S.response(req, 200, 'OK'), source(from));
		if (c.state != 'up') {
			c.last = S.response(c.req, 487, 'Request Terminated', { to_tag: c.local_tag });
			send(c.last, c.addr);
			// the call first: the line's 'ended' must not send a second final
			end_call(c, 'cancelled by the phone');
			hangup_modem(c);
		}
	};

	let on_bye = (req, from) => {
		if (!in_dialog(req))
			return send(S.response(req, 481, 'Call/Transaction Does Not Exist'), source(from));

		let c = call;

		send(S.response(req, 200, 'OK'), source(from));
		end_call(c, 'phone hung up');
		hangup_modem(c);
	};

	let on_ack = (req) => {
		if (in_dialog(req) && call.dir == 'out')
			stop_retx(call);
	};

	// ---- modem events ------------------------------------------------------------------

	// data = { modem, calls: [ { id, state, direction, number, ... } ] }
	let on_call_event = (data) => {
		if (data?.modem != cfg.modem)
			return;

		let calls = data.calls ?? [];
		let c = call;

		// an incoming call nobody is handling yet
		if (!c)
			for (let mc in calls)
				if (mc.direction == 'mt' && (mc.state == 'incoming' || mc.state == 'waiting'))
					return in_start(mc);

		if (!c)
			return;

		let mc = null;
		for (let x in calls)
			if (c.mid != null && x.id == c.mid)
				mc = x;

		// the outgoing call's id is not known before the dial answers; its
		// first events still belong to it
		if (!mc && c.dir == 'out' && c.mid == null)
			for (let x in calls)
				if (x.direction == 'mo')
					mc = x;

		let gone = !mc || mc.state == 'end' || mc.state == 'disconnecting';

		if (gone) {
			if (c.mid == null && !mc)
				return;
			c.modem_gone = true;
			if (c.dir == 'out' && c.state != 'up') {
				// the network refused or the callee did not answer
				c.last = S.response(c.req, 480, 'Temporarily Unavailable', { to_tag: c.local_tag,
					headers: mc?.end_reason != null
						? [ [ 'Reason', sprintf('Q.850;cause=16;text="modem end reason %d"', mc.end_reason) ] ]
						: [] });
				send(c.last, c.addr);
			}
			else if (c.dir == 'in' && c.state != 'up')
				send(to_phone(c, 'CANCEL', { cseq: 1, branch: c.branch }), c.addr);
			else
				send(to_phone(c, 'BYE'), c.addr);
			return end_call(c, 'modem call ended');
		}

		if (c.dir == 'out')
			out_event(c, mc);
	};

	// ---- dispatch --------------------------------------------------------------------------

	let on_packet = (buf, from) => {
		let msg = S.parse(buf);

		if (!msg)
			return;
		if (msg.status != null)
			return on_response(msg, from);

		switch (msg.method) {
		case 'REGISTER': return on_register(msg, from);
		case 'INVITE':   return on_invite(msg, from);
		case 'ACK':      return on_ack(msg);
		case 'CANCEL':   return on_cancel(msg, from);
		case 'BYE':      return on_bye(msg, from);
		case 'OPTIONS':
			return send(S.response(msg, 200, 'OK', { to_tag: tag(), headers: [
				[ 'Allow', 'INVITE, ACK, CANCEL, BYE, OPTIONS, REGISTER' ] ] }), source(from));
		default:
			return send(S.response(msg, 501, 'Not Implemented', { to_tag: tag() }), source(from));
		}
	};

	return {
		on_packet: on_packet,
		on_call_event: on_call_event,
		on_line_incoming: on_line_incoming,
		bindings: () => bindings,
		// bindings saved by an earlier run (env.bindings_changed): the ones not
		// expired come back, so a restart does not wait for the next REGISTER;
		// a TCP binding's connection is gone with the old process, so not those
		restore: (saved) => {
			for (let u, b in saved ?? {})
				if (cfg.users[u] && b?.expires > env.now() && b.addr?.transport != 'TCP')
					bindings[u] = b;
			return length(keys(bindings));
		},
		call: () => call,
		// the running call, for a status page: no SIP internals
		current: () => call ? {
			dir: call.dir, number: call.number, extension: call.ext, state: call.state,
			start: call.started, answered: call.answered, codec: call.codec_name ?? call.codec,
			backend: call.lc || call.media ? 'ue' : 'qmi',
			packets: call.media ? env.relay.stats?.(call.media) : null,
		} : null,
		history: () => history,
		// a history saved by an earlier run (env.history_changed)
		restore_history: (saved) => {
			history = (type(saved) == 'array')
				? slice(filter(saved, (r) => type(r) == 'object' && r.start != null), 0, HISTORY) : [];
			return length(history);
		},
		// the registered phones: user -> { address, port, transport, expires }
		extensions: () => {
			let out = {}, now = env.now();
			for (let u in sort(keys(cfg.users))) {
				let b = bindings[u];
				out[u] = (b && b.expires > now) ? { registered: true, address: b.addr?.address, port: b.addr?.port,
					transport: b.addr?.transport ?? 'UDP', expires: b.expires - now } : { registered: false };
			}
			return out;
		},
	};
}

return { create: create };
