// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// IMS registration on the UE side (3GPP TS 24.229 5.1.1, TS 33.203 6-7):
//
//   1. REGISTER, unprotected, to the P-CSCF's port 5060, with
//      Security-Client (our SPIs and protected ports) and an Authorization
//      carrying only the private identity;
//   2. 401: Digest AKAv1-MD5 challenge + Security-Server. The USIM answers
//      the challenge (ue/aka.uc); the four SAs go into the kernel
//      (ue/secagree.uc);
//   3. REGISTER again, now from our protected client port to the P-CSCF's
//      protected server port, so it travels inside the SA, with the Digest
//      response and Security-Verify;
//   4. 200: registered; Service-Route, the associated IMPUs and the granted
//      expiry are kept for what follows.
//   A sync failure (the USIM returns AUTS) restarts at 1 with `auts` in the
//   Authorization (RFC 3310 3.4).
//
// No sockets here: the caller hands in `send(buf, dst_addr, dst_port,
// src_port)`, `timer(ms, fn) -> { cancel }`, the card ({ open, send, close },
// ue/aka.uc) and the xfrm module, and feeds received messages to
// on_message(). UDP only for now; retransmission per RFC 3261 17.1.2 (T1
// doubling up to T2, giving up after 64*T1).

'use strict';

import * as AKA from 'ue_aka';
import * as SA from 'ue_secagree';
import * as fs from 'fs';

let SIP = require('sipd_sip');

const MMTEL = 'urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel';

export function hostport(addr, port)
{
	let h = index(addr, ':') >= 0 ? '[' + addr + ']' : addr;
	return port ? h + ':' + port : h;
}

// urn:gsma:imei with the spare digit 0 in place of the check digit
// (RFC 7254 4, TS 23.003 6.2.1)
export function imei_urn(imei)
{
	if (!match(imei ?? '', /^[0-9]{14,16}$/))
		return null;
	return sprintf('urn:gsma:imei:%s-%s-0', substr(imei, 0, 8), substr(imei, 8, 6));
}

// P-Access-Network-Info for E-UTRAN (TS 24.229 7.2A.4): MCC, MNC (3 digits
// as received, 2 or 3), TAC (4 hex), ECI (7 hex)
export function pani_eutran(mcc, mnc, mnc_digits, tac, eci, tdd)
{
	if (mcc == null || mnc == null || tac == null || eci == null)
		return null;
	let m = (mnc_digits == 3) ? sprintf('%03d', +mnc) : sprintf('%02d', +mnc);
	return sprintf('3GPP-E-UTRAN-%s; utran-cell-id-3gpp=%03d%s%04X%07X',
		tdd ? 'TDD' : 'FDD', +mcc, m, +tac, +eci);
}

// random hex for tags, branches and the cnonce, from the kernel
function rnd_hex(n)
{
	let f = fs.open('/dev/urandom', 'r');
	let b = f ? f.read(n) : null;
	if (f)
		f.close();
	return hexenc(b ?? sprintf('%016x', time()));
}

// header value helpers
function q(s) { return '"' + s + '"'; }

export function create(o)
{
	let ids = (o.impi && o.impu && o.domain)
		? { impi: o.impi, impu: o.impu, domain: o.domain, realm: o.domain }
		: AKA.identities(o.imsi, o.mnc_len);

	let self = {
		state: 'idle',       // idle | reserving | unprotected | auth | protected | registered | failed
		ids: ids,
		call_id: o.call_id ?? (rnd_hex(12) + '@' + hostport(o.ue_addr)),
		from_tag: o.from_tag ?? rnd_hex(6),
		cseq: 0,
		spis: null,          // { spi_c, spi_s } reserved inbound
		sa_set: null,        // applied SA plan
		server: null,        // chosen Security-Server entry
		server_raw: null,    // Security-Server as received, for Security-Verify
		chal: null,          // { realm, nonce, opaque, algorithm, qop }
		aka: null,           // { res, ck, ik }
		nc: 0,
		result: null,        // on 200: { expires, service_route, associated, pcscf }
		error: null,
	};

	let log = o.log ?? (() => null);
	let timer = o.timer;
	let t1 = o.t1 ?? 500, t2 = o.t2 ?? 4000;
	let pending = null;       // { branch, buf, dst, port, src, wait, total, handle }
	let done_cb = null;
	let pcscf_port = o.pcscf_port ?? 5060;

	if (!ids) {
		self.state = 'failed';
		self.error = { error: 'identity', detail: 'no IMSI/MNC length or explicit identities' };
	}

	// closures resolve names at compile time: declared before use
	let release_reserved = () => {
		if (!self.spis)
			return;
		for (let spi in [ self.spis.spi_c, self.spis.spi_s ])
			o.xfrm.sa_del({ src: o.pcscf_addr, dst: o.ue_addr, spi: spi });
		self.spis = null;
	};

	let stop_pending;
	let finish = (err) => {
		stop_pending();
		self.error = err;
		if (err) {
			self.state = 'failed';
			SA.remove(o.xfrm, self.sa_set);
			self.sa_set = null;
			release_reserved();
		}
		else
			self.state = 'registered';
		let cb = done_cb;
		done_cb = null;
		if (cb)
			cb(err, err ? null : self.result);
	};

	// one client transaction, retransmitted over UDP until a response:
	// Timer E from T1 doubling up to T2, Timer F = 64*T1 (RFC 3261 17.1.2.2)
	stop_pending = () => {
		if (pending) {
			pending.handle?.cancel();
			pending.timer_f?.cancel();
		}
		pending = null;
	};

	let transmit = (buf, port, src) => {
		stop_pending();
		let p = { buf: buf, port: port, src: src, wait: t1 };
		pending = p;
		p.timer_f = timer(64 * t1, () => {
			if (pending === p)
				finish({ error: 'timeout', state: self.state });
		});
		let tick;
		tick = () => {
			if (pending !== p)
				return;
			o.send(p.buf, o.pcscf_addr, p.port, p.src);
			p.handle = timer(p.wait, tick);
			p.wait = (p.wait * 2 > t2) ? t2 : p.wait * 2;
		};
		tick();
	};

	let authorization = (extra) => {
		let a = sprintf('Digest username=%s, realm=%s, uri=%s', q(ids.impi), q(self.chal?.realm ?? ids.realm),
			q('sip:' + ids.domain));
		if (!self.chal)
			return a + ', nonce="", response=""';

		a += sprintf(', nonce=%s, algorithm=%s', q(self.chal.nonce), self.chal.algorithm ?? 'AKAv1-MD5');
		if (self.chal.opaque != null)
			a += sprintf(', opaque=%s', q(self.chal.opaque));
		return a + (extra ?? '');
	};

	// Digest response (RFC 2617 3.2.2) with the AKAv1 password = RES
	let digest = (password) => {
		let ha1 = SIP.md5(sprintf('%s:%s:%s', ids.impi, self.chal.realm, password));
		let ha2 = SIP.md5(sprintf('REGISTER:sip:%s', ids.domain));

		if (self.chal.qop != null && index(split(self.chal.qop, ','), 'auth') >= 0) {
			let nc = sprintf('%08x', ++self.nc);
			let cnonce = o.cnonce ?? rnd_hex(8);
			let r = SIP.md5(sprintf('%s:%s:%s:%s:auth:%s', ha1, self.chal.nonce, nc, cnonce, ha2));
			return sprintf(', response=%s, qop=auth, nc=%s, cnonce=%s', q(r), nc, q(cnonce));
		}
		return sprintf(', response=%s', q(SIP.md5(sprintf('%s:%s:%s', ha1, self.chal.nonce, ha2))));
	};

	// the REGISTER; `phase` 'initial' (unprotected) or 'protected'
	let register = (phase, auth_extra) => {
		let protect = (phase == 'protected' || phase == 'dereg');
		let expires = (phase == 'dereg') ? 0 : (o.expires ?? 600000);
		let via_port = o.port_s;
		let branch = 'z9hG4bK' + rnd_hex(8);
		// +sip.instance: the IMEI (TS 24.229 5.1.1.2.1), else a UUID URN
		// (a card without a modem: o.instance), else none
		let inst = imei_urn(o.imei) ?? o.instance;
		let contact = sprintf('<sip:%s@%s>;expires=%d%s;+g.3gpp.icsi-ref=%s%s',
			o.imsi ?? split(ids.impi, '@')[0], hostport(o.ue_addr, o.port_s), expires,
			inst ? ';+sip.instance=' + q('<' + inst + '>') : '', q(MMTEL), o.smsip ? ';+g.3gpp.smsip' : '');

		self.cseq++;

		let hs = [
			[ 'Via', sprintf('SIP/2.0/UDP %s;branch=%s;rport', hostport(o.ue_addr, via_port), branch) ],
			[ 'Max-Forwards', '70' ],
			[ 'From', sprintf('<%s>;tag=%s', ids.impu, self.from_tag) ],
			[ 'To', sprintf('<%s>', ids.impu) ],
			[ 'Call-ID', self.call_id ],
			[ 'CSeq', sprintf('%d REGISTER', self.cseq) ],
			[ 'Contact', contact ],
			[ 'Expires', sprintf('%d', expires) ],
			[ 'Authorization', authorization(auth_extra) ],
			[ 'Require', 'sec-agree' ],
			[ 'Proxy-Require', 'sec-agree' ],
			[ 'Supported', 'path, sec-agree' ],
			[ 'Allow', 'INVITE, ACK, CANCEL, BYE, UPDATE, PRACK, MESSAGE, OPTIONS, NOTIFY, REFER, INFO' ],
			[ 'Security-Client', SA.client_header(self.spis.spi_c, self.spis.spi_s, o.port_c, o.port_s,
				o.algs, o.ealgs) ],
			[ 'P-Access-Network-Info', o.pani ],
			[ 'User-Agent', o.user_agent ?? 'wwand-ims' ],
		];
		if (protect)
			push(hs, [ 'Security-Verify', self.server_raw ]);

		let buf = SIP.build(sprintf('REGISTER sip:%s SIP/2.0', ids.domain), hs, '');

		self.state = (phase == 'dereg') ? 'deregistering' : (protect ? 'protected' : 'unprotected');
		transmit(buf, protect ? self.server.port_s : pcscf_port, o.port_c);
	};

	let on_401 = (msg) => {
		let ch = SIP.auth_parse(SIP.get(msg, 'www-authenticate'));
		let srv = SIP.all(msg, 'security-server');

		if (!ch?.nonce)
			return finish({ error: 'challenge', detail: 'no Digest nonce in 401' });
		if (lc(ch.algorithm ?? '') != 'akav1-md5')
			return finish({ error: 'challenge', detail: 'algorithm ' + (ch.algorithm ?? 'none') });

		let raw = join(', ', srv);
		let chosen = SA.choose(SA.parse(raw), o.algs, o.ealgs);
		if (!chosen)
			return finish({ error: 'sec-agree', detail: 'no acceptable Security-Server: ' + raw });

		let n = AKA.nonce_split(ch.nonce);
		if (!n)
			return finish({ error: 'challenge', detail: 'nonce is not RAND || AUTN' });

		self.chal = ch;
		self.server = { ...chosen, addr: o.pcscf_addr };
		self.server_raw = raw;
		self.nc = 0;
		self.state = 'auth';

		AKA.authenticate(o.card, o.aid ?? AKA.AID_USIM, n.rand, n.autn, (err, r) => {
			if (self.state != 'auth')
				return;

			if (err)
				return finish({ error: 'aka', detail: err });

			if (r.sync) {
				// RFC 3310 3.4: AUTS goes back in a fresh unprotected REGISTER,
				// the Digest computed with an empty password
				log('notice', 'AKA sync failure, resynchronising with AUTS');
				if (self.resynced)
					return finish({ error: 'aka', detail: 'second sync failure' });
				self.resynced = true;
				return register('initial', sprintf(', auts=%s', q(AKA.auts_param(r.auts))) + digest(''));
			}

			self.aka = r;
			self.sa_set = SA.plan(
				{ addr: o.ue_addr, port_c: o.port_c, port_s: o.port_s, spi_c: self.spis.spi_c, spi_s: self.spis.spi_s },
				self.server, self.server.alg, self.server.ealg, r.ck, r.ik, o.reqid ?? 0x1500, o.sa_opts);

			let e = SA.apply(o.xfrm, self.sa_set, [ self.spis.spi_c, self.spis.spi_s ]);
			if (e) {
				self.sa_set = null;
				return finish({ error: 'xfrm', detail: e });
			}
			// the reserved SPIs are now real SAs of the set
			self.spis_applied = true;

			register('protected', digest(AKA.akav1_password(r.res)));
		});
	};

	let on_200 = (msg) => {
		let ours = null;
		for (let c in SIP.all(msg, 'contact'))
			if (index(c, hostport(o.ue_addr, o.port_s)) >= 0)
				ours = c;
		let exp = SIP.param(ours ?? '', 'expires') ?? SIP.get(msg, 'expires');

		self.result = {
			expires: exp != null ? +exp : null,
			service_route: SIP.all(msg, 'service-route'),
			associated: map(SIP.all(msg, 'p-associated-uri'), (u) => SIP.uri_of(u)),
			path: SIP.all(msg, 'path'),
			pcscf: { addr: o.pcscf_addr, port_s: self.server.port_s, port_c: self.server.port_c },
			sec: { alg: self.server.alg, ealg: self.server.ealg },
		};
		finish(null);
	};

	self.start = function(cb) {
		if (self.state == 'failed')
			return cb(self.error, null);

		done_cb = cb;
		self.state = 'reserving';
		let r = SA.reserve(o.xfrm, o.ue_addr, o.pcscf_addr);
		if (r.error)
			return finish({ error: 'xfrm', detail: r.error });
		self.spis = r;
		register('initial');
	};

	// a received SIP message (string); only responses to our REGISTER matter
	self.on_message = function(buf) {
		let msg = SIP.parse(buf);
		let cs = msg ? SIP.cseq(msg) : null;

		if (!msg?.status || cs?.method != 'REGISTER' || cs.seq != self.cseq || SIP.get(msg, 'call-id') != self.call_id)
			return false;
		if (msg.status < 200)
			return true;           // provisional: keep waiting

		stop_pending();

		if (msg.status == 401 && self.state == 'unprotected')
			on_401(msg);
		else if (msg.status >= 200 && msg.status < 300 && self.state == 'protected')
			on_200(msg);
		else if (self.state == 'deregistering') {
			let cb = done_cb;
			done_cb = null;
			self.close();
			if (cb)
				cb((msg.status >= 200 && msg.status < 300) ? null : { error: 'status', status: msg.status }, null);
		}
		else
			finish({ error: 'status', status: msg.status, reason: msg.reason, state: self.state,
			         warning: SIP.get(msg, 'warning') });
		return true;
	};

	// de-REGISTER (Expires 0) inside the SAs, then take them down;
	// cb(err) once the P-CSCF answered or Timer F fired
	self.deregister = function(cb) {
		if (self.state != 'registered')
			return cb({ error: 'not_registered' });
		done_cb = (e) => { if (e) self.close(); cb(e); };
		// the challenge stays valid for the registration (nc counts on)
		register('dereg', digest(AKA.akav1_password(self.aka.res)));
	};

	// tear the registration's security down (SAs and any reservation)
	self.close = function() {
		stop_pending();
		SA.remove(o.xfrm, self.sa_set);
		self.sa_set = null;
		if (!self.spis_applied)
			release_reserved();
		self.spis = null;
		self.state = 'idle';
	};

	return self;
}
