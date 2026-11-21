// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// SIP message parsing and building (RFC 3261), SDP (RFC 4566, offer/answer
// RFC 3264) and Digest authentication (RFC 2617 with qop=auth, as RFC 3261
// 22.4 requires). Pure functions only: no sockets, no state. sipd talks to
// one or a few phones on the LAN, so this covers what desk phones and
// softphones send, not the whole grammar.

'use strict';


// RFC 3261 7.3.3 compact forms
const COMPACT = {
	v: 'via', f: 'from', t: 'to', i: 'call-id', m: 'contact', l: 'content-length',
	c: 'content-type', k: 'supported', e: 'content-encoding', s: 'subject',
};

function hname(n)
{
	n = lc(trim(n));
	return COMPACT[n] ?? n;
}

// first value of a header, or null
function get(msg, name)
{
	name = hname(name);
	for (let h in msg?.headers ?? [])
		if (h[0] == name)
			return h[1];
	return null;
}

// split a header value at commas outside "quotes" and <angle brackets>
function split_list(v)
{
	let out = [], cur = '', q = false, a = false;

	for (let i = 0; i < length(v); i++) {
		let c = substr(v, i, 1);

		if (c == '"' && !a)
			q = !q;
		else if (c == '<' && !q)
			a = true;
		else if (c == '>' && !q)
			a = false;

		if (c == ',' && !q && !a) {
			push(out, trim(cur));
			cur = '';
		}
		else
			cur += c;
	}
	if (length(trim(cur)))
		push(out, trim(cur));
	return out;
}

// every value of a header, comma lists split (for Via, Contact, Route)
function all(msg, name)
{
	name = hname(name);
	let out = [];

	for (let h in msg?.headers ?? [])
		if (h[0] == name)
			for (let v in split_list(h[1]))
				push(out, v);
	return out;
}

// a ;param=value from a header value (tag, branch, expires, received, ...)
function param(v, name)
{
	let m = match(v ?? '', regexp(';[ \t]*' + name + '(=("[^"]*"|[^;,> \t]*))?([;, \t>]|$)', 'i'));

	if (!m)
		return null;
	return replace(m[2] ?? '', /^"|"$/g, '');
}

// the URI inside a name-addr ("Alice" <sip:a@b>;tag=x) or an addr-spec
function uri_of(v)
{
	let m = match(v ?? '', /<([^>]*)>/);

	return m ? m[1] : trim(split(v ?? '', ';')[0]);
}

// sip:user@host:port;params -> { user, host, port, params }
function parse_uri(u)
{
	let m = match(u ?? '', /^(sips?|tel):(([^@;>]*)@)?([^;:>?]*)(:([0-9]+))?([^>?]*)/i);

	if (!m)
		return null;
	if (lc(m[1]) == 'tel')
		return { scheme: 'tel', user: m[4], host: null, port: null, params: m[7] ?? '' };

	return { scheme: lc(m[1]), user: m[3], host: m[4], port: m[6] ? +m[6] : null, params: m[7] ?? '' };
}

function cseq(msg)
{
	let m = match(get(msg, 'cseq') ?? '', /^([0-9]+)\s+([A-Z]+)/);

	return m ? { seq: +m[1], method: m[2] } : null;
}

// parse(buf) -> { method, uri } or { status, reason }, plus headers (a list
// of [lowercase name, value], in order; comma-separated Via/Contact/Route
// values are kept as received) and body. null when it is not SIP.
function parse(buf)
{
	if (type(buf) != 'string')
		return null;

	let sep = index(buf, '\r\n\r\n');
	let head = (sep >= 0) ? substr(buf, 0, sep) : buf;
	let body = (sep >= 0) ? substr(buf, sep + 4) : '';

	// RFC 3261 7.3.1: header continuation lines start with whitespace
	head = replace(head, /\r\n[ \t]+/g, ' ');

	let lines = split(head, '\r\n');
	let first = shift(lines);
	let m, msg;

	if ((m = match(first, /^SIP\/2\.0 ([0-9]{3}) ?(.*)$/)))
		msg = { status: +m[1], reason: m[2] };
	else if ((m = match(first, /^([A-Z]+) (\S+) SIP\/2\.0$/)))
		msg = { method: m[1], uri: m[2] };
	else
		return null;

	msg.headers = [];
	for (let l in lines) {
		let c = index(l, ':');

		if (c > 0)
			push(msg.headers, [ hname(substr(l, 0, c)), trim(substr(l, c + 1)) ]);
	}

	let cl = get(msg, 'content-length');
	msg.body = (cl != null) ? substr(body, 0, +cl) : body;

	return msg;
}

// build a message: start line, headers as [name, value] pairs, body
function build(start, headers, body)
{
	body ??= '';
	let out = start + '\r\n';

	for (let h in headers)
		if (h[1] != null && lc(h[0]) != 'content-length')
			out += h[0] + ': ' + h[1] + '\r\n';
	out += 'Content-Length: ' + length(body) + '\r\n\r\n' + body;
	return out;
}

const NAMES = {
	via: 'Via', from: 'From', to: 'To', 'call-id': 'Call-ID', cseq: 'CSeq',
	'record-route': 'Record-Route',
};

// RFC 3261 8.2.6: a response copies Via (all, in order), From, To, Call-ID
// and CSeq from the request; the To tag is added when given and absent.
function response(req, status, reason, extra, body)
{
	let hs = [];

	for (let h in req.headers)
		if (h[0] in NAMES && h[0] != 'record-route') {
			let v = h[1];

			if (h[0] == 'to' && extra?.to_tag && param(v, 'tag') == null)
				v += ';tag=' + extra.to_tag;
			push(hs, [ NAMES[h[0]], v ]);
		}

	for (let h in (extra?.headers ?? []))
		push(hs, h);

	return build(sprintf('SIP/2.0 %d %s', status, reason), hs, body);
}

// ---- SDP ------------------------------------------------------------------

// static payload types (RFC 3551) and the dynamic one sipd uses for DTMF
const CODECS = {
	pcma: { pt: 8, name: 'PCMA', rate: 8000 },
	pcmu: { pt: 0, name: 'PCMU', rate: 8000 },
	g722: { pt: 9, name: 'G722', rate: 8000 },	// RFC 3551: clock 8000 by convention
};
const DTMF_PT = 101;

// sdp_offer({ ip, port, session, codecs: [ 'pcma', ... ] })
function sdp(o)
{
	let pts = map(o.codecs, (c) => CODECS[c].pt);
	let s = [
		'v=0',
		sprintf('o=wwand-ims %d %d IN IP4 %s', o.session, o.version ?? o.session, o.ip),
		's=wwand-ims',
		'c=IN IP4 ' + o.ip,
		't=0 0',
		sprintf('m=audio %d RTP/AVP %s %d', o.port, join(' ', pts), DTMF_PT),
	];

	for (let c in o.codecs)
		push(s, sprintf('a=rtpmap:%d %s/%d', CODECS[c].pt, CODECS[c].name, CODECS[c].rate));
	push(s, sprintf('a=rtpmap:%d telephone-event/8000', DTMF_PT));
	push(s, sprintf('a=fmtp:%d 0-15', DTMF_PT));
	push(s, 'a=ptime:20');
	push(s, 'a=' + (o.dir ?? 'sendrecv'));

	return join('\r\n', s) + '\r\n';
}

// parse the audio part of an SDP: { ip, port, pts: [ payload types ],
// names: { pt: 'pcma' }, dtmf_pt, dir } or null
function sdp_parse(body)
{
	let ip = null, port = null, pts = [], names = {}, dtmf = null, dir = 'sendrecv';
	let in_audio = false;

	for (let l in split(replace(body ?? '', /\r/g, ''), '\n')) {
		let m;

		if ((m = match(l, /^c=IN IP4 (\S+)/)))
			ip = m[1];
		else if ((m = match(l, /^m=(\S+) ([0-9]+) RTP\/AVP (.*)$/))) {
			in_audio = (m[1] == 'audio');
			if (in_audio) {
				port = +m[2];
				pts = map(split(trim(m[3]), /\s+/), (p) => +p);
			}
		}
		else if (in_audio && (m = match(l, /^a=rtpmap:([0-9]+) ([^\/]+)\//))) {
			let n = lc(m[2]);

			if (n == 'telephone-event')
				dtmf = +m[1];
			else
				names[m[1]] = n;
		}
		else if (in_audio && (m = match(l, /^a=(sendrecv|sendonly|recvonly|inactive)$/)))
			dir = m[1];
	}

	if (port == null)
		return null;

	// static payload types need no rtpmap (RFC 3551)
	for (let p in pts)
		for (let c, d in CODECS)
			if (d.pt == p && names[sprintf('%d', p)] == null)
				names[sprintf('%d', p)] = c;

	return { ip: ip, port: port, pts: pts, names: names, dtmf_pt: dtmf, dir: dir };
}

// the first codec of `ours` (preference order) the peer offered, or null
function sdp_pick(peer, ours)
{
	for (let c in ours)
		for (let p in peer?.pts ?? [])
			if (peer.names[sprintf('%d', p)] == c)
				return c;
	return null;
}

// ---- Digest (RFC 2617, qop=auth) -------------------------------------------

// MD5 (RFC 1321). ucode-mod-digest when it is installed; otherwise this
// implementation, so sipd does not depend on that package (and the host
// tests run without it). Digest auth is the only user.
let native_md5 = null;
try { native_md5 = require('digest')?.md5; } catch (e) { native_md5 = null; }

const MD5_S = [ 7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21 ];
const MD5_K = [
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

function md5_pure(str)
{
	const M = 0xffffffff;
	let rotl = (x, c) => ((x << c) | (x >> (32 - c))) & M;
	let n = length(str), msg = str + chr(0x80);

	while (length(msg) % 64 != 56)
		msg += chr(0);
	let bits = n * 8;
	for (let i = 0; i < 8; i++)
		msg += chr((bits >> (8 * i)) & 0xff);

	let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;

	for (let off = 0; off < length(msg); off += 64) {
		let w = [];
		for (let i = 0; i < 16; i++)
			w[i] = ord(msg, off + 4 * i) | (ord(msg, off + 4 * i + 1) << 8) |
			       (ord(msg, off + 4 * i + 2) << 16) | (ord(msg, off + 4 * i + 3) << 24);

		let a = a0, b = b0, c = c0, d = d0;
		for (let i = 0; i < 64; i++) {
			let f, g;
			if (i < 16) { f = (b & c) | (~b & M & d); g = i; }
			else if (i < 32) { f = (d & b) | (~d & M & c); g = (5 * i + 1) % 16; }
			else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
			else { f = c ^ (b | (~d & M)); g = (7 * i) % 16; }
			f = (f + a + MD5_K[i] + w[g]) & M;
			a = d; d = c; c = b;
			b = (b + rotl(f, MD5_S[(i >> 4) * 4 + (i % 4)])) & M;
		}
		a0 = (a0 + a) & M; b0 = (b0 + b) & M; c0 = (c0 + c) & M; d0 = (d0 + d) & M;
	}

	let out = '';
	for (let v in [ a0, b0, c0, d0 ])
		for (let i = 0; i < 4; i++)
			out += sprintf('%02x', (v >> (8 * i)) & 0xff);
	return out;
}

function md5(s)
{
	return native_md5 ? native_md5(s) : md5_pure(s);
}

// Authorization / Proxy-Authorization header -> { username, realm, nonce,
// uri, response, qop, nc, cnonce, ... }
function auth_parse(v)
{
	let m = match(v ?? '', /^Digest\s+(.*)$/i);

	if (!m)
		return null;

	let out = {};
	for (let p in match(m[1], /([a-zA-Z]+)=("[^"]*"|[^,\s]*)/g))
		out[lc(p[1])] = replace(p[2], /^"|"$/g, '');
	return out;
}

// does the Authorization `a` prove knowledge of `password` for `method`?
function auth_check(a, method, password)
{
	if (!a?.username || !a?.nonce || !a?.uri || !a?.response)
		return false;

	let ha1 = md5(sprintf('%s:%s:%s', a.username, a.realm, password));
	let ha2 = md5(sprintf('%s:%s', method, a.uri));
	let want = a.qop
		? md5(sprintf('%s:%s:%s:%s:%s:%s', ha1, a.nonce, a.nc, a.cnonce, a.qop, ha2))
		: md5(sprintf('%s:%s:%s', ha1, a.nonce, ha2));

	return lc(a.response) == want;
}

// ---- call diversion: History-Info (RFC 7044) -> Diversion (RFC 5806) ----
// The IMS network reports a forwarded call (TS 24.604 CDIV) in History-Info:
// one entry per hop, in order; the new target of a diversion carries the
// RFC 4458 `cause` URI parameter, its parent entry (index minus the last
// component) is the diverting user. What the subscriber may not see the
// network leaves out itself (Privacy: history), so it is passed as it comes.

// RFC 4458 cause -> RFC 5806 reason (the mapping of RFC 6044 / TS 29.163)
const DIVERSION_REASON = {
	'302': 'unconditional', '486': 'user-busy', '408': 'no-answer', '480': 'deflection',
	'487': 'deflection', '503': 'unavailable', '404': 'unknown',
};

// the entries of every History-Info value: { uri, user, index, cause }
function history_info(values)
{
	let out = [];
	for (let v in values ?? [])
		for (let e in split_list(v)) {
			let m = match(e, /<([^>]*)>(.*)$/);
			if (!m)
				continue;
			let uri = m[1];
			let u = match(uri, /^(tel|sips?):([^@;?>]+)/);
			let c = match(uri, /;cause=([0-9]{3})/);
			let ix = match(m[2], /;[ \t]*index=([0-9.]+)/);
			push(out, { uri: uri, user: u ? u[2] : null, index: ix ? ix[1] : null, cause: c ? c[1] : null });
		}
	return out;
}

// the diversions in History-Info entries, the latest first (Diversion's
// order): { user, reason, cause }
function diversions(entries)
{
	let out = [];
	for (let i = 0; i < length(entries); i++) {
		let e = entries[i];
		if (!e.cause)
			continue;
		let from = null;
		if (e.index && index(e.index, '.') > 0) {
			let parent = replace(e.index, /\.[0-9]+$/, '');
			for (let x in entries)
				if (x.index == parent)
					from = x;
		}
		from ??= (i > 0) ? entries[i - 1] : null;
		if (from?.user)
			unshift(out, { user: from.user, reason: DIVERSION_REASON[e.cause] ?? 'unknown', cause: e.cause });
	}
	return out;
}

// Diversion header values for the LAN side (Asterisk: REDIRECTING()); the
// host is ours, the user the diverting number
function diversion_headers(divs, host)
{
	let out = [];
	for (let i = 0; i < length(divs); i++)
		push(out, sprintf('<sip:%s@%s>;reason=%s;counter=1', divs[i].user, host, divs[i].reason));
	return out;
}

function challenge(realm, nonce)
{
	return sprintf('Digest realm="%s", nonce="%s", algorithm=MD5, qop="auth"', realm, nonce);
}

return {
	parse: parse, get: get, all: all, param: param, uri_of: uri_of, parse_uri: parse_uri,
	cseq: cseq, build: build, response: response,
	CODECS: CODECS, DTMF_PT: DTMF_PT, sdp: sdp, sdp_parse: sdp_parse, sdp_pick: sdp_pick,
	md5: md5, md5_pure: md5_pure, auth_parse: auth_parse, auth_check: auth_check, challenge: challenge,
	history_info: history_info, diversions: diversions, diversion_headers: diversion_headers,
};
