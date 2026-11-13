// sipcall.uc SERVER USER PASSWORD [NUMBER [SECONDS]]
//
// A minimal SIP UA for testing sipd from a workstation: registers USER with
// Digest, then (with NUMBER) calls it, prints every response, ACKs the
// final one and, on a 200 OK, hangs up with BYE after SECONDS (default 5).
// Uses the host's ucode with the socket module and sipd's own message layer:
//
//   ucode -L "$HOME/.local/lib/ucode/*.so" -L sipd/*.uc tools/sipcall.uc 192.168.203.245 100 secret +4930123

'use strict';

import * as socket from 'socket';
import * as fs from 'fs';

let S = require('sipd_sip');
let server = ARGV[0], user = ARGV[1], pass = ARGV[2], number = ARGV[3], secs = ARGV[4];

if (!pass) {
	warn('usage: sipcall.uc SERVER USER PASSWORD [NUMBER [SECONDS]]\n');
	exit(2);
}
secs = +(secs ?? 5);

let sock = socket.create(socket.AF_INET, socket.SOCK_DGRAM);
sock.connect({ address: server, port: 5060 });
let me = sock.sockname();
let srv = { address: server, port: 5060 };
let seq = 0;
let rnd = () => sprintf('%08x', ord(fs.open('/dev/urandom', 'r').read(4), 0) * 16777216 + time());

let send = (text) => sock.send(text, 0, srv);

let recv = (timeout_ms) => {
	let end = time() * 1000 + timeout_ms;

	while (time() * 1000 < end) {
		let r = socket.poll(500, [ sock, socket.POLLIN ]);

		if (r?.[0]?.[1] & socket.POLLIN) {
			let m = S.parse(sock.recv(65535));

			if (m) {
				print(sprintf('  <- %s%s\n', m.status ?? m.method, m.status ? ' ' + m.reason : ''));
				return m;
			}
		}
	}
	return null;
};

let authorize = (chal, method, uri) => {
	let realm = match(chal, /realm="([^"]*)"/)[1];
	let nonce = match(chal, /nonce="([^"]*)"/)[1];
	let ha1 = S.md5(sprintf('%s:%s:%s', user, realm, pass));
	let ha2 = S.md5(sprintf('%s:%s', method, uri));
	let cn = rnd();

	return sprintf('Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", qop=auth, nc=00000001, cnonce="%s"',
		user, realm, nonce, uri, S.md5(sprintf('%s:%s:00000001:%s:auth:%s', ha1, nonce, cn, ha2)), cn);
};

let request = (method, uri, to, call_id, ftag, extra, body) => {
	let hs = [
		[ 'Via', sprintf('SIP/2.0/UDP %s:%d;branch=z9hG4bK%s;rport', me.address, me.port, rnd()) ],
		[ 'Max-Forwards', '70' ],
		[ 'From', sprintf('<sip:%s@%s>;tag=%s', user, server, ftag) ],
		[ 'To', to ],
		[ 'Call-ID', call_id ],
		[ 'CSeq', sprintf('%d %s', ++seq, method) ],
		[ 'Contact', sprintf('<sip:%s@%s:%d>', user, me.address, me.port) ],
		...(extra ?? []),
	];
	print(sprintf('  -> %s %s\n', method, uri));
	send(S.build(sprintf('%s %s SIP/2.0', method, uri), hs, body));
};

// REGISTER, answering the challenge
let ruri = 'sip:' + server, aor = sprintf('<sip:%s@%s>', user, server), rid = rnd() + '@reg';
print('REGISTER\n');
request('REGISTER', ruri, aor, rid, 'r1', [ [ 'Expires', '300' ] ]);
let r = recv(3000);
if (r?.status == 401) {
	request('REGISTER', ruri, aor, rid, 'r1', [ [ 'Expires', '300' ],
		[ 'Authorization', authorize(S.get(r, 'www-authenticate'), 'REGISTER', ruri) ] ]);
	r = recv(3000);
}
if (r?.status != 200) {
	print('register failed\n');
	exit(1);
}

if (!number)
	exit(0);

// INVITE with an offer
let curi = sprintf('sip:%s@%s', number, server), cto = sprintf('<%s>', curi), cid = rnd() + '@call';
let offer = S.sdp({ ip: me.address, port: 30000, session: 1, codecs: [ 'pcma', 'pcmu' ] });
let sdp_h = [ [ 'Content-Type', 'application/sdp' ] ];

print(sprintf('INVITE %s\n', number));
request('INVITE', curi, cto, cid, 'c1', sdp_h, offer);
r = recv(3000);
if (r?.status == 407) {
	request('INVITE', curi, cto, cid, 'c1',
		[ ...sdp_h, [ 'Proxy-Authorization', authorize(S.get(r, 'proxy-authenticate'), 'INVITE', curi) ] ], offer);
	r = recv(3000);
}

let to_tagged = cto, final = null, started = time();
while (time() - started < 60) {
	if (r?.status >= 200) {
		final = r;
		break;
	}
	if (S.param(S.get(r, 'to'), 'tag') != null)
		to_tagged = S.get(r, 'to');
	r = recv(60000);
}

if (!final) {
	print('no final response\n');
	exit(1);
}
to_tagged = S.get(final, 'to');
request('ACK', curi, to_tagged, cid, 'c1');
if (final.status == 200) {
	print(sprintf('answered, hanging up in %d s\n', secs));
	sleep(secs * 1000);
	request('BYE', curi, to_tagged, cid, 'c1');
	recv(3000);
}
print(sprintf('result %d %s%s\n', final.status, final.reason,
	S.get(final, 'reason') ? ' (' + S.get(final, 'reason') + ')' : ''));
