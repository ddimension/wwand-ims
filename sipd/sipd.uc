#!/usr/bin/env ucode
// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// sipd: SIP for LAN phones, bridged to the modem's IMS calls through the
// wwand ims plugin. Reads /etc/config/wwand_ims (sip_gateway, extension),
// listens on UDP, follows the plugin's wwand.ims.call events and calls its
// ops over ubus.
//
//   ucode -L /usr/share/wwand-ims /usr/share/wwand-ims/sipd.uc

'use strict';

import * as uloop from 'uloop';
import * as ubus from 'ubus';
import * as uci from 'uci';
import * as socket from 'socket';
import * as fs from 'fs';

let CORE = require('sipd_core');

let level = { debug: 0, info: 1, warn: 2, error: 3 };
let verbose = (ARGV[0] == '-v');
let log = (lv, msg) => {
	if (verbose || level[lv] >= 1)
		warn(sprintf('%s %s\n', lv, msg));
};

// ---- configuration ----------------------------------------------------------------

let cur = uci.cursor();
let gw = null, users = {}, modem = null;

cur.foreach('wwand_ims', 'sip_gateway', (s) => { gw ??= s; });
cur.foreach('wwand_ims', 'extension', (s) => {
	if (s.username && s.password) {
		users[s.username] = { password: s.password };
		modem ??= s.modem;
	}
});

if (!gw || !length(keys(users))) {
	log('error', 'sipd: no sip_gateway or no extension with username and password in /etc/config/wwand_ims');
	exit(1);
}

uloop.init();
let bus = ubus.connect();

if (!bus) {
	log('error', 'sipd: no ubus');
	exit(1);
}

// `listen` names a netifd interface or is an address
let listen_ip = gw.listen ?? 'lan';
if (!match(listen_ip, /^[0-9.]+$/)) {
	let st = bus.call('network.interface.' + listen_ip, 'status', {});
	listen_ip = st?.['ipv4-address']?.[0]?.address;
}
if (!listen_ip) {
	log('error', sprintf('sipd: no IPv4 address for listen %s', gw.listen));
	exit(1);
}

let port = +(gw.port ?? 5060);
let codecs = filter(gw.codec ?? [ 'pcma', 'pcmu' ], (c) => c in { pcma: 1, pcmu: 1, g722: 1 });
modem ??= 'wwmodem0';

// ---- transport ----------------------------------------------------------------------

let sock = socket.create(socket.AF_INET, socket.SOCK_DGRAM);
if (!sock || !sock.bind({ address: listen_ip, port: port })) {
	log('error', sprintf('sipd: cannot bind %s:%d (%s)', listen_ip, port, socket.error()));
	exit(1);
}

let send = (text, addr) => {
	if (verbose)
		log('debug', sprintf('-> %s:%d\n%s', addr.address, addr.port, text));
	sock.send(text, 0, { address: addr.address, port: addr.port });
};

let random = () => {
	let f = fs.open('/dev/urandom', 'r');
	let b = f.read(8);
	f.close();
	return join('', map(split(b, ''), (c) => sprintf('%02x', ord(c))));
};

// ---- media ------------------------------------------------------------------------------
// Until mediad exists: reserve an even RTP port and keep it, no audio.
let media_socks = {};
let media = {
	start: (c) => {
		for (let p = 40000; p < 41000; p += 2) {
			let s = socket.create(socket.AF_INET, socket.SOCK_DGRAM);

			if (s?.bind({ address: listen_ip, port: p })) {
				media_socks[c.call_id] = s;
				return p;
			}
			s?.close();
		}
		return 0;
	},
	connect: (c) => log('info', sprintf('sipd: media %s <-> %s:%d (%s): no media bridge yet',
		c.call_id, c.remote_rtp?.address, c.remote_rtp?.port, c.codec)),
	stop: (c) => {
		media_socks[c.call_id]?.close();
		delete media_socks[c.call_id];
	},
};

// ---- the plugin ---------------------------------------------------------------------------

let ims = (op, args, cb) => {
	bus.defer('wwand', 'modem_plugin', { modem: modem, plugin: 'ims', op: op, args: args }, (rc, res) => {
		if (rc != 0 || res?.ok === false)
			return cb({ error: res?.error ?? rc }, null);
		cb(null, res);
	});
};

let core = CORE.create({
	cfg: { ip: listen_ip, port: port, realm: gw.realm ?? 'wwand-ims', modem: modem,
	       codecs: codecs, users: users },
	send: send,
	ims: ims,
	media: media,
	timer: (ms, fn) => {
		let t = uloop.timer(ms, fn);
		return { cancel: () => t.cancel() };
	},
	now: () => time(),
	random: random,
	log: log,
});

bus.listener('wwand.ims.call', (type, data) => core.on_call_event(data));

uloop.handle(sock.fileno(), () => {
	let from = {};
	let buf;

	while ((buf = sock.recv(65535, socket.MSG_DONTWAIT, from)) != null) {
		if (verbose)
			log('debug', sprintf('<- %s:%d\n%s', from.address, from.port, buf));
		core.on_packet(buf, { address: from.address, port: from.port });
		from = {};
	}
}, uloop.ULOOP_READ);

log('info', sprintf('sipd: listening on %s:%d for %s, modem %s, codecs %s',
	listen_ip, port, join(',', keys(users)), modem, join(',', codecs)));
uloop.run();
