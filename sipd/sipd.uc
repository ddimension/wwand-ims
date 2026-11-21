#!/usr/bin/env ucode
// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// sipd: SIP for LAN phones or a PBX trunk, bridged to IMS calls. Two
// backends (config ims_modem, option backend):
//   'ue'  the router's own IMS UE (sipd/line_ue.uc): it registers over the
//         IMS PDN wwand carries (option ims_iface, option vrf), the SDP and
//         the RTP are relayed 1:1 (sipd/relay.uc), AMR-WB/AMR end to end;
//   'qmi' the modem's IMS through the wwand ims plugin (its ops over ubus,
//         its wwand.ims.call events), the default.
// Reads /etc/config/wwand_ims (sip_gateway, extension, ims_modem).
//
//   ucode -L /usr/share/wwand-ims /usr/share/wwand-ims/sipd.uc

'use strict';

import * as uloop from 'uloop';
import * as ubus from 'ubus';
import * as uci from 'uci';
import * as socket from 'socket';
import * as fs from 'fs';
import * as CALL from 'ue_call';
import * as LINE from 'sipd_line_ue';
import * as RELAY from 'sipd_relay';
import * as PROFILE from 'sipd_profile';
import * as logmod from 'wwand.log';
import * as sms_pdu from 'wwand.sms_pdu';

let CORE = require('sipd_core');

// Log to /dev/log through wwand's own logging seam (wwand_io), so each line
// carries its real severity and the 'wwand-ims-sipd' ident instead of landing
// at procd's fixed daemon.err under the generic 'ucode' program name. Falls
// back to stderr when wwand_io or /dev/log is unavailable (host tests). The
// `log` callback is handed down to line_ue/core/relay, so this fixes the
// "ue: ..." lines too.
let verbose = (ARGV[0] == '-v');
let _io = null;
try { _io = require('wwand_io'); } catch (e) { _io = null; }
logmod.open(_io, { ident: 'wwand-ims-sipd', level: verbose ? 'debug' : 'info' });
let log = (lv, msg) => logmod.log(lv, '%s', msg);

// ---- configuration ----------------------------------------------------------------

let cur = uci.cursor();
let gw = null, users = {}, modem = null;

let im = null;
cur.foreach('wwand_ims', 'sip_gateway', (s) => { gw ??= s; });
cur.foreach('wwand_ims', 'ims_modem', (s) => { im ??= s; });
// the operator profiles; the one for the SIM is picked at each registration
let profiles = [];
cur.foreach('wwand_ims', 'ims_profile', (s) => { push(profiles, s); });
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

// option sip_trace '<file>': every SIP message, LAN and IMS side, in full
// into that file (the IMS side is ESP, no packet capture shows it; syslog
// would cut an INVITE short). For debugging only: it holds identities.
let trace_fd = gw.sip_trace ? fs.open(gw.sip_trace, 'a', 0o600) : null;
// an existing file keeps its mode: root only all the same
if (trace_fd)
	fs.chmod?.(gw.sip_trace, 0o600);
if (gw.sip_trace && !trace_fd)
	log('warn', sprintf('sipd: cannot open sip_trace %s: %s', gw.sip_trace, fs.error()));
let trace = trace_fd ? (dir, peer, text) => {
	let t = clock(), lt = localtime(t[0]);
	trace_fd.write(sprintf('==== %04d-%02d-%02d %02d:%02d:%02d.%03d %s %s\n%s\n',
		lt.year, lt.mon, lt.mday, lt.hour, lt.min, lt.sec, int(t[1] / 1000000), dir, peer, text));
	trace_fd.flush();
} : null;
let codecs = filter(gw.codec ?? [ 'pcma', 'pcmu' ], (c) => c in { pcma: 1, pcmu: 1, g722: 1 });
modem ??= im?.modem ?? 'wwmodem0';
let backend = im?.backend ?? 'qmi';

// ---- transport ----------------------------------------------------------------------

let sock = socket.create(socket.AF_INET, socket.SOCK_DGRAM);
if (!sock || !sock.bind({ address: listen_ip, port: port })) {
	log('error', sprintf('sipd: cannot bind %s:%d (%s)', listen_ip, port, socket.error()));
	exit(1);
}

// TCP: one listener; each accepted connection keeps its socket and a byte
// buffer. A message ends after its headers plus Content-Length bytes (RFC
// 3261 18.3, mandatory on stream transports). A request to a phone that
// registered over TCP goes over that connection (the phone does not listen
// for new ones behind its own firewall).
let tcp = socket.create(socket.AF_INET, socket.SOCK_STREAM);
tcp?.setopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, true);
if (!tcp || !tcp.bind({ address: listen_ip, port: port }) || !tcp.listen(16)) {
	log('error', sprintf('sipd: cannot listen on TCP %s:%d (%s)', listen_ip, port, socket.error()));
	exit(1);
}
let conns = {}, next_conn = 0;

let send = (text, addr) => {
	trace?.('lan ->', sprintf('%s %s:%d', addr.transport ?? 'UDP', addr.address, addr.port), text);
	if (verbose)
		log('debug', sprintf('-> %s %s:%d\n%s', addr.transport ?? 'UDP', addr.address, addr.port, text));
	if (addr.transport == 'TCP') {
		let c = conns[sprintf('%d', addr.conn)];

		if (!c)
			return log('warn', sprintf('sipd: TCP connection to %s:%d is gone', addr.address, addr.port));
		return c.sock.send(text);
	}
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

// the phones' / PBX's registrations survive a restart of sipd (they are kept
// until their expiry; a PBX would else be unreachable until it registers again)
const BINDINGS = '/var/run/wwand-ims-sipd.bindings';
// the last calls (sipd_core HISTORY). RAM by default; option call_history on
// sip_gateway puts it elsewhere (on flash it is one write per call)
let HISTORY_FILE = gw.call_history ?? '/var/run/wwand-ims-sipd.calls';
let started = time();

// the UE line's state for `wwandctl status`: the 'ue' backend broadcasts it on
// the ubus event `wwand.ims.ue` (the ims plugin listens and turns the latest
// into a status row). A heartbeat keeps the plugin's view fresh; the plugin
// ages a report out on its own if the heartbeats stop.
const UE_EVENT = 'wwand.ims.ue';

// ---- the UE line (backend 'ue') -------------------------------------------------------------

let core = null, line = null, relay = null;

if (backend == 'ue') {
	let xfrm = null;
	// the NETLINK_XFRM binding lives in wwand's native module (wwand_io.so,
	// sub-namespace xfrm); it is on ucode's default /usr/lib/ucode path.
	try { xfrm = require('wwand_io').xfrm; } catch (e) { xfrm = null; }
	if (!xfrm) {
		log('error', 'sipd: backend ue needs wwand_io.xfrm (install/upgrade wwand)');
		exit(1);
	}
	relay = RELAY.create({ socket: socket, uloop: uloop, lan_ip: listen_ip,
		ims_ip: () => line?.ue_addr(), vrf: im.vrf, log: log,
		base: +(im.rtp_base ?? 40000), span: +(im.rtp_span ?? 200),
		rtp_timeout: () => line?.profile()?.rtp_timeout,
		rtcp_timeout: () => line?.profile()?.rtcp_timeout });
	line = LINE.create({ bus: bus, uloop: uloop, socket: socket, xfrm: xfrm,
		modem: modem, iface: im.ims_iface ?? 'wwims', vrf: im.vrf,
		// the APN to find the IMS PDN's line in AT+CGCONTRDP: config, else the
		// interface's own option apn
		apn: im.ims_apn ?? cur.get('network', im.ims_iface ?? 'wwims', 'apn'),
		mnc_len: im.mnc_len ? +im.mnc_len : null,
		pcscf: im.pcscf, relay: relay, log: log, trace: trace,
		// SMS over IP (ims_modem option smsip): what arrives is written into
		// the modem's own store (option sms_storage, ME or SM), as if the
		// modem had received it, and managed there like any SMS
		smsip: (im.smsip == '1' || im.smsip == 'on' || im.smsip == 'true'),
		encode_submit: sms_pdu.encode_submit,
		deliver: (pdu, cb) => {
			let r = bus.call('wwand', 'modem_sms_deliver', { modem: modem, storage: (im.sms_storage == 'SM') ? 'SM' : 'ME',
				pdu: pdu, via: 'ims' });
			if (r?.ok)
				return cb(null);
			cb(r ?? { error: 'ubus', detail: ubus.error() });
		},
		profile_for: (sim) => PROFILE.ue_opts(PROFILE.select(profiles, im.profile, sim)),
		on_incoming: (inc) => core?.on_line_incoming(inc) });
}

// ---- the plugin ---------------------------------------------------------------------------

let ims = (op, args, cb) => {
	bus.defer('wwand', 'modem_plugin', { modem: modem, plugin: 'ims', op: op, args: args }, (rc, res) => {
		if (rc != 0 || res?.ok === false)
			return cb({ error: res?.error ?? rc }, null);
		cb(null, res);
	});
};

core = CORE.create({
	cfg: { ip: listen_ip, port: port, realm: gw.realm ?? 'wwand-ims', modem: modem,
	       codecs: codecs, users: users },
	send: send,
	ims: ims,
	media: media,
	line: line, relay: relay,
	history_changed: (h) => {
		let f = fs.open(HISTORY_FILE + '.new', 'w');
		if (f) {
			f.write(sprintf('%J', h));
			f.close();
			fs.rename(HISTORY_FILE + '.new', HISTORY_FILE);
		}
	},
	bindings_changed: (b) => {
		let f = fs.open(BINDINGS + '.new', 'w');
		if (f) {
			f.write(sprintf('%J', b));
			f.close();
			fs.rename(BINDINGS + '.new', BINDINGS);
		}
	},
	sdp: { relay: CALL.sdp_relay, media: CALL.sdp_media },
	timer: (ms, fn) => {
		let t = uloop.timer(ms, fn);
		return { cancel: () => t.cancel() };
	},
	now: () => time(),
	random: random,
	log: log,
});

let saved = null;
try { saved = json(fs.readfile(BINDINGS) ?? 'null'); } catch (e) { saved = null; }
let restored = core.restore(saved);
if (restored)
	log('info', sprintf('sipd: %d registration(s) restored from %s', restored, BINDINGS));
try { saved = json(fs.readfile(HISTORY_FILE) ?? 'null'); } catch (e) { saved = null; }
core.restore_history(saved);

// ---- ubus: what a status page shows (luci-app-wwand-ims) ---------------------------------
// Every method takes ubus_rpc_session, as LuCI sends it (wwand's rule).
let ubus_obj = bus.publish('wwand-ims', {
	status: {
		args: { ubus_rpc_session: '' },
		call: (req) => ({
			backend: backend, modem: modem, listen: listen_ip, port: port, started: started, now: time(),
			ue: line ? line.status() : null,
			extensions: core.extensions(),
			call: core.current(),
		}),
	},
	calls: {
		args: { ubus_rpc_session: '' },
		call: (req) => ({ now: time(), calls: core.history() }),
	},
	// an SMS over IMS: wwand's modem_sms_send hands it here (the ims plugin's
	// sms_send hook) while option smsip is on; the reply is wwand's shape
	sms_send: {
		args: { modem: '', number: '', text: '', ubus_rpc_session: '' },
		call: (req) => {
			if (!line)
				return { ok: false, error: 'smsip_off', detail: 'backend qmi: the modem sends SMS itself' };
			if (req.args.modem && req.args.modem != modem)
				return { ok: false, error: 'no_such_modem' };
			req.defer();
			line.sms_send(req.args.number, req.args.text, (err, res) =>
				req.reply(err ? { ok: false, ...err } : { ok: true, ...(res ?? {}) }));
		},
	},
});
if (!ubus_obj)
	log('warn', sprintf('sipd: cannot publish ubus object wwand-ims: %s', ubus.error()));

// publish the UE line's state so `wwandctl status` (the ims plugin) can show it
let emit_ue_status = (state) => {
	if (!line)
		return;
	let s = (state != null) ? { state: state } : line.status();
	try { bus.event(UE_EVENT, { modem: modem, backend: backend, updated: time(), ...s }); }
	catch (e) {}
};

if (line) {
	let ue_tick;
	ue_tick = () => { emit_ue_status(); uloop.timer(5000, ue_tick); };
	line.start();
	ue_tick();
}
else
	bus.listener('wwand.ims.call', (type, data) => core.on_call_event(data));

// SIGTERM / SIGINT: the UE de-REGISTERs and takes its SAs down first
let stopping = false;
let stop = () => {
	if (stopping)
		return;
	stopping = true;
	log('info', 'sipd: stopping');
	emit_ue_status('down');	// let the plugin drop the row at once, not on age-out
	if (!line)
		return uloop.end();
	uloop.timer(5000, () => uloop.end());
	line.stop(() => uloop.end());
};
signal('SIGTERM', stop);
signal('SIGINT', stop);

uloop.handle(sock.fileno(), () => {
	let from = {};
	let buf;

	while ((buf = sock.recv(65535, socket.MSG_DONTWAIT, from)) != null) {
		trace?.('lan <-', sprintf('UDP %s:%d', from.address, from.port), buf);
		if (verbose)
			log('debug', sprintf('<- %s:%d\n%s', from.address, from.port, buf));
		core.on_packet(buf, { address: from.address, port: from.port, transport: 'UDP' });
		from = {};
	}
}, uloop.ULOOP_READ);

let tcp_frames = (c) => {
	for (;;) {
		// RFC 5626 4.4.1 keepalive: CRLFCRLF ping, CRLF pong
		if (substr(c.buf, 0, 4) == '\r\n\r\n') {
			c.buf = substr(c.buf, 4);
			c.sock.send('\r\n');
			continue;
		}
		c.buf = replace(c.buf, /^(\r\n)+/, '');

		let he = index(c.buf, '\r\n\r\n');
		if (he < 0)
			return;

		let m = match(substr(c.buf, 0, he), /(^|\r\n)([Cc]ontent-[Ll]ength|l)[ \t]*:[ \t]*([0-9]+)/);
		let len = m ? +m[3] : 0;

		if (length(c.buf) < he + 4 + len)
			return;

		let msg = substr(c.buf, 0, he + 4 + len);
		c.buf = substr(c.buf, he + 4 + len);
		trace?.('lan <-', sprintf('TCP %s:%d', c.addr.address, c.addr.port), msg);
		if (verbose)
			log('debug', sprintf('<- TCP %s:%d\n%s', c.addr.address, c.addr.port, msg));
		core.on_packet(msg, { ...c.addr });
	}
};

uloop.handle(tcp.fileno(), () => {
	let peer = {};
	let cs = tcp.accept(peer);

	if (!cs)
		return;

	let id = ++next_conn;
	let c = { sock: cs, buf: '', addr: { address: peer.address, port: peer.port, transport: 'TCP', conn: id } };

	conns[sprintf('%d', id)] = c;
	log('info', sprintf('sipd: TCP connection %d from %s:%d', id, peer.address, peer.port));

	c.h = uloop.handle(cs.fileno(), () => {
		let d = cs.recv(65535, socket.MSG_DONTWAIT);

		if (d == null && socket.error(true) == 11)	// EAGAIN
			return;
		if (!d) {
			log('info', sprintf('sipd: TCP connection %d closed', id));
			c.h.delete();
			cs.close();
			delete conns[sprintf('%d', id)];
			return;
		}
		c.buf += d;
		if (length(c.buf) > 65536) {
			log('warn', sprintf('sipd: TCP connection %d: no message end in 64 kB, closing', id));
			c.buf = '';
			cs.close();
		}
		else
			tcp_frames(c);
	}, uloop.ULOOP_READ);
}, uloop.ULOOP_READ);

log('info', sprintf('sipd: listening on UDP and TCP %s:%d for %s, modem %s, backend %s%s',
	listen_ip, port, join(',', keys(users)), modem, backend,
	line ? sprintf(' (IMS PDN %s, VRF %s)', im.ims_iface ?? 'wwims', im.vrf ?? '-') : ', codecs ' + join(',', codecs)));
uloop.run();
