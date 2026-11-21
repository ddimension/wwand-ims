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
import * as LINES from 'sipd_lines';
import * as IW from 'ims_iwlan';
import * as KC from 'ue_kcrypto';
import * as READER from 'ue_reader';
import { DEFAULT_ALGS, DEFAULT_EALGS } from 'ue_secagree';
import * as logmod from 'wwand.log';
import * as sms_pdu from 'wwand.sms_pdu';

let CORE = require('sipd_core');

// Log to /dev/log through wwand's own logging seam (wwand_io), so each line
// carries its real severity and the 'wwand-ims-sipd' ident instead of landing
// at procd's fixed daemon.err under the generic 'ucode' program name. Falls
// back to stderr when wwand_io or /dev/log is unavailable (host tests). The
// `log` callback is handed down to line_ue/core/relay, so this fixes the
// "ue: ..." lines too.
// sipd [-v] [--line <ims_modem section or modem>]: one instance per IMS
// line (files/wwand-ims-sipd.init starts one per ims_modem section)
let verbose = false, line_want = null;
for (let i = 0; i < length(ARGV); i++) {
	if (ARGV[i] == '-v')
		verbose = true;
	else if (ARGV[i] == '--line')
		line_want = ARGV[++i];
}
let _io = null;
try { _io = require('wwand_io'); } catch (e) { _io = null; }
logmod.open(_io, { ident: 'wwand-ims-sipd', level: verbose ? 'debug' : 'info' });
let log = (lv, msg) => logmod.log(lv, '%s', msg);

// ---- configuration ----------------------------------------------------------------

let cur = uci.cursor();
let gw = null, users = {}, modem = null;

cur.foreach('wwand_ims', 'sip_gateway', (s) => { gw ??= s; });
// the IMS lines (sipd_lines.uc): this instance runs the one --line names, or
// the first; what it uses comes from its position among them
let lines_cfg = [], sims = [], exts = [];
cur.foreach('wwand_ims', 'ims_modem', (s) => { push(lines_cfg, s); });
cur.foreach('wwand_ims', 'ims_sim', (s) => { push(sims, s); });
cur.foreach('wwand_ims', 'extension', (s) => { push(exts, s); });
let LN = LINES.pick(lines_cfg, line_want);
if (line_want != null && !LN) {
	log('error', sprintf('sipd: no ims_modem section or modem %s in /etc/config/wwand_ims', line_want));
	exit(1);
}
let RES = LINES.resources(LN?.im, LN?.index ?? 0, gw);
if (RES.index > 0)
	logmod.open(_io, { ident: sprintf('wwand-ims-sipd.%s', LN.name), level: verbose ? 'debug' : 'info' });
// the operator profiles; the one for the SIM is picked at each registration
let profiles = [];
cur.foreach('wwand_ims', 'ims_profile', (s) => { push(profiles, s); });
// the phones / PBX of this line (option line; without one: the first line)
for (let s in LINES.extensions(exts, LN?.name, RES.index)) {
	if (s.username && s.password) {
		users[s.username] = { password: s.password };
		modem ??= s.modem;
	}
}

if (!gw || !length(keys(users))) {
	log('error', sprintf('sipd: no sip_gateway or no extension with username and password for line %s in /etc/config/wwand_ims',
		LN?.name ?? '-'));
	exit(1);
}

uloop.init();
let bus = ubus.connect();

if (!bus) {
	log('error', 'sipd: no ubus');
	exit(1);
}

// a line with a card but no modem (ims_modem option card: a reader spec of
// wwand-rsim's rsim-card, ue/reader.uc): VoWiFi only, the identity read from
// the card once it answers
let CARD = LN?.im?.card;
if (CARD) {
	modem = LN.im.modem ?? LN.name;
	RES.objects = (RES.index == 0) ? [ 'wwand-ims', sprintf('wwand-ims.%s', modem) ] : [ sprintf('wwand-ims.%s', modem) ];
}

// the line's settings with its SIM's (ims_sim, by ICCID) over them; a card
// that changes under the line (slot switch, eSIM profile, remote SIM) ends
// this instance so procd starts it anew for the new card
modem = LN?.im?.modem ?? modem ?? 'wwmodem0';
let sim_iccid = CARD ? null : bus.call('wwand', 'status', {})?.modems?.[modem]?.iccid;
let SIM = LINES.sim_for(sims, sim_iccid);
let im = LN ? LINES.effective(LN.im, SIM) : null;
if (SIM)
	log('info', sprintf('sipd: line %s, SIM %s: overrides from ims_sim %s', LN?.name ?? '-',
		substr(sim_iccid ?? '', 0, 8) + '…', SIM['.name']));

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

let port = RES.sip_port;

// option sip_trace '<file>': every SIP message, LAN and IMS side, in full
// into that file (the IMS side is ESP, no packet capture shows it; syslog
// would cut an INVITE short). For debugging only: it holds identities.
let trace_fd = RES.sip_trace ? fs.open(RES.sip_trace, 'a', 0o600) : null;
// an existing file keeps its mode: root only all the same
if (trace_fd)
	fs.chmod?.(RES.sip_trace, 0o600);
if (RES.sip_trace && !trace_fd)
	log('warn', sprintf('sipd: cannot open sip_trace %s: %s', RES.sip_trace, fs.error()));
let trace = trace_fd ? (dir, peer, text) => {
	let t = clock(), lt = localtime(t[0]);
	trace_fd.write(sprintf('==== %04d-%02d-%02d %02d:%02d:%02d.%03d %s %s\n%s\n',
		lt.year, lt.mon, lt.mday, lt.hour, lt.min, lt.sec, int(t[1] / 1000000), dir, peer, text));
	trace_fd.flush();
} : null;
let codecs = filter(gw.codec ?? [ 'pcma', 'pcmu' ], (c) => c in { pcma: 1, pcmu: 1, g722: 1 });
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
const BINDINGS = RES.bindings;
// the last calls (sipd_core HISTORY). RAM by default; option call_history on
// sip_gateway puts it elsewhere (on flash it is one write per call)
let HISTORY_FILE = RES.history;
let started = time();

// the UE line's state for `wwandctl status`: the 'ue' backend broadcasts it on
// the ubus event `wwand.ims.ue` (the ims plugin listens and turns the latest
// into a status row). A heartbeat keeps the plugin's view fresh; the plugin
// ages a report out on its own if the heartbeats stop.
const UE_EVENT = 'wwand.ims.ue';

// ---- the UE line (backend 'ue') -------------------------------------------------------------

let core = null, line = null, relay = null, vowifi = null;
// the VoWiFi tunnel's netifd interfaces, created at run time: { ensure, remove }
let vowifi_net = null;
// the kernel crypto check (ue/kcrypto.uc), backend ue
let kc_opts = null;
// the orderly end (SIGTERM, another SIM): declared here, the tick calls it
let stop = null;

// ims_modem option access 'vowifi': the UE's IMS goes through an IKEv2
// tunnel to the operator's ePDG instead of the IMS PDN (wwand-ims-vowifi,
// its modules loaded only then)
let access = CARD ? 'vowifi' : (im?.access ?? 'pdn');
if (CARD && backend != 'ue') {
	log('error', sprintf('sipd: line %s: a card without a modem needs backend ue', LN?.name ?? '-'));
	exit(1);
}

// the card reader (ims_modem option card): started below; its identity
// (ICCID, IMSI, MNC length) and the card for the AKA
let reader = null, card_info = null, card_instance = null;
if (CARD) {
	// the helper gone (reader unplugged, SSH link down): this instance ends,
	// procd starts it again, the card powered up and read anew
	reader = READER.create({ spec: CARD, log: log, ssh_key: LN.im.card_ssh_key, on_gone: () => stop?.(),
		spawn: (argv, on_line, on_exit) => READER.spawn_lines(_io, uloop, argv, on_line, on_exit) });
	// +sip.instance: a UUID URN stable for this line (TS 24.229 5.1.1.2.1
	// allows one where there is no IMEI), from the config or derived
	card_instance = LN.im.instance ?? READER.instance_urn(sprintf('wwand-ims/%s/%s', LN.name, CARD), require('sipd_sip').md5);
}
// the VoWiFi tunnel's controller, made once the SIM's identity is known
let make_vowifi = null;

if (backend == 'ue' && access == 'vowifi') {
	let VICI = null, CTL = null;
	try {
		let v = require('vowifi_lazy');
		VICI = v.VICI;
		CTL = v.CTL;
	}
	catch (e) { VICI = null; }
	if (!VICI || !CTL) {
		log('error', 'sipd: access vowifi needs the package wwand-ims-vowifi');
		exit(1);
	}
	// the tunnel for the SIM `m` ({ imsi, iccid, mnc_len? }): from the modem
	// at once, from a card reader once it is read
	make_vowifi = (m) => {
	// what the operator's ePDG wants: the SIM's ims_profile (vowifi_*), and
	// ims_modem's own option over it
	let p = PROFILE.select(profiles, im.profile, { imsi: m.imsi, iccid: m.iccid }) ?? {};
	let opt = (name) => im[name] ?? p[name];
	let lst = (name) => length(PROFILE.list_of(opt(name))) ? PROFILE.list_of(opt(name)) : null;
	let num_opt = (name) => (opt(name) != null && match(sprintf('%s', opt(name)), /^[0-9]+$/)) ? +opt(name) : null;
	// charon restarted or crashed: the controller loads the tunnel again
	let vici = VICI.create({ socket: socket, uloop: uloop, log: log, on_close: (why) => vowifi?.vici_closed(why) });
	// the netifd interface (proto wwandvowifi) that takes the tunnel's IP
	// configuration: renew it whenever the tunnel comes up
	let vw_iface = RES.vowifi_iface;
	vowifi = CTL.create({ vici: vici, uloop: uloop, log: log,
		run: (argv) => system(argv),
		// deferred: the proto handler asks sipd (vowifi_addr) back right away
		notify: () => bus.defer(sprintf('network.interface.%s', vw_iface), 'renew', {},
			(rc) => rc ? log('warn', sprintf('vowifi: netifd renew %s: %s', vw_iface, ubus.error() ?? rc)) : null),
		imsi: m.imsi, mnc_len: im.mnc_len ? +im.mnc_len : (m.mnc_len ?? LINE.home_mnc_len(m)),
		if_id: RES.vowifi_if_id, dev: RES.vowifi_dev, conn: RES.vowifi_conn,
		epdg: im.epdg ?? p.vowifi_epdg, apn: opt('vowifi_apn'),
		proposals: lst('vowifi_proposals'), esp_proposals: lst('vowifi_esp_proposals'),
		remote_auth: opt('vowifi_remote_auth'), pani: opt('vowifi_pani'),
		rekey_s: num_opt('vowifi_rekey_s'), esp_rekey_s: num_opt('vowifi_esp_rekey_s'), dpd_s: num_opt('vowifi_dpd_s'),
		// charon's detail for the tunnel's setup, 0-4 (2: every IKE step)
		loglevel: im.vowifi_loglevel != null ? +im.vowifi_loglevel : 1 });
	// the UE registers once netifd has the tunnel's address and route
	// (its ifup / ifupdate of the interface), not at its next retry and not
	// before: an earlier REGISTER finds no route ("Network unreachable")
	vowifi.iface = vw_iface;

	// its two netifd interfaces, created at run time (network add_dynamic)
	// with the XFRM interface in the IMS firewall zone, gone again when sipd
	// stops; netifd forgets dynamic interfaces on a restart, so ensure()
	// runs again on sipd's tick. A section of that name in
	// /etc/config/network (an older `wwandctl ims setup` wrote them) is used
	// as it is.
	let specs = CTL.net_specs({ dev: RES.vowifi_dev, iface: vw_iface,
		if_id: RES.vowifi_if_id, mtu: im.vowifi_mtu ?? 1280, table: RES.vowifi_table,
		zone: RES.vowifi_zone });
	let is_static = (name) => cur.get('network', name) == 'interface';
	vowifi_net = {
		ensure: () => {
			for (let s in specs) {
				if (is_static(s.name) || bus.call(sprintf('network.interface.%s', s.name), 'status', {}) != null)
					continue;
				// add_dynamic answers without data: null is success as well,
				// ubus.error() tells
				bus.call('network', 'add_dynamic', s);
				let e = ubus.error();
				if (e != null && !match(e, /^Success/i))
					log('warn', sprintf('vowifi: netifd add_dynamic %s: %s', s.name, e));
				else
					log('info', sprintf('vowifi: netifd interface %s (%s) created', s.name, s.proto));
			}
		},
		remove: () => {
			for (let i = length(specs) - 1; i >= 0; i--)
				if (!is_static(specs[i].name))
					bus.call(sprintf('network.interface.%s', specs[i].name), 'remove', {});
		},
	};
	};
	if (!CARD) {
		let st = bus.call('wwand', 'status', {});
		let m = st?.modems?.[modem ?? im.modem];
		if (!m?.imsi) {
			// procd starts sipd again; by then the modem has read its card
			log('warn', sprintf('sipd: vowifi: modem %s has no IMSI yet', modem ?? im.modem ?? '?'));
			exit(1);
		}
		make_vowifi(m);
	}
}

if (backend == 'ue') {
	let xfrm = null;
	// the NETLINK_XFRM binding lives in wwand's native module (wwand_io.so,
	// sub-namespace xfrm); it is on ucode's default /usr/lib/ucode path.
	try { xfrm = require('wwand_io').xfrm; } catch (e) { xfrm = null; }
	if (!xfrm) {
		log('error', 'sipd: backend ue needs wwand_io.xfrm (install/upgrade wwand)');
		exit(1);
	}
	// can the kernel do the encrypted sec-agree SAs we offer? A crypto driver
	// that cannot take their keys (MT7621's EIP-93) is unloaded now, before
	// the VoWiFi tunnel uses it (ue/kcrypto.uc)
	let combos = [];
	for (let a in DEFAULT_ALGS)
		for (let e in DEFAULT_EALGS)
			push(combos, [ a, e ]);
	kc_opts = { xfrm: xfrm, exists: (p) => fs.stat(p) != null, run: (argv) => system(argv), log: log, combos: combos };
	// a module still in use is tried again for a while: the kernel frees the
	// SAs of a tunnel just taken down, and their crypto, only later (xfrm
	// state GC); a running VoWiFi tunnel holds the module through its own
	// cbc(aes), so the tunnel starts only after this
	let kc_settle = (cb) => {
		let n = 0, quiet = { ...kc_opts, log: (l, m) => null }, step;
		step = () => {
			let r = KC.check(n == 0 ? kc_opts : quiet);
			if (r.busy && ++n < 15)
				return uloop.timer(1000, step);
			if (r.busy)
				log('warn', sprintf('ue: %s still in use after %d s; encrypted sec-agree stays refused', r.busy, n));
			else if (n > 0 && r.unloaded)
				log('warn', sprintf('ue: kernel module %s unloaded after %d s', r.unloaded, n));
			cb?.();
		};
		step();
	};
	kc_opts.settle = kc_settle;
	// ... and again when a registration finds it refused anyway: the VoWiFi
	// tunnel is taken down for it (once a minute at most)
	let kc_last = 0;
	kc_opts.refused = () => {
		if (time() - kc_last < 60)
			return;
		kc_last = time();
		let r = KC.check(kc_opts);
		if (r.busy && vowifi) {
			log('warn', sprintf('ue: taking the VoWiFi tunnel down to unload %s', r.busy));
			vowifi.stop(() => kc_settle(() => vowifi.start(null)));
		}
		else if (r.busy)
			kc_settle(null);
	};
	relay = RELAY.create({ socket: socket, uloop: uloop, lan_ip: listen_ip,
		ims_ip: () => line?.ue_addr(), vrf: () => vowifi ? vowifi.access()?.bind : RES.vrf, log: log,
		base: RES.rtp_base, span: RES.rtp_span,
		rtp_timeout: () => line?.profile()?.rtp_timeout,
		rtcp_timeout: () => line?.profile()?.rtcp_timeout });
	line = LINE.create({ bus: bus, uloop: uloop, socket: socket, xfrm: xfrm,
		on_xfrm_refused: (err) => kc_opts.refused(),
		modem: modem, iface: RES.ims_iface, vrf: RES.vrf, reqid_base: RES.reqid_base,
		// the APN to find the IMS PDN's line in AT+CGCONTRDP: config, else the
		// interface's own option apn
		apn: im.ims_apn ?? cur.get('network', RES.ims_iface, 'apn'),
		mnc_len: im.mnc_len ? +im.mnc_len : null,
		pcscf: im.pcscf, relay: relay, log: log, trace: trace,
		access: (vowifi || CARD) ? (() => vowifi?.access()) : null,
		// a card without a modem: the identity read from it, the AKA on it;
		// the IMEI is not there — +sip.instance a UUID URN of the line's own
		sim_info: CARD ? (() => card_info ? { ...card_info, instance: card_instance } : null) : null,
		card: reader ? reader.card() : null,
		// SMS over IP (ims_modem option smsip): what arrives is written into
		// the modem's own store (option sms_storage, ME or SM), as if the
		// modem had received it, and managed there like any SMS
		smsip: !CARD && (im.smsip == '1' || im.smsip == 'on' || im.smsip == 'true'),
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
	       codecs: codecs, users: users, redirect_info: gw.redirect_info != '0' },
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
// one object per line, wwand-ims.<modem>; the first line also as wwand-ims
let ubus_methods = {
	status: {
		args: { ubus_rpc_session: '' },
		call: (req) => ({
			line: LN?.name, backend: backend, modem: modem, listen: listen_ip, port: port, started: started, now: time(),
			sim: SIM ? SIM['.name'] : null,
			ue: line ? line.status() : null,
			vowifi: vowifi ? vowifi.status() : null,
			extensions: core.extensions(),
			call: core.current(),
		}),
	},
	calls: {
		args: { ubus_rpc_session: '' },
		call: (req) => ({ now: time(), calls: core.history() }),
	},
	// the VoWiFi tunnel's IP configuration, for its netifd proto handler
	// (files/vowifi-proto.sh, proto wwandvowifi): up, the inner addresses
	vowifi_addr: {
		args: { ubus_rpc_session: '' },
		call: (req) => {
			let a = vowifi?.access();
			return a ? { up: 1, v4: a.v4, v6: a.v6, dev: vowifi.status().dev } : { up: 0 };
		},
	},

	// a new operator profile from what is in use now (LuCI: "clone from
	// current settings"): the modem's carrier configuration and what the
	// network gave the UE, as `config ims_profile` options (sipd/profile.uc
	// snapshot). Nothing is written: the caller saves it under a name.
	profile_snapshot: {
		args: { ubus_rpc_session: '' },
		call: (req) => {
			let st = bus.call('wwand', 'status', {}) ?? {};
			let m = st.modems?.[modem] ?? {};
			let ims_apn = null;
			for (let p in bus.call('wwand', 'modem_profiles', { modem: modem })?.profiles ?? [])
				if (!match(lc(p.apn ?? ''), /^sos/) && (p.imcn == 1 || (!ims_apn && match(lc(p.apn ?? ''), /^ims/))))
					ims_apn = p;
			let mbn = null;
			let cc = bus.call('wwand', 'modem_carrier_config', { modem: modem, op: 'get' });
			if (cc?.active)
				for (let c in bus.call('wwand', 'modem_carrier_config', { modem: modem, op: 'list' })?.configs ?? [])
					if (c.id == cc.active)
						mbn = c.description ?? c.name;
			let diag = bus.call('wwand', 'modem_plugin', { modem: modem, plugin: 'ims', op: 'diag', args: {} });
			let csca = bus.call('wwand', 'modem_at', { modem: modem, command: 'AT+CSCA?', timeout: 3000 });
			// the VoWiFi settings of the carrier config (its iwlan_s2b_config.xml:
			// over AT+QNVFR, else DIAG)
			let iw = IW.read((method, args) => bus.call('wwand', method, args), modem, {});
			let vowifi = IW.options(IW.parse(iw.xml));
			let lt = localtime();
			let snap = PROFILE.snapshot({ imsi: m.imsi, plmn: m.registration?.plmn, mbn: mbn, ims_apn: ims_apn, vowifi: vowifi,
				selection: diag?.selection, ue: line?.status(), prof: line?.profile(),
				smsc: LINE.smsc_from_csca(csca?.response),
				date: sprintf('%04d-%02d-%02d', lt.year, lt.mon, lt.mday) });
			return { ok: true, ...snap, sources: { mbn: mbn != null, ims_profile: ims_apn != null,
				vowifi: iw.xml != null ? iw.via : null,
				selection: diag?.selection != null, registered: line?.status()?.state == 'registered' } };
		},
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
	// the line's card without a modem, for strongSwan's ext-aka (vowifi/
	// card.uc): the same shape as wwand's modem_apdu; imsi names the card
	// meant, another line's answers other_card
	card_apdu: {
		args: { imsi: '', op: '', aid: '', channel: 0, apdu: '', ubus_rpc_session: '' },
		call: (req) => {
			if (!reader || !card_info)
				return { ok: false, error: 'no_card' };
			if (req.args.imsi && req.args.imsi != card_info.imsi)
				return { ok: false, error: 'other_card' };
			req.defer();
			reader.apdu(req.args, (err, res) =>
				req.reply(err ? { ok: false, ...(type(err) == 'object' ? err : { error: 'card', detail: err }) } : { ok: true, ...(res ?? {}) }));
		},
	},
};
let ubus_objs = [];
for (let name in RES.objects) {
	let o = bus.publish(name, ubus_methods);
	if (o)
		push(ubus_objs, o);
	else
		log('warn', sprintf('sipd: cannot publish ubus object %s: %s', name, ubus.error()));
}

// publish the UE line's state so `wwandctl status` (the ims plugin) can show it
let emit_ue_status = (state) => {
	if (!line)
		return;
	let s = (state != null) ? { state: state } : line.status();
	// how the UE reaches the IMS: VoWiFi (the ePDG tunnel) or VoLTE (the
	// modem's IMS PDN)
	s.access = vowifi ? 'vowifi' : 'volte';
	// the VoWiFi tunnel too (wwandctl status shows it in a row of its own)
	if (vowifi) {
		let v = vowifi.status();
		s.vowifi = { state: v.state, epdg: v.epdg, v4: v.v4, v6: v.v6, pcscf: v.pcscf, error: v.error, tries: v.tries };
	}
	try { bus.event(UE_EVENT, { modem: modem, backend: backend, updated: time(), ...s }); }
	catch (e) {}
};

if (line) {
	let ue_tick;
	ue_tick = () => {
		// another card in the modem: this instance ends, procd starts it anew
		// with that card's settings (ims_sim)
		let now_iccid = CARD ? null : bus.call('wwand', 'status', {})?.modems?.[modem]?.iccid;
		if (now_iccid && now_iccid != sim_iccid) {
			log('info', sprintf('sipd: line %s: the modem has another SIM now; starting again for it', LN?.name ?? '-'));
			return stop();
		}
		emit_ue_status();
		vowifi_net?.ensure();
		uloop.timer(5000, ue_tick);
	};
	// over VoWiFi the tunnel first: the controller keeps it up from here
	// on, the line registers when netifd has its address (or retries)
	let tunnel_up = () => {
		// after the crypto check (a faulty driver module unloaded first)
		let go = () => { vowifi_net.ensure(); vowifi.start(null); };
		kc_opts ? kc_opts.settle(go) : go();
		bus.listener('network.interface', (type, data) => {
			if (data?.interface == vowifi.iface && (data?.action == 'ifup' || data?.action == 'ifupdate') && vowifi.access())
				line?.retry_now();
		});
	};
	if (vowifi)
		tunnel_up();
	// a card without a modem: the tunnel once the card is read (its IMSI
	// names the tunnel's identity, its ICCID picks the ims_sim); a card that
	// does not answer ends the instance, procd tries again
	if (CARD) {
		reader.start((err, info) => {
			if (err) {
				log('warn', sprintf('sipd: line %s: card %s: %s', LN?.name ?? '-', CARD, err.detail ?? err.error));
				return stop();
			}
			card_info = info;
			let sim = LINES.sim_for(sims, info.iccid);
			if (sim) {
				log('info', sprintf('sipd: line %s, SIM %.8s…: overrides from ims_sim %s', LN?.name ?? '-', info.iccid, sim['.name']));
				im = LINES.effective(LN.im, sim);
				SIM = sim;
			}
			log('info', sprintf('sipd: line %s: card %s, IMSI %.5s…, VoWiFi without a modem', LN?.name ?? '-', CARD, info.imsi));
			make_vowifi(info);
			tunnel_up();
		});
	}
	line.start();
	ue_tick();
}
else
	bus.listener('wwand.ims.call', (type, data) => core.on_call_event(data));

// SIGTERM / SIGINT: the UE de-REGISTERs and takes its SAs down first
let stopping = false;
stop = () => {
	if (stopping)
		return;
	stopping = true;
	log('info', 'sipd: stopping');
	emit_ue_status('down');	// let the plugin drop the row at once, not on age-out
	if (!line)
		return uloop.end();
	uloop.timer(5000, () => uloop.end());
	let done_ = () => { reader?.stop(); uloop.end(); };
	line.stop(() => vowifi ? vowifi.stop(() => { vowifi_net?.remove(); done_(); }) : done_());
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

log('info', sprintf('sipd: line %s: listening on UDP and TCP %s:%d for %s, modem %s, backend %s%s',
	LN?.name ?? '-', listen_ip, port, join(',', keys(users)), modem, backend,
	vowifi ? sprintf(' (VoWiFi to %s)', vowifi.status().epdg ?? '?')
	: (line ? sprintf(' (IMS PDN %s, VRF %s)', RES.ims_iface, RES.vrf) : ', codecs ' + join(',', codecs))));
uloop.run();
