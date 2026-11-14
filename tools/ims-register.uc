#!/usr/bin/env ucode
// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// Phase 1 spike on the router: one IMS registration by the router itself
// (ue/reg.uc), over the IMS PDN that wwand carries, the USIM through
// wwand's APDU channel, sec-agree through the wwand_ims_xfrm module.
//
//   ucode -L <dir> -L '<dir>/*.so' <dir>/ims-register.uc \
//       --modem wwmodem0 --iface wwims [--vrf ims] [--family 4|6]
//       [--pcscf ADDR] [--mnc-len 2|3] [--hold SECONDS] [--port-c 5062]
//       [--port-s 5064] [--ealg null,aes-cbc] [--aid HEX] [--slot N]
//       [--call +E164 [--ring 30] [--talk 15] [--rtp-port 40000] [--echo 1|0]] [--ue-addr ADDR]
//       [--answer SECONDS (incoming calls, with --hold as the wait)] [--preconditions 1|0|always]
//       [--mt-modes plain,rel183 (test: one per incoming call, in turn)]
//
// <dir> holds ue_aka.uc, ue_secagree.uc, ue_reg.uc, sipd_sip.uc and
// wwand_ims_xfrm.so. Every SIP message in and out is printed. After the
// 200 the registration is held for --hold seconds (default 30), then it is
// de-REGISTERed inside the SAs and the SAs are removed. With --call, the
// number is called once registered (ue/call.uc): cancelled after --ring
// seconds without an answer, hung up --talk seconds after it. A socket on
// --rtp-port counts what the far end sends and (--echo 1, the default)
// sends each frame straight back; there is no codec of our own yet.

'use strict';

import * as uloop from 'uloop';
import * as ubus from 'ubus';
import * as socket from 'socket';
import * as xfrm from 'wwand_ims_xfrm';
import * as REG from 'ue_reg';
import * as AKA from 'ue_aka';
import * as CALL from 'ue_call';

let opt = { modem: 'wwmodem0', iface: 'wwims', vrf: null, family: null, pcscf: null,
            mnc_len: null, hold: 30, port_c: 5062, port_s: 5064, ealg: null, aid: null, slot: null,
            call: null, ring: 30, talk: 15, rtp_port: 40000, ue_addr: null, echo: 1, answer: null, preconditions: 1, mt_modes: null, dup_udp: 1 };

for (let i = 0; i < length(ARGV); i++) {
	let k = replace(ARGV[i], /^--/, '');
	k = replace(k, '-', '_');
	if (!exists(opt, k)) {
		warn(sprintf('unknown option %s\n', ARGV[i]));
		exit(2);
	}
	opt[k] = ARGV[++i];
}
for (let k in [ 'hold', 'port_c', 'port_s', 'mnc_len', 'family', 'slot', 'ring', 'talk', 'rtp_port', 'echo', 'answer', 'preconditions', 'dup_udp' ])
	if (opt[k] != null && opt[k] !== 'always')
		opt[k] = +opt[k];

let say = (fmt, ...a) => print(sprintf('[%s] ', sprintf('%.3f', clock(true)[0] + clock(true)[1] / 1e9)), sprintf(fmt, ...a), '\n');

let conn = ubus.connect();
if (!conn) {
	warn('no ubus\n');
	exit(1);
}

// ---- what wwand and netifd know ---------------------------------------------------

let st = conn.call('wwand', 'status', {});
let m = st?.modems?.[opt.modem];
let ctx = st?.contexts?.[opt.iface];
if (!m || !ctx) {
	warn(sprintf('modem %s or interface %s not in wwand status\n', opt.modem, opt.iface));
	exit(1);
}

let ifst = conn.call(sprintf('network.interface.%s', opt.iface), 'status', {});
let v4 = ifst?.['ipv4-address']?.[0]?.address;
let v6 = null;
for (let a in ifst?.['ipv6-address'] ?? [])
	if (!match(a.address, /^fe80/))
		v6 = a.address;

let pcscf4 = ctx.ipv4?.pcscf ?? [];
let family = opt.family ?? ((opt.pcscf && index(opt.pcscf, ':') >= 0) ? 6 : (length(pcscf4) ? 4 : (v6 ? 6 : 4)));
let ue_addr = opt.ue_addr ?? ((family == 6) ? v6 : v4);
let pcscf = opt.pcscf ?? ((family == 4) ? pcscf4[0] : ctx.ipv6?.pcscf?.[0]);

// the cell for P-Access-Network-Info, Quectel AT+QENG (the format the
// RG650E answers): "servingcell",<state>,"LTE",<FDD|TDD>,<mcc>,<mnc>,<cellid hex>,<pci>,<earfcn>,<band>,<ul bw>,<dl bw>,<tac hex>,...
let pani = null;
let q = conn.call('wwand', 'modem_at', { modem: opt.modem, command: 'AT+QENG="servingcell"', timeout: 3000 });
let ql = q?.response?.[0] ?? '';
let mm = match(ql, /"LTE","(FDD|TDD)",([0-9]+),([0-9]+),([0-9A-Fa-f]+),[0-9]+,[0-9]+,[0-9]+,[0-9]+,[0-9]+,([0-9A-Fa-f]+),/);
if (mm)
	pani = REG.pani_eutran(+mm[2], +mm[3], length(mm[3]) == 3 ? 3 : 2, hex(mm[5]), hex(mm[4]), mm[1] == 'TDD');

let mnc_len = opt.mnc_len ?? m.registration?.plmn?.mnc_digits ?? 2;

say('modem %s imsi %s imei %s, iface %s (%s) ipv4 %s ipv6 %s', opt.modem, m.imsi, m.imei, opt.iface,
	ctx.l3_device, v4 ?? '-', v6 ?? '-');
say('family %d: UE %s, P-CSCF %s (PCO list %J), MNC length %d, PANI %s', family, ue_addr ?? '-', pcscf ?? '-',
	pcscf4, mnc_len, pani ?? '-');

if (!ue_addr || !pcscf || !m.imsi) {
	warn('no UE address, P-CSCF or IMSI\n');
	exit(1);
}

// ---- sockets: our protected client and server port, in the IMS VRF ----------------

let AF = (family == 6) ? socket.AF_INET6 : socket.AF_INET;
let socks = {};

for (let port in [ opt.port_c, opt.port_s ]) {
	let s = socket.create(AF, socket.SOCK_DGRAM);
	if (opt.vrf && !s.setopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, opt.vrf)) {
		warn(sprintf('bind to VRF %s: %s\n', opt.vrf, socket.error()));
		exit(1);
	}
	s.setopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);
	if (!s.bind({ address: ue_addr, port: port })) {
		warn(sprintf('bind %s port %d: %s\n', ue_addr, port, socket.error()));
		exit(1);
	}
	socks[sprintf('%d', port)] = s;
}

// the RTP port of the offer: nothing is sent yet, the packets are counted
let rtp = { sock: null, pkts: 0, bytes: 0, from: null, sent: 0 };
let RTP_SSRC = chr(0x57, 0x57, 0x49, 0x4d);	// "WWIM"
if (opt.call || opt.answer != null) {
	rtp.sock = socket.create(AF, socket.SOCK_DGRAM);
	if (opt.vrf)
		rtp.sock.setopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, opt.vrf);
	if (!rtp.sock.bind({ address: ue_addr, port: opt.rtp_port })) {
		warn(sprintf('bind RTP port %d: %s\n', opt.rtp_port, socket.error()));
		exit(1);
	}
}

// ---- the card: wwand's APDU channel, through this ubus connection ------------------

let ubus_call = (obj, method, args, cb) => {
	let r = conn.call(obj, method, args);
	if (r == null)
		return cb(sprintf('ubus %s %s: %s', obj, method, ubus.error()), null);
	if (r.error)
		return cb(r, null);
	cb(null, r);
};
let card = AKA.wwand_card(ubus_call, opt.modem, opt.slot);

// ---- run ---------------------------------------------------------------------------

uloop.init();

let reg = null;
let finish_after = (secs) => uloop.timer(secs * 1000, () => {
	if (reg.state != 'registered') {
		reg.close();
		say('SAs removed, done');
		return uloop.end();
	}
	reg.deregister((e) => {
		say('de-REGISTER %s; SAs removed, done', e ? sprintf('failed: %J', e) : 'ok');
		uloop.end();
	});
});

let call = null;
let reg_res = null, take_call = null;	// set below, used by the socket handler

// SIP over TCP (RFC 3261 18.1.1: a request over ~1300 bytes, an INVITE with
// its SDP from the network, comes over TCP). The P-CSCF connects
// P:port_c -> U:port_s, inside the same SAs (their selectors carry no
// protocol). The response to a request that came over TCP goes back on that
// connection (18.2.2): tcp_by_callid remembers it per Call-ID.
let tcp_by_callid = {};
let callid_of = (buf) => {
	let mm = match(buf, /\r\n(Call-ID|i)[ \t]*:[ \t]*([^\r\n]+)/i);
	return mm ? trim(mm[2]) : null;
};

let send = (buf, dst, port, src) => {
	let conn = (substr(buf, 0, 8) == 'SIP/2.0 ') ? tcp_by_callid[callid_of(buf) ?? ''] : null;
	if (conn) {
		say('>>> over TCP (%d bytes)\n%s', length(buf), buf);
		if (conn.send(buf) == null)
			say('TCP send failed: %s', socket.error());
		// a provisional also goes over UDP on the pair the P-CSCF takes our
		// responses on (U:port_c -> P:port_s). Vodafone DE (Nokia/ALU) acts on
		// no 18x that comes only back on its TCP connection (P:port_c ->
		// U:port_s): the caller hears no ringback, gets no PRACK, and after
		// some seconds without an 18x the call goes to the mailbox. A 200 on
		// the connection is taken. HW 2026-11-14 mt14: with this copy the
		// caller rang (Android ImsPhoneCall ALERTING) and the late 200 was
		// ACKed. The transaction layer drops the duplicate. --dup-udp 0 off.
		if (opt.dup_udp && match(buf, /^SIP\/2\.0 1[0-9][0-9] /) && substr(buf, 8, 3) != '100' && reg_res) {
			say('>>> (dup) over UDP to %s port %d from port %d', reg_res.pcscf.addr, reg_res.pcscf.port_s, opt.port_c);
			socks[sprintf('%d', opt.port_c)].send(buf, 0, { address: reg_res.pcscf.addr, port: reg_res.pcscf.port_s });
		}
		return;
	}
	say('>>> to %s port %d from port %d (%d bytes)\n%s', dst, port, src, length(buf), buf);
	let s = socks[sprintf('%d', src)];
	if (!s.send(buf, 0, { address: dst, port: port }))
		say('send failed: %s', socket.error());
};

reg = REG.create({
	imsi: m.imsi, mnc_len: mnc_len, imei: m.imei,
	ue_addr: ue_addr, pcscf_addr: pcscf, port_c: opt.port_c, port_s: opt.port_s,
	ealgs: opt.ealg ? split(opt.ealg, ',') : null,
	aid: opt.aid,
	pani: pani,
	card: card, xfrm: xfrm,
	smsip: false,
	sa_opts: opt.vrf ? { } : null,
	timer: (ms, fn) => uloop.timer(ms, fn),
	log: (lvl, msg) => say('%s: %s', lvl, msg),
	send: send,
});

// one received SIP message, from UDP or TCP
let dispatch = (data) => {
	if (reg.on_message(data) || call?.on_message(data))
		return;
	// the network's reachability check before an incoming call (paging OPTIONS)
	let opts = reg_res ? CALL.options_ok(data, { ue_addr: ue_addr, port_s: opt.port_s,
		contact_user: m.imsi, imei_urn: REG.imei_urn(m.imei) }) : null;
	if (opts)
		return send(opts, reg_res.pcscf.addr, reg_res.pcscf.port_s, opt.port_c);   // as ue/call.uc reply()
	let inv = (opt.answer != null && reg_res) ? CALL.initial_invite(data) : null;
	if (inv)
		return take_call(inv);
	say('(not ours, ignored)');
};

for (let k, s in socks) {
	let sk = s;
	uloop.handle(sk, () => {
		let buf = sk.recvmsg(65535, null, 0);
		if (!buf)
			return;
		say('<<< from %s port %d to port %s (%d bytes)\n%s', buf.address?.address, buf.address?.port, k,
			length(buf.data), buf.data);
		dispatch(buf.data);
	}, uloop.ULOOP_READ);
}

// the next complete message at the start of a TCP stream buffer, by
// Content-Length (RFC 3261 18.3), or null while it is incomplete
let tcp_frame = (b) => {
	let he = index(b, '\r\n\r\n');
	if (he < 0)
		return null;
	let mm = match(substr(b, 0, he), /\r\n(Content-Length|l)[ \t]*:[ \t]*([0-9]+)/i);
	let total = he + 4 + (mm ? +mm[2] : 0);
	return (length(b) >= total) ? total : null;
};

let tcp_l = socket.create(AF, socket.SOCK_STREAM);
if (opt.vrf)
	tcp_l.setopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, opt.vrf);
tcp_l.setopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);
if (!tcp_l.bind({ address: ue_addr, port: opt.port_s }) || !tcp_l.listen(4))
	say('TCP listen on port %d: %s (SIP over TCP not available)', opt.port_s, socket.error());
else
	uloop.handle(tcp_l, () => {
		let c = tcp_l.accept();
		if (!c)
			return;
		let peer = c.peername();
		say('TCP connection from %s port %d to port %d', peer?.address, peer?.port, opt.port_s);
		let rx = '';
		let h;
		h = uloop.handle(c, () => {
			let d = c.recv(65535);
			if (d == null || d == '') {
				say('TCP connection from %s port %d closed', peer?.address, peer?.port);
				for (let id, v in tcp_by_callid)
					if (v === c)
						delete tcp_by_callid[id];
				h.delete();
				c.close();
				return;
			}
			rx += d;
			for (let n = tcp_frame(rx); n != null; n = tcp_frame(rx)) {
				let msg = substr(rx, 0, n);
				rx = substr(rx, n);
				say('<<< over TCP from %s port %d (%d bytes)\n%s', peer?.address, peer?.port, length(msg), msg);
				let id = callid_of(msg);
				if (id && substr(msg, 0, 8) != 'SIP/2.0 ')
					tcp_by_callid[id] = c;
				dispatch(msg);
			}
		}, uloop.ULOOP_READ);
	}, uloop.ULOOP_READ);

// the SAs for Wireshark (Preferences > Protocols > ESP > ESP SAs, or
// ~/.config/wireshark/esp_sa): one line per SA, as that UAT file takes them
let print_esp_sas = () => {
	for (let sa in reg.sa_set?.sas ?? [])
		say('ESP-SA "%s","%s","%s","0x%08x","%s","0x%s","%s","0x%s"',
			index(sa.src, ':') >= 0 ? 'IPv6' : 'IPv4', sa.src, sa.dst, sa.spi,
			sa.enc ? 'AES-CBC [RFC3602]' : 'NULL', sa.enc ? hexenc(sa.enc.key) : '',
			sa.auth.trunc == 96 && match(sa.auth.name, /sha1/) ? 'HMAC-SHA-1-96 [RFC2404]' : 'HMAC-MD5-96 [RFC2403]',
			hexenc(sa.auth.key));
};

if (rtp.sock)
	uloop.handle(rtp.sock, () => {
		let p = rtp.sock.recvmsg(2048, null, 0);
		if (!p)
			return;
		if (!rtp.pkts)
			say('first RTP packet from %s port %d (%d bytes)', p.address?.address, p.address?.port, length(p.data));
		rtp.pkts++;
		rtp.bytes += length(p.data);
		rtp.from = p.address;
		// echo: the frame goes back to where it came from under our own
		// SSRC (sequence and timestamp stay the far end's: monotonic, so a
		// valid stream). The network's media guard drops a call whose UE sends
		// no RTP (BYE "Media Guard Timer Expired" after ~13 s), and the
		// called phone hears itself: an audio path check without a codec.
		if (opt.echo && length(p.data) >= 12 && rtp.sock.send(substr(p.data, 0, 8) + RTP_SSRC + substr(p.data, 12),
				0, p.address))
			rtp.sent++;
	}, uloop.ULOOP_READ);


// our precondition segment: the QCI 1 bearer on the IMS PDN, which the
// network sets up for the call. The modem lists it in AT+CGEQOSRDP
// ("+CGEQOSRDP: <cid>,<qci>,..."; the RG650E: 107,1,... as a secondary
// context of the IMS cid, +CGSCONTRDP: 107,2,7). Polled every 200 ms; after
// 10 s the call goes on as if it were up (with a warning), rather than hang.
let qos_wait = (cb) => {
	let t0 = clock(true)[0], tick;
	tick = () => {
		let r = conn.call('wwand', 'modem_at', { modem: opt.modem, command: 'AT+CGEQOSRDP', timeout: 2000 });
		for (let l in r?.response ?? [])
			if (match(l, /^\+CGEQOSRDP: *[0-9]+, *1(,|$)/)) {
				say('QCI 1 bearer up: %s', l);
				return cb();
			}
		if (clock(true)[0] - t0 >= 10) {
			say('warn: no QCI 1 bearer after 10 s; going on');
			return cb();
		}
		uloop.timer(200, tick);
	};
	tick();
};

let mt_n = 0, mt_mode = null;
let new_call = (res) => CALL.create({
		ue_addr: ue_addr, port_c: opt.port_c, port_s: opt.port_s,
		pcscf: res.pcscf, route: res.service_route,
		impu: filter(res.associated, (u) => match(u, /^sip:/))[0] ?? reg.ids.impu,
		contact_user: m.imsi, imei_urn: REG.imei_urn(m.imei), pani: pani,
		sec_verify: reg.server_raw, rtp_port: opt.rtp_port,
		timer: (ms, fn) => uloop.timer(ms, fn),
		log: (lvl, msg) => say('%s: %s', lvl, msg),
		send: send,
		preconditions: opt.preconditions == 'always' ? 'always' : opt.preconditions != 0,
		qos_wait: qos_wait,
		mt_mode: mt_mode,
	});

let call_ended = (d) => {
	say('CALL ENDED: %J; RTP received: %d packets, %d bytes%s; echoed %d', d, rtp.pkts, rtp.bytes,
		rtp.from ? sprintf(' from %s port %d', rtp.from.address, rtp.from.port) : '', rtp.sent);
	say('SDP answer:\n%s', call.answer ?? '-');
	rtp.pkts = 0; rtp.bytes = 0; rtp.sent = 0; rtp.from = null;
	// with test modes still to go, stay registered for the next call
	if (opt.mt_modes && mt_n < length(split(opt.mt_modes, ',')))
		return say('waiting for the next incoming call (%d of %d done)', mt_n, length(split(opt.mt_modes, ',')));
	finish_after(1);
};

// --answer N: an incoming call is answered after N seconds, hung up --talk
// seconds after that (or by the caller). A second one while busy gets 486.
// RTP before the far end sends any (an incoming call that rings): AMR-WB
// NO_DATA frames every 20 ms to the offer's media address, until the first
// packet comes in and the echo takes over. Without uplink RTP the network
// drops the media after ~13 s (MO: BYE "Media Guard Timer Expired"; MT: our
// 200 after 15 s of ringing was never ACKed, HW 2026-11-14 mt11).
let ka = { t: null, seq: 0, ts: 0, n: 0 };
let ka_stop = () => {
	ka.t?.cancel();
	ka.t = null;
};
let ka_start = (offer, answer) => {
	let mc = match(offer ?? '', /\nc=IN IP[46] ([^\r\n ]+)/);
	let mm = match(offer ?? '', /\nm=audio ([0-9]+) /);
	let pt = match(answer ?? '', /\nm=audio [0-9]+ RTP\/AVP ([0-9]+)/);
	if (!mc || !mm || !pt || !rtp.sock)
		return;
	let dst = { address: mc[1], port: +mm[1] }, p = +pt[1];
	ka_stop();
	let tick;
	tick = () => {
		if (rtp.pkts > 0 || !call || call.state == 'ended') {
			if (ka.n)
				say('RTP keepalive: %d NO_DATA packets sent', ka.n);
			return ka_stop();
		}
		let hdr = chr(0x80, p & 0x7f, (ka.seq >> 8) & 255, ka.seq & 255,
			(ka.ts >> 24) & 255, (ka.ts >> 16) & 255, (ka.ts >> 8) & 255, ka.ts & 255) + RTP_SSRC;
		ka.seq = (ka.seq + 1) & 0xffff;
		ka.ts = (ka.ts + 320) & 0xffffffff;     // 20 ms at 16 kHz
		// CMR 15, TOC F=0 FT=15 (NO_DATA) Q=1: 1111 0 1111 1 + padding
		if (rtp.sock.send(hdr + chr(0xf7, 0xc0), 0, dst))
			ka.n++;
		ka.t = uloop.timer(20, tick);
	};
	say('RTP keepalive (AMR-WB NO_DATA, pt %d) to %s port %d until the far end sends', p, dst.address, dst.port);
	tick();
};

take_call = (inv) => {
	if (call && call.state != 'ended') {
		let busy = new_call(reg_res);
		busy.incoming(inv, () => null);
		busy.reject(486, 'Busy Here');
		return;
	}
	let modes = opt.mt_modes ? split(opt.mt_modes, ',') : null;
	mt_mode = modes ? modes[mt_n++ % length(modes)] : null;
	if (mt_mode)
		say('MT test mode for this call: %s', mt_mode);
	call = new_call(reg_res);
	mt_mode = null;
	let ans_t = null, talk_t = null;
	call.incoming(inv, (ev, d) => {
		if (ev == 'incoming') {
			say('INCOMING CALL from %s; answering in %d s', d.from, opt.answer);
			ka_start(call.offer, call.answer);
			ans_t = uloop.timer(opt.answer * 1000, () => call.accept());
		}
		if (ev == 'answered') {
			say('ANSWERED; hanging up in %d s', opt.talk);
			talk_t = uloop.timer(opt.talk * 1000, () => call.hangup());
		}
		if (ev == 'ended') {
			ka_stop();
			ans_t?.cancel();
			talk_t?.cancel();
			call_ended(d);
		}
	});
};

// the call, once registered; finish_after() de-REGISTERs when it is over
let place_call = (res) => {
	call = new_call(res);
	let ring_t = null, talk_t = null;
	call.dial(opt.call, (ev, d) => {
		if (ev == 'trying' && !ring_t)
			ring_t = uloop.timer(opt.ring * 1000, () => {
				if (call.state == 'early' || call.state == 'calling') {
					say('no answer after %d s, cancelling', opt.ring);
					call.hangup();
				}
			});
		if (ev == 'answered') {
			ring_t?.cancel();
			say('ANSWERED; hanging up in %d s', opt.talk);
			talk_t = uloop.timer(opt.talk * 1000, () => call.hangup());
		}
		if (ev == 'ended') {
			ring_t?.cancel();
			talk_t?.cancel();
			call_ended(d);
		}
	});
};

reg.start((err, res) => {
	if (err) {
		say('REGISTRATION FAILED: %J', err);
		finish_after(1);
		return;
	}
	say('REGISTERED: %J', res);
	print_esp_sas();
	reg_res = res;
	if (opt.call)
		return place_call(res);
	if (opt.answer != null)
		say('waiting %d s for an incoming call', opt.hold);
	// the hold ends the run unless a call is going on (that one ends it)
	uloop.timer(opt.hold * 1000, () => {
		if (!call || call.state == 'ended')
			finish_after(0);
	});
});

// SIGINT / SIGTERM: de-REGISTER and remove the SAs instead of leaving them
// (and their policies, which a next run would collide with) in the kernel
let stopping = false;
let stop = () => {
	if (stopping)
		return;
	stopping = true;
	say('signal: stopping');
	if (call && call.state != 'ended')
		call.hangup();
	finish_after(0);
};
signal('SIGINT', stop);
signal('SIGTERM', stop);

uloop.run();
