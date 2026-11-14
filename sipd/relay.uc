// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// The RTP relay between the LAN phone (or PBX) and the IMS PDN: one socket
// on each side per call, packets moved 1:1. The codecs are the same on both
// legs (the SDP is relayed with its payload types, ue/call.uc sdp_relay),
// so nothing is decoded or rewritten. RTCP (port + 1) goes the same way.
//
// The far ends are taken from the SDP and then learnt from the first
// packet that arrives (symmetric RTP: a NAT or a PBX that sends from
// another port wins). Until the LAN side sends, the IMS side gets an
// AMR(-WB) NO_DATA frame every 20 ms: without uplink RTP the network drops
// the media after ~13 s (research/rg650e-245/NOTES.md, 2026-11-14).
//
//   let r = RELAY.create({ socket, uloop, lan_ip, ims_ip (or a function), vrf, log, base, span })
//   let m = r.alloc()           -> { id, lan_port, ims_port } or null
//   r.connect(m, { lan: { address, port }, ims: { address, port }, ims_pt })
//   r.stop(m)

'use strict';

export function create(o)
{
	let socket = o.socket, uloop = o.uloop;
	let log = o.log ?? (() => null);
	let base = o.base ?? 40000, span = o.span ?? 200;
	let next_id = 0;
	let all = {};

	let open = (fam, addr, port, vrf) => {
		let s = socket.create(fam, socket.SOCK_DGRAM);
		if (!s)
			return null;
		if (vrf && !s.setopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, vrf)) {
			s.close();
			return null;
		}
		if (!s.bind({ address: addr, port: port })) {
			s.close();
			return null;
		}
		return s;
	};

	let fam_of = (a) => index(a, ':') >= 0 ? socket.AF_INET6 : socket.AF_INET;

	// an even port with its odd neighbour free on both sides
	let alloc_pair = (addr, vrf, start) => {
		for (let p = start; p < base + span; p += 2) {
			let a = open(fam_of(addr), addr, p, vrf);
			if (!a)
				continue;
			let b = open(fam_of(addr), addr, p + 1, vrf);
			if (b)
				return { port: p, rtp: a, rtcp: b };
			a.close();
		}
		return null;
	};

	let close_pair = (pr) => {
		pr?.rtp?.close();
		pr?.rtcp?.close();
	};

	let self = {};

	self.alloc = function() {
		let lan = alloc_pair(o.lan_ip, null, base);
		if (!lan)
			return null;
		let ims_ip = (type(o.ims_ip) == 'function') ? o.ims_ip() : o.ims_ip;
		let ims = ims_ip ? alloc_pair(ims_ip, o.vrf, base) : null;
		if (!ims) {
			close_pair(lan);
			return null;
		}
		let m = { id: ++next_id, lan: lan, ims: ims, lan_port: lan.port, ims_port: ims.port,
		          handles: [], peer: {}, n: { up: 0, down: 0, ka: 0 } };
		all[sprintf('%d', m.id)] = m;
		return m;
	};

	// one direction: what arrives on `from` goes out of `to` to peer[key]
	let pipe = (m, from, to, key, count, on_first) => {
		let h = uloop.handle(from, () => {
			let p = from.recvmsg(2048, null, 0);
			if (!p)
				return;
			let back = (key == 'ims') ? 'lan' : 'ims';
			// symmetric RTP: the side we receive from is where we send to
			if (p.address)
				m.peer[back + count.suffix] = p.address;
			let dst = m.peer[key + count.suffix];
			if (dst && to.send(p.data, 0, dst))
				m.n[count.dir]++;
			on_first?.();
		}, uloop.ULOOP_READ);
		push(m.handles, h);
	};

	self.connect = function(m, far) {
		if (!m || m.connected)
			return;
		m.connected = true;
		m.peer.lan = far.lan;
		m.peer.ims = far.ims;
		m.peer.lan_rtcp = far.lan ? { address: far.lan.address, port: far.lan.port + 1 } : null;
		m.peer.ims_rtcp = far.ims ? { address: far.ims.address, port: far.ims.port + 1 } : null;

		let lan_heard = false;
		pipe(m, m.lan.rtp, m.ims.rtp, 'ims', { dir: 'up', suffix: '' }, () => { lan_heard = true; });
		pipe(m, m.ims.rtp, m.lan.rtp, 'lan', { dir: 'down', suffix: '' });
		pipe(m, m.lan.rtcp, m.ims.rtcp, 'ims', { dir: 'up', suffix: '_rtcp' });
		pipe(m, m.ims.rtcp, m.lan.rtcp, 'lan', { dir: 'down', suffix: '_rtcp' });

		// NO_DATA keepalive towards the IMS side until the LAN side sends:
		// CMR 15, TOC F=0 FT=15 Q=1 (RFC 4867 4.3, AMR and AMR-WB alike)
		if (far.ims_pt != null) {
			let seq = 0, ts = 0, ssrc = chr(0x57, 0x57, 0x49, 0x4d), tick;
			let step = far.ims_rate == 8000 ? 160 : 320;
			tick = () => {
				if (lan_heard || m.stopped) {
					if (m.n.ka)
						log('info', sprintf('relay %d: %d keepalive frames before the LAN side sent', m.id, m.n.ka));
					return;
				}
				let hdr = chr(0x80, far.ims_pt & 0x7f, (seq >> 8) & 255, seq & 255,
					(ts >> 24) & 255, (ts >> 16) & 255, (ts >> 8) & 255, ts & 255) + ssrc;
				seq = (seq + 1) & 0xffff;
				ts = (ts + step) & 0xffffffff;
				if (m.peer.ims && m.ims.rtp.send(hdr + chr(0xf7, 0xc0), 0, m.peer.ims))
					m.n.ka++;
				m.ka = uloop.timer(20, tick);
			};
			tick();
		}
		log('info', sprintf('relay %d: LAN %s:%d <-> IMS %s:%d', m.id,
			far.lan?.address ?? '?', far.lan?.port ?? 0, far.ims?.address ?? '?', far.ims?.port ?? 0));
	};

	self.stop = function(m) {
		if (!m || m.stopped)
			return;
		m.stopped = true;
		m.ka?.cancel();
		for (let h in m.handles)
			h.delete();
		close_pair(m.lan);
		close_pair(m.ims);
		delete all[sprintf('%d', m.id)];
		log('info', sprintf('relay %d: stopped; up %d, down %d packets', m.id, m.n.up, m.n.down));
	};

	self.stats = (m) => m?.n;

	return self;
};
