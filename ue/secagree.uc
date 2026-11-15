// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// IMS security agreement on the UE side: the Security-Client / -Server /
// -Verify headers (RFC 3329, 3GPP TS 33.203 7.2 and Annex H), the ESP keys
// from CK/IK (TS 33.203 Annex I) and the four SAs with their policies (TS
// 33.203 7.1), applied through the wwand_io.xfrm netlink module.
//
// The xfrm module is passed in, so the host tests can check the plan without
// a kernel and, in a network namespace of their own, against a real one.

'use strict';

// what we offer, best first; the names are the TS 33.203 ones, `kernel` the
// Linux crypto API ones
export const ALGS = {
	'hmac-sha-1-96': { kernel: 'hmac(sha1)', trunc: 96 },
	'hmac-md5-96':   { kernel: 'hmac(md5)',  trunc: 96 },
};
export const EALGS = {
	'aes-cbc':      { kernel: 'cbc(aes)' },
	'des-ede3-cbc': { kernel: 'cbc(des3_ede)' },
	'null':         { kernel: 'ecb(cipher_null)' },
};

export const DEFAULT_ALGS = [ 'hmac-sha-1-96', 'hmac-md5-96' ];
export const DEFAULT_EALGS = [ 'null', 'aes-cbc', 'des-ede3-cbc' ];

// ---- headers -----------------------------------------------------------------

// one Security-Client entry per (alg, ealg) pair, in the order given
// (TS 33.203 Annex H: the UE lists the combinations it supports)
export function client_header(spi_c, spi_s, port_c, port_s, algs, ealgs)
{
	let out = [];

	for (let a in (algs ?? DEFAULT_ALGS)) {
		if (!ALGS[a])
			continue;
		for (let e in (ealgs ?? DEFAULT_EALGS)) {
			if (!EALGS[e])
				continue;
			push(out, sprintf('ipsec-3gpp;alg=%s;ealg=%s;mod=trans;prot=esp;spi-c=%d;spi-s=%d;port-c=%d;port-s=%d',
				a, e, spi_c, spi_s, port_c, port_s));
		}
	}
	return join(', ', out);
}

// a Security-Server (or -Client) value, possibly several comma-separated
// entries -> [ { mech, alg, ealg, spi_c, spi_s, port_c, port_s, q, raw } ]
export function parse(value)
{
	let out = [];

	for (let entry in split(value ?? '', ',')) {
		entry = trim(entry);
		if (!length(entry))
			continue;

		let parts = split(entry, ';');
		let o = { mech: lc(trim(parts[0])), raw: entry };

		for (let i = 1; i < length(parts); i++) {
			let kv = split(trim(parts[i]), '=', 2);
			o[replace(lc(kv[0]), '-', '_')] = kv[1] ?? '';
		}

		for (let k in [ 'spi_c', 'spi_s', 'port_c', 'port_s' ])
			if (o[k] != null)
				o[k] = +o[k];

		o.q = (o.q != null) ? +o.q : 0.0;
		// RFC 3329 2.2: ealg absent means null (TS 33.203 Annex H)
		o.ealg = lc(o.ealg ?? 'null');
		o.alg = lc(o.alg ?? '');
		push(out, o);
	}
	return out;
}

// the server's entry to use: ipsec-3gpp, with an alg/ealg we offered, the
// highest q first, the server's order on a tie (RFC 3329 2.3)
export function choose(server, algs, ealgs)
{
	algs = algs ?? DEFAULT_ALGS;
	ealgs = ealgs ?? DEFAULT_EALGS;

	let best = null;

	for (let s in server) {
		if (s.mech != 'ipsec-3gpp' || !ALGS[s.alg] || !EALGS[s.ealg])
			continue;
		if (index(algs, s.alg) < 0 || index(ealgs, s.ealg) < 0)
			continue;
		if (s.spi_c == null || s.spi_s == null || s.port_c == null || s.port_s == null)
			continue;
		if (s.prot && lc(s.prot) != 'esp')
			continue;
		if (s.mod && lc(s.mod) != 'trans')
			continue;
		if (!best || s.q > best.q)
			best = s;
	}
	return best;
}

// Security-Verify repeats the server's list as received (RFC 3329 2.3.1)
export function verify_header(server_value)
{
	return join(', ', map(parse(server_value), (s) => s.raw));
}

// ---- keys (TS 33.203 Annex I) ------------------------------------------------

// ck, ik: 16-byte binary strings from the USIM
export function keys(ck, ik, alg, ealg)
{
	if (length(ck) != 16 || length(ik) != 16 || !ALGS[alg] || !EALGS[ealg])
		return null;

	let auth = (alg == 'hmac-sha-1-96')
		? ik + '\x00\x00\x00\x00'          // IK_ESP = IK || 32 zero bits
		: ik;                              // hmac-md5-96: IK_ESP = IK

	let enc = null;
	if (ealg == 'aes-cbc')
		enc = ck;                          // CK_ESP = CK
	else if (ealg == 'des-ede3-cbc')
		enc = substr(ck, 0, 8) + substr(ck, 8, 8) + substr(ck, 0, 8);   // CK1 || CK2 || CK1

	return { auth: auth, enc: enc };
}

// ---- the four SAs (TS 33.203 7.1) ----------------------------------------------

// ue = { addr, port_c, port_s, spi_c, spi_s } (ours: spi_c/spi_s are the
// inbound SPIs we announced), pcscf = the chosen Security-Server entry plus
// { addr }. `reqid` is the first of four consecutive reqids for this set.
// Returns { sas: [...], policies: [...] } in the shape the xfrm module takes.
export function plan(ue, pcscf, alg, ealg, ck, ik, reqid, opts)
{
	let k = keys(ck, ik, alg, ealg);

	if (!k)
		return null;

	let auth = { name: ALGS[alg].kernel, key: k.auth, trunc: ALGS[alg].trunc };
	let enc = (ealg == 'null') ? null : { name: EALGS[ealg].kernel, key: k.enc };
	let U = ue.addr, P = pcscf.addr;
	let dev = opts?.dev;

	// [ direction, src, sport, dst, dport, spi ]
	let rows = [
		[ 'out', U, ue.port_c,     P, pcscf.port_s, pcscf.spi_s ],   // UE client -> P-CSCF server
		[ 'in',  P, pcscf.port_c,  U, ue.port_s,    ue.spi_s ],      // P-CSCF client -> UE server
		[ 'out', U, ue.port_s,     P, pcscf.port_c, pcscf.spi_c ],   // UE server -> P-CSCF client
		[ 'in',  P, pcscf.port_s,  U, ue.port_c,    ue.spi_c ],      // P-CSCF server -> UE client
	];

	let sas = [], policies = [];

	for (let i, r in rows) {
		let sel = { src: r[1], sport: r[2], dst: r[3], dport: r[4] };
		if (dev && r[0] == 'out')
			sel.dev = dev;

		let sa = { dir: r[0], src: r[1], dst: r[3], spi: r[5], reqid: reqid + i,
		           auth: auth, sel: { ...sel }, replay_window: 32 };
		if (enc)
			sa.enc = enc;
		if (opts?.if_id != null)
			sa.if_id = opts.if_id;
		push(sas, sa);

		let pol = { dir: r[0], sel: { ...sel }, priority: opts?.priority ?? 1000,
		            tmpl: { src: r[1], dst: r[3], reqid: reqid + i } };
		if (opts?.if_id != null)
			pol.if_id = opts.if_id;
		push(policies, pol);
	}

	return { sas: sas, policies: policies };
}

function sa_args(sa, update)
{
	let a = { ...sa };
	delete a.dir;
	if (update)
		a.update = true;
	return a;
}

// Undo a set: policies first (so no packet goes out in clear between the
// two steps), then the SAs. Missing entries are not an error: a set may be
// half applied, or already gone with the netns.
export function remove(xfrm, set)
{
	for (let p in set?.policies ?? [])
		xfrm.policy_del({ dir: p.dir, sel: p.sel, if_id: p.if_id });
	for (let s in set?.sas ?? [])
		xfrm.sa_del({ src: s.src, dst: s.dst, spi: s.spi });
}

// Apply a set: SAs first, then the policies that point at them. Inbound SPIs
// reserved with reserve() are larval SAs and are filled in with UPDSA (the
// `reserved` list holds those SPIs); if the reservation has meanwhile
// expired the SA is created afresh. All or nothing: on an error everything
// added so far is taken down again. Returns null or { error, step }.
export function apply(xfrm, set, reserved)
{
	let done = { sas: [], policies: [] };

	let fail = (step) => {
		let err = xfrm.error();
		remove(xfrm, done);
		return { error: err, step: step };
	};

	for (let s in set.sas) {
		let larval = s.dir == 'in' && index(reserved ?? [], s.spi) >= 0;
		let ok = xfrm.sa_add(sa_args(s, larval));

		if (!ok && larval)
			ok = xfrm.sa_add(sa_args(s, false));
		if (!ok)
			return fail(sprintf('sa %s spi %d', s.dir, s.spi));
		push(done.sas, s);
	}

	for (let p in set.policies) {
		if (!xfrm.policy_add(p))
			return fail(sprintf('policy %s %s:%d -> %s:%d', p.dir, p.sel.src, p.sel.sport, p.sel.dst, p.sel.dport));
		push(done.policies, p);
	}

	return null;
}

// Reserve the two inbound SPIs before the first REGISTER, so the ones we
// announce in Security-Client are ours. The kernel keeps a larval SA for
// them until apply() fills it in (or it expires, net.core.xfrm_acq_expires).
export function reserve(xfrm, ue_addr, pcscf_addr, min, max)
{
	let spi_c = xfrm.alloc_spi({ src: pcscf_addr, dst: ue_addr, min: min ?? 0x1000, max: max ?? 0x0fffffff });
	let spi_s = (spi_c != null)
		? xfrm.alloc_spi({ src: pcscf_addr, dst: ue_addr, min: min ?? 0x1000, max: max ?? 0x0fffffff })
		: null;

	if (spi_c == null || spi_s == null) {
		let err = xfrm.error();
		if (spi_c != null)
			xfrm.sa_del({ src: pcscf_addr, dst: ue_addr, spi: spi_c });
		return { error: err };
	}
	return { spi_c: spi_c, spi_s: spi_s };
}
