// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// Can the kernel do the sec-agree SAs we offer? A hardware crypto driver that
// registers an algorithm it cannot set a key for makes every SA of that
// combination fail with EINVAL, although the kernel's software
// implementation would do it.
//
// Measured: MT7621's EIP-93 (OpenWrt 25.12, kernel 6.12, module
// crypto_hw_eip93) registers authenc(hmac(sha1|md5|sha256),cbc(aes)) at a
// priority above the software ones, and rejects every key for them; Vodafone
// DE's P-CSCF offers only hmac-sha-1-96 + aes-cbc (NR7101, 2026-11-21). With
// the module unloaded the software implementation takes the SAs. charon's
// own tunnel (hmac(sha2_512), which the EIP-93 lacks) was never affected.
//
//   let r = KC.check({ xfrm, exists, run, log, combos: [ [ alg, ealg ], … ] })
//   r: { ok: true } | { ok: false, failed: [ … ], unloaded?, busy? }
//
// `exists(path)` stats a path, `run(argv)` runs a command and returns its
// exit code (sipd: system()). The probe SA lives on 2001:db8::/32
// (documentation addresses, RFC 3849) for an instant.

'use strict';

import { ALGS, EALGS } from 'ue_secagree';

// driver modules known to reject keys they advertise algorithms for
export const MODULES = [ 'crypto_hw_eip93' ];

const SRC = '2001:db8:ffff::1', DST = '2001:db8:ffff::2', SPI = 0x0ffffff0;

function bytes(n, v)
{
	let s = '';
	for (let i = 0; i < n; i++)
		s += chr(v);
	return s;
}

// one SA of this combination, added and removed again: null or the error
export function probe(xfrm, alg, ealg)
{
	let a = ALGS[alg], e = EALGS[ealg];
	if (!a || !e)
		return 'unknown algorithm';
	let sa = { src: SRC, dst: DST, spi: SPI, reqid: 0x0fff, replay_window: 32,
	           sel: { src: SRC, dst: DST, sport: 0, dport: 0 },
	           auth: { name: a.kernel, key: bytes((alg == 'hmac-md5-96') ? 16 : 20, 0x11), trunc: a.trunc } };
	if (ealg != 'null')
		sa.enc = { name: e.kernel, key: bytes((ealg == 'des-ede3-cbc') ? 24 : 16, 0x22) };
	if (!xfrm.sa_add(sa))
		return xfrm.error() ?? 'refused';
	xfrm.sa_del({ src: SRC, dst: DST, spi: SPI });
	return null;
}

// the combinations that fail: [ { alg, ealg, error } ]
export function failing(xfrm, combos)
{
	let out = [];
	for (let c in combos) {
		let err = probe(xfrm, c[0], c[1]);
		if (err)
			push(out, { alg: c[0], ealg: c[1], error: err });
	}
	return out;
}

// probe the encrypted combinations; where they fail with EINVAL and a known
// driver is loaded, unload it and probe again
export function check(o)
{
	let log = o.log ?? (() => null);
	let combos = filter(o.combos ?? [], (c) => c[1] != 'null');
	let bad = failing(o.xfrm, combos);
	if (!length(bad))
		return { ok: true };
	let einval = filter(bad, (b) => match(sprintf('%s', b.error), /Invalid argument/));
	let names = join(', ', map(bad, (b) => b.alg + '+' + b.ealg));
	if (!length(einval)) {
		log('warn', sprintf('ue: the kernel refuses IPsec %s: %s', names, bad[0].error));
		return { ok: false, failed: bad };
	}
	for (let m in MODULES) {
		if (!o.exists('/sys/module/' + m))
			continue;
		if (o.run([ 'rmmod', m ]) != 0) {
			log('warn', sprintf('ue: the kernel refuses IPsec %s (EINVAL), and %s is in use — not unloaded', names, m));
			return { ok: false, failed: bad, busy: m };
		}
		let still = failing(o.xfrm, combos);
		log('warn', sprintf('ue: kernel module %s unloaded: it refuses the keys of IPsec %s (EINVAL); the kernel\'s own crypto takes over%s',
			m, names, length(still) ? sprintf(' — still refused: %s', join(', ', map(still, (b) => b.alg + '+' + b.ealg))) : ''));
		return { ok: !length(still), failed: still, unloaded: m };
	}
	log('warn', sprintf('ue: the kernel refuses IPsec %s: %s', names, einval[0].error));
	return { ok: false, failed: bad };
}
