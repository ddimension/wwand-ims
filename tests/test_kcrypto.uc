// Host tests for ue/kcrypto.uc against a stand-in for the xfrm binding: a
// kernel whose crypto driver refuses AES keys (MT7621's EIP-93), the module
// unloaded, a module in use, a refusal that is not EINVAL.
'use strict';

import { eq, ok, done } from './lib/check.uc';
import * as KC from 'ue_kcrypto';

function kernel(refuse)
{
	let k = { added: [], deleted: 0, loaded: { crypto_hw_eip93: true }, busy: false, ran: [], err: null };
	k.xfrm = {
		sa_add: (sa) => {
			push(k.added, sa);
			let why = sa.enc ? refuse(sa, k) : null;
			if (why) {
				k.err = (type(why) == 'string') ? why : 'kernel: Invalid argument';
				return false;
			}
			return true;
		},
		sa_del: (sa) => { k.deleted++; return true; },
		error: () => k.err,
	};
	k.opts = {
		xfrm: k.xfrm, combos: [ [ 'hmac-sha-1-96', 'null' ], [ 'hmac-sha-1-96', 'aes-cbc' ], [ 'hmac-md5-96', 'aes-cbc' ] ],
		exists: (p) => !!k.loaded[replace(p, /^\/sys\/module\//, '')],
		run: (argv) => {
			push(k.ran, join(' ', argv));
			if (k.busy)
				return 1;
			delete k.loaded[argv[1]];
			return 0;
		},
		log: (l, m) => push(k.ran, 'LOG ' + m),
	};
	return k;
}

// the EIP-93 case: AES refused while the module is loaded
let eip = (sa, k) => k.loaded.crypto_hw_eip93 && sa.enc.name == 'cbc(aes)';
let k = kernel(eip);
let r = KC.check(k.opts);
eq([ r.ok, r.unloaded, k.ran[0] ], [ true, 'crypto_hw_eip93', 'rmmod crypto_hw_eip93' ], 'check: AES refused -> the module unloaded, then accepted');
ok(!length(filter(k.added, (sa) => !sa.enc)), 'check: the null combinations are not probed');
eq(k.added[0].src, '2001:db8:ffff::1', 'check: probes on documentation addresses');
ok(k.deleted == 2, 'check: every probe SA that went in is removed again');
ok(index(k.ran[1], 'unloaded') > 0, 'check: says what it did');

// all fine: nothing done
k = kernel(() => false);
eq([ KC.check(k.opts), length(k.ran) ], [ { ok: true }, 0 ], 'check: a kernel that takes them -> nothing done');

// the module in use (the VoWiFi tunnel holds it)
k = kernel(eip);
k.busy = true;
r = KC.check(k.opts);
eq([ r.ok, r.busy ], [ false, 'crypto_hw_eip93' ], 'check: module in use -> busy, nothing unloaded');

// refused for another reason, or without a known module
k = kernel(() => 'kernel: No such file or directory');
r = KC.check(k.opts);
eq([ r.ok, length(filter(k.ran, (x) => index(x, 'rmmod') == 0)) ], [ false, 0 ], 'check: not EINVAL -> no module touched');
k = kernel((sa) => sa.enc.name == 'cbc(aes)');
delete k.loaded.crypto_hw_eip93;
eq(KC.check(k.opts).ok, false, 'check: EINVAL without a known module loaded -> reported only');

done();
