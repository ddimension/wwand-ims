#!/usr/bin/env ucode
// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// The program strongSwan's ext-aka plugin runs (vowifi/card.uc does the
// work): /usr/libexec/strongswan/ext-aka, a wrapper that starts this with
// the wwand-ims module path.

'use strict';

import * as ubus from 'ubus';
import * as CARD from 'vowifi_card';

let bus = ubus.connect();
if (!bus) {
	warn('ext-aka: no ubus\n');
	exit(1);
}

// a synchronous ubus call in the shape card.uc wants
let call = (obj, method, args, cb) => {
	let r = bus.call(obj, method, args);
	if (r == null)
		return cb({ error: 'ubus', detail: ubus.error() }, null);
	if (r?.ok === false)
		return cb(r, null);
	cb(null, r);
};

let code = 1;
CARD.run(ARGV, call, (c, lines, err) => {
	code = c;
	for (let l in lines)
		print(l, '\n');
	if (err)
		warn(err, '\n');
});
exit(code);
