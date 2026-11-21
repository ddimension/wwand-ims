#!/usr/bin/env ucode
// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// The program strongSwan's ext-aka plugin runs (vowifi/card.uc does the
// work): /usr/libexec/strongswan/ext-aka, a wrapper that starts this with
// the wwand-ims module path. charon reads its stdout only: what happened
// goes to syslog (ident wwand-ims-vowifi), never the keys or RES.

'use strict';

import * as ubus from 'ubus';
import * as logmod from 'wwand.log';
import * as CARD from 'vowifi_card';

let _io = null;
try { _io = require('wwand_io'); } catch (e) { _io = null; }
logmod.open(_io, { ident: 'wwand-ims-vowifi', level: 'info' });

let bus = ubus.connect();
if (!bus) {
	logmod.log('err', '%s', 'ext-aka: no ubus');
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
	if (err) {
		logmod.log('warn', '%s', err);
		warn(err, '\n');
	}
	else if (length(lines) == 1)
		logmod.log('info', '%s', 'ext-aka: the USIM reports a sequence number out of sync (AUTS for resynchronisation)');
	else
		logmod.log('info', '%s', 'ext-aka: AUTHENTICATE on the USIM done (RES, CK, IK to charon)');
});
exit(code);
