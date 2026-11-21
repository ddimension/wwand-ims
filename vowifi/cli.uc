#!/usr/bin/env ucode
// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// The VoWiFi tunnel by hand, without sipd: for bringing it up on a new
// network and looking at what the ePDG says.
//
//   wwand-ims-vowifi up [modem] [epdg]     load the connection, start it, wait
//   wwand-ims-vowifi down                  end it, remove the interface
//   wwand-ims-vowifi status                charon's view (list-sas)
//
// charon must run (the swanctl service starts it, idle) with the ext-aka
// plugin; the identity comes from the modem's IMSI in wwand.

'use strict';

import * as uloop from 'uloop';
import * as ubus from 'ubus';
import * as socket from 'socket';
import * as VICI from 'vowifi_vici';
import * as CTL from 'vowifi_ctl';
import * as TUN from 'vowifi_tunnel';
import { home_mnc_len } from 'sipd_line_ue';

let op = ARGV[0] ?? 'status';
uloop.init();
let log = (lvl, msg) => warn(sprintf('%s: %s\n', lvl, msg));
let vici = VICI.create({ socket: socket, uloop: uloop, log: log });
let code = 0;

let ctl_for = (modem, epdg) => {
	let bus = ubus.connect();
	let st = bus?.call('wwand', 'status', {});
	let names = sort(keys(st?.modems ?? {}));
	modem ??= names[0];
	let m = st?.modems?.[modem];
	if (!m?.imsi)
		die(sprintf('no modem %s with an IMSI in wwand\n', modem ?? '?'));
	return CTL.create({ vici: vici, uloop: uloop, log: log, run: (argv) => system(argv),
		imsi: m.imsi, mnc_len: home_mnc_len(m), if_id: 7001, dev: 'imswifi0', vrf: 'imswifi', table: 31,
		epdg: epdg });
};

if (op == 'up') {
	let t = ctl_for(ARGV[1], ARGV[2]);
	t.start((err) => {
		if (err)
			code = 1;
		printf('%.J\n', err ? { error: err, status: t.status() } : t.status());
		uloop.end();
	});
}
else if (op == 'down') {
	let t = ctl_for(ARGV[1]);
	t.stop(() => uloop.end());
}
else if (op == 'status') {
	let sas = [];
	vici.stream('list-sas', {}, 'list-sa', (m) => push(sas, m), (err) => {
		printf('%.J\n', err ? { error: err } : sas);
		uloop.end();
	});
}
else {
	warn('usage: wwand-ims-vowifi up [modem] [epdg] | down | status\n');
	exit(2);
}
uloop.run();
vici.close();
exit(code);
