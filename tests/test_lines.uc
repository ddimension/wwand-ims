// Host tests for sipd/lines.uc: picking a line, what each line uses, the
// per-SIM overrides, the extensions of a line. Made-up identifiers.
'use strict';

import { eq, ok, done } from './lib/check.uc';
import * as L from 'sipd_lines';

let S = [ { '.name': 'ue', modem: 'wwmodem0', backend: 'ue' },
          { '.name': 'ue2', modem: 'wwmodem1', backend: 'ue', access: 'vowifi' } ];
eq(L.pick(S, null).name, 'ue', 'pick: no wish -> the first line');
eq([ L.pick(S, 'ue2').index, L.pick(S, 'wwmodem1').name ], [ 1, 'ue2' ], 'pick: by section name or by modem');
eq(L.pick(S, 'nope'), null, 'pick: an unknown line');
eq(L.for_modem(S, 'wwmodem1').name, 'ue2', 'for_modem: the section of that modem');
eq(L.for_modem([ { '.name': 'ue' } ], 'wwmodem3').name, 'ue', 'for_modem: a section without a modem (one line of before)');
eq(L.for_modem(S, 'wwmodem7'), null, 'for_modem: none');

// the first line keeps the names of a single line
let r0 = L.resources(S[0], 0, { port: '5060' });
eq([ r0.ims_iface, r0.vrf, r0.zone, r0.table, r0.vowifi_dev, r0.vowifi_iface, r0.vowifi_table, r0.vowifi_if_id,
     r0.vowifi_conn, r0.sip_port, r0.rtp_base, r0.bindings, r0.objects ],
	[ 'wwims', 'ims', 'ims', 30, 'imswifi0', 'wwvowifi', 31, 7001, 'wwand-vowifi', 5060, 40000,
	  '/var/run/wwand-ims-sipd.bindings', [ 'wwand-ims', 'wwand-ims.wwmodem0' ] ],
	'resources: line 0 as one line always was, and wwand-ims.<modem> too');
// the second gets its own
let r1 = L.resources(S[1], 1, { port: '5060', sip_trace: '/tmp/t' });
eq([ r1.ims_iface, r1.vrf, r1.table, r1.vowifi_dev, r1.vowifi_iface, r1.vowifi_table, r1.vowifi_if_id,
     r1.vowifi_conn, r1.sip_port, r1.rtp_base, r1.reqid_base, r1.bindings, r1.sip_trace, r1.objects ],
	[ 'wwims1', 'ims1', 32, 'imswifi1', 'wwvowifi1', 33, 7002, 'wwand-vowifi1', 5061, 40200, 0x1600,
	  '/var/run/wwand-ims-sipd.1.bindings', '/tmp/t.1', [ 'wwand-ims.wwmodem1' ] ],
	'resources: line 1 with names, tables, ports and files of its own');
eq(L.resources({ ...S[1], vrf: 'imsb', sip_port: '5070', table: '40' }, 1, {}).sip_port, 5070, 'resources: an option wins');
eq(L.resources({ vrf: 'imsb' }, 1, {}).zone, 'imsb', 'resources: the zone follows the VRF');

// per-SIM overrides
let SIMS = [ { '.name': 's1', iccid: '8949020', access: 'pdn' },
             { '.name': 's2', iccid: [ '894920261234567890', '89490299' ], access: 'vowifi', profile: 'vodafone_de', modem: 'x' } ];
eq(L.sim_for(SIMS, '8949020012345678901')['.name'], 's1', 'sim_for: an ICCID prefix');
eq(L.sim_for(SIMS, '894920261234567890')['.name'], 's2', 'sim_for: one of a list, exact');
eq(L.sim_for(SIMS, '8900000000000000000'), null, 'sim_for: none');
eq(L.sim_for(SIMS, null), null, 'sim_for: no ICCID');
let e = L.effective(S[0], SIMS[1]);
eq([ e.access, e.profile, e.modem, e.backend, e['.name'] ], [ 'vowifi', 'vodafone_de', 'wwmodem0', 'ue', 'ue' ],
	'effective: the SIM\'s options over the line\'s, the line\'s own name and modem kept');
eq(L.effective(S[1], null), S[1], 'effective: no SIM section -> the line as it is');

// extensions
let X = [ { username: 'a' }, { username: 'b', line: 'ue2' }, { username: 'c', line: 'ue' } ];
eq(map(L.extensions(X, 'ue', 0), (x) => x.username), [ 'a', 'c' ], 'extensions: line 0 takes those without a line');
eq(map(L.extensions(X, 'ue2', 1), (x) => x.username), [ 'b' ], 'extensions: line 1 only its own');

done();
