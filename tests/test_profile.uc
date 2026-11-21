// Host tests for sipd/profile.uc: which `config ims_profile` belongs to a
// SIM, its values in the UE's terms, and that they reach the REGISTER.
// All identifiers are made-up example values.
'use strict';

import { eq, ok, done } from './lib/check.uc';
import * as PROFILE from 'sipd_profile';
import * as REG from 'ue_reg';
import * as LINE from 'sipd_line_ue';

let SIP = require('sipd_sip');

// sections as uci's foreach hands them over
let P = [
	{ '.name': 'broad', match_imsi: '262' },
	{ '.name': 'op_a', match_imsi: [ '26299', '90199' ], match_iccid: '8949990',
	  sip_t1_ms: '2000', sip_t2_s: '16', reg_expires: '3600',
	  ipsec_integrity: 'hmac-sha-1-96', ipsec_encryption: [ 'null', 'aes' ],
	  sip_transport: 'udp,tcp', reg_event: '1', auth: 'akav1-md5' },
	{ '.name': 'op_a_m2m', match_imsi: '2629955' },
	{ '.name': 'unmatched', sip_t1_ms: '700' },
];

// ---- select -----------------------------------------------------------------------

eq(PROFILE.list_of('a, b c'), [ 'a', 'b', 'c' ], 'list_of: commas and blanks');
eq(PROFILE.list_of([ 'a', 'b,c' ]), [ 'a', 'b', 'c' ], 'list_of: a uci list');
eq(PROFILE.list_of(null), [], 'list_of: nothing');

let name = (p) => p?.['.name'];
eq(name(PROFILE.select(P, 'auto', { imsi: '262991234567890' })), 'op_a', 'auto: the longer IMSI prefix wins');
eq(name(PROFILE.select(P, null, { imsi: '262995534567890' })), 'op_a_m2m', 'no option = auto; longest of all');
eq(name(PROFILE.select(P, 'auto', { imsi: '262011234567890' })), 'broad', 'auto: the broad one is the fallback');
eq(name(PROFILE.select(P, 'auto', { imsi: '901991234567890' })), 'op_a', 'auto: any prefix of a list');
eq(name(PROFILE.select(P, 'auto', { imsi: '310150123456789', iccid: '89499901234567890123' })), 'op_a',
	'auto: by ICCID when the IMSI matches nothing');
eq(PROFILE.select(P, 'auto', { imsi: '310150123456789', iccid: '8901' }), null, 'auto: no match, no profile');
eq(PROFILE.select(P, 'auto', {}), null, 'auto: no SIM read yet, no profile');
eq(name(PROFILE.select(P, 'unmatched', { imsi: '310150123456789' })), 'unmatched', 'a name picks that profile');
eq(PROFILE.select(P, 'nosuch', { imsi: '262991234567890' }), null, 'a name that is not there: none, not a guess');
eq(PROFILE.select(null, 'auto', { imsi: '262991234567890' }), null, 'no profiles configured');

// ---- ue_opts ------------------------------------------------------------------------

let u = PROFILE.ue_opts(P[1]);
eq([ u.name, u.t1, u.t2, u.expires ], [ 'op_a', 2000, 16000, 3600 ], 'T1 in ms, T2 in ms from seconds, expiry');
eq(u.algs, [ 'hmac-sha-1-96' ], 'integrity as configured');
eq(u.ealgs, [ 'null', 'aes-cbc' ], 'encryption: aes is aes-cbc on the wire');
eq([ u.udp, u.tcp, u.reg_event ], [ true, true, true ], 'transport and reg-event');
eq(u.warn, [], 'nothing to complain about');

let d = PROFILE.ue_opts(null);
eq([ d.name, d.t1, d.t2, d.expires, d.algs, d.ealgs, d.user_agent, d.pcscf_port, d.rtp_timeout ],
	[ null, null, null, null, null, null, null, null, null ], 'no profile: every value left to the UE default');
eq([ d.udp, d.tcp, d.reg_event ], [ true, true, true ], 'no profile: UDP and TCP, reg-event on');

let w = PROFILE.ue_opts({ '.name': 'odd', ipsec_integrity: 'hmac-sha2-256-128', ipsec_encryption: 'aes-gcm, 3des',
	sip_transport: 'tcp', auth: 'akav2-md5', reg_event: '0', user_agent: 'Example-UE/1.0', pcscf_port: '5070',
	rtp_timeout_s: '0', rtcp_timeout_s: '45', sip_t1_ms: '3000', sip_t2_s: '2', alert_delay_ms: '4000' });
eq(w.algs, null, 'no supported integrity: the UE defaults, not an empty offer');
eq(w.ealgs, [ 'des-ede3-cbc' ], 'the supported cipher stays, the unknown one goes');
eq([ w.udp, w.tcp ], [ true, true ], 'tcp only: listened on, requests still over UDP');
eq(w.reg_event, false, 'reg_event 0');
eq([ w.user_agent, w.pcscf_port, w.rtp_timeout, w.rtcp_timeout ], [ 'Example-UE/1.0', 5070, 0, 45 ],
	'User-Agent, P-CSCF port, media timeouts (0 = off is kept)');
eq([ w.t1, w.t2 ], [ 3000, 3000 ], 'T2 never below T1');
eq([ w.alert_delay, d.alert_delay ], [ 4000, 4500 ], 'alert_delay_ms; 4.5 s without a profile');
let sp = PROFILE.ue_opts({ sms_smsc: '+4917000000', sms_psi: 'sip:%s@ims.example.net;user=phone' });
eq([ sp.sms_smsc, sp.sms_psi, d.sms_smsc ], [ '+4917000000', 'sip:%s@ims.example.net;user=phone', null ],
	'sms_smsc and sms_psi; none without a profile');
let sp2 = PROFILE.ue_opts({ sms_smsc: '+49 170' });
ok(sp2.sms_smsc == null && length(filter(sp2.warn, (x) => index(x, 'sms_smsc') == 0)) == 1, 'sms_smsc not a number: left out, warned');
let long_delay = PROFILE.ue_opts({ alert_delay_ms: '6000' });
ok(long_delay.alert_delay == 6000 && length(filter(long_delay.warn, (x) => index(x, 'alert_delay_ms 6000') == 0)) == 1,
	'alert_delay_ms above 5 s: kept, with a warning');
eq(PROFILE.ue_opts({ alert_delay_ms: '0' }).alert_delay, 0, 'alert_delay_ms 0: the 180 at once');
eq(length(w.warn), 5, 'one warning per thing that could not be honoured');
eq(PROFILE.ue_opts({ sip_transport: 'udp' }).tcp, false, 'udp only: no TCP listener');

// ---- the values reach the REGISTER ---------------------------------------------------

let sent = [], timers = [];
let xfrm = { n: 0x2000 };
xfrm.alloc_spi = () => ++xfrm.n;
xfrm.sa_add = () => true;
xfrm.sa_del = () => true;
xfrm.policy_add = () => true;
xfrm.policy_del = () => true;
xfrm.error = () => null;

let reg = REG.create({
	imsi: '262991234567890', mnc_len: 2, imei: '353456789012345',
	ue_addr: '2001:db8::5', pcscf_addr: '2001:db8:ff::10', port_c: 5062, port_s: 5064,
	card: {}, xfrm: xfrm, pani: 'x',
	timer: (ms, fn) => { push(timers, ms); return { cancel: () => null }; },
	send: (buf, dst, port, src) => push(sent, { msg: SIP.parse(buf), port: port }),
	t1: w.t1, t2: w.t2, expires: u.expires, algs: u.algs, ealgs: u.ealgs,
	user_agent: w.user_agent, pcscf_port: w.pcscf_port,
});
reg.start(() => null);
let m = sent[0].msg;
eq(sent[0].port, 5070, 'REGISTER to the profile\'s P-CSCF port');
eq(SIP.get(m, 'expires'), '3600', 'REGISTER asks for the profile\'s expiry');
eq(SIP.get(m, 'user-agent'), 'Example-UE/1.0', 'REGISTER carries the profile\'s User-Agent');
let sc = SIP.get(m, 'security-client');
ok(index(sc, 'alg=hmac-sha-1-96;ealg=null') >= 0 && index(sc, 'alg=hmac-sha-1-96;ealg=aes-cbc') >= 0 &&
	index(sc, 'hmac-md5-96') < 0 && index(sc, 'des-ede3-cbc') < 0,
	'Security-Client offers exactly the profile\'s algorithms');
eq(sort(timers), [ 3000, 192000 ], 'Timer E starts at the profile\'s T1, Timer F is 64*T1');

// ---- P-CSCF failover helpers (sipd/line_ue.uc) ------------------------------------------

eq(LINE.pcscf_failed({ error: 'timeout', state: 'unprotected' }), true, 'failover: nobody answered');
eq(LINE.pcscf_failed({ error: 'status', status: 503 }), true, 'failover: a server error');
eq(LINE.pcscf_failed({ error: 'status', status: 403 }), false, 'no failover: a 403 is about us');
eq(LINE.pcscf_failed({ error: 'aka', detail: 'x' }), false, 'no failover: the card');
eq(LINE.pcscf_failed({ error: 'bind: Address in use' }), false, 'no failover: a local error');
let L = [ '2001:db8:ff::10', '2001:db8:ff::11' ];
eq([ LINE.pcscf_pick(L, 0), LINE.pcscf_pick(L, 1), LINE.pcscf_pick(L, 2) ], [ L[0], L[1], L[0] ],
	'pick: round robin over the PDN\'s list');
eq(LINE.pcscf_pick([], 3), null, 'pick: an empty list');

done();
