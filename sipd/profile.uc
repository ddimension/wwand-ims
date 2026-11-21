// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// The operator profile (`config ims_profile` in /etc/config/wwand_ims) for
// the router's own IMS UE: which one belongs to the SIM, and its values in
// the shape sipd/line_ue.uc, ue/reg.uc and sipd/relay.uc take them.
//
//   let p = PROFILE.select(sections, 'auto' | name, { imsi, iccid })   -> section or null
//   let u = PROFILE.ue_opts(p)   -> { name, t1, t2, expires, algs, ealgs, user_agent,
//                                     pcscf_port, reg_event, udp, tcp, rtp_timeout,
//                                     rtcp_timeout, alert_delay, warn: [ ... ] }
//
// A value the profile does not set is null: the UE's own default applies
// (alert_delay: 4.5 s, see ALERT_DELAY).

'use strict';

import * as SA from 'ue_secagree';

// what a profile may call the ESP ciphers (the config says 'aes', the
// Security-Client header 'aes-cbc', RFC 3329 / TS 33.203 Annex H)
const EALG_NAMES = { 'null': 'null', 'aes': 'aes-cbc', 'aes-cbc': 'aes-cbc',
	'3des': 'des-ede3-cbc', 'des-ede3-cbc': 'des-ede3-cbc' };

// a uci option or list as a list: 'a,b', 'a b' and [ 'a', 'b' ] alike
export function list_of(v)
{
	if (v == null)
		return [];
	let out = [];
	for (let x in (type(v) == 'array') ? v : [ v ])
		for (let y in split(sprintf('%s', x), /[, \t]+/))
			if (length(y))
				push(out, y);
	return out;
}

// the longest prefix in `prefixes` that `id` starts with, as its length (0: none)
function prefix_len(prefixes, id)
{
	let best = 0;
	if (!length(id ?? ''))
		return 0;
	for (let p in list_of(prefixes))
		if (length(p) > best && substr(id, 0, length(p)) == p)
			best = length(p);
	return best;
}

// The profile for a SIM. `want` is ims_modem's `profile`: a section name
// picks that one (null if there is none), 'auto' or nothing matches by the
// SIM: the longest match_imsi / match_iccid prefix wins, the first section
// on a tie. A profile without either never matches by itself.
export function select(profiles, want, sim)
{
	if (want != null && want != '' && want != 'auto') {
		for (let p in profiles ?? [])
			if (p['.name'] == want)
				return p;
		return null;
	}
	let best = null, best_len = 0;
	for (let p in profiles ?? []) {
		let n = max(prefix_len(p.match_imsi, sim?.imsi), prefix_len(p.match_iccid, sim?.iccid));
		if (n > best_len) {
			best = p;
			best_len = n;
		}
	}
	return best;
}

// our 180 to an incoming call this late by default (ms). One number on
// several SIMs (Telekom MultiSIM, docs/design.md 5.6): an at-once 180 kept
// the network from alerting a phone in idle; 4 s were enough there, 4.5 s
// leave the paging some margin. Not longer than ALERT_DELAY_MAX: that
// network cancels a leg that has sent no 18x after 5.9 s (CANCEL Reason 480
// CC_NOT_REACHABLE, measured with 6 s and 8 s).
const ALERT_DELAY = 4500, ALERT_DELAY_MAX = 5000;

function num(v)
{
	return (v != null && match(sprintf('%s', v), /^[0-9]+$/)) ? +v : null;
}

function flag(v, dflt)
{
	if (v == null)
		return dflt;
	return index([ '1', 'on', 'yes', 'true', 'enabled' ], lc(sprintf('%s', v))) >= 0;
}

// the profile's values for the UE; p may be null (no profile: all defaults)
export function ue_opts(p)
{
	let u = { name: p?.['.name'], warn: [],
		t1: null, t2: null, expires: null, algs: null, ealgs: null,
		user_agent: p?.user_agent, pcscf_port: num(p?.pcscf_port),
		reg_event: flag(p?.reg_event, true), udp: true, tcp: true,
		rtp_timeout: num(p?.rtp_timeout_s), rtcp_timeout: num(p?.rtcp_timeout_s),
		alert_delay: num(p?.alert_delay_ms) ?? ALERT_DELAY };

	let t1 = num(p?.sip_t1_ms), t2 = num(p?.sip_t2_s), exp = num(p?.reg_expires);
	if (t1)
		u.t1 = t1;
	if (t2)
		u.t2 = t2 * 1000;
	if (u.t1 && u.t2 && u.t2 < u.t1)
		u.t2 = u.t1;
	if (exp)
		u.expires = exp;

	let algs = [], ealgs = [];
	for (let a in list_of(p?.ipsec_integrity)) {
		if (SA.ALGS[lc(a)])
			push(algs, lc(a));
		else
			push(u.warn, sprintf('ipsec_integrity %s is not supported, left out', a));
	}
	for (let e in list_of(p?.ipsec_encryption)) {
		let n = EALG_NAMES[lc(e)];
		if (n && SA.EALGS[n]) {
			if (index(ealgs, n) < 0)
				push(ealgs, n);
		}
		else
			push(u.warn, sprintf('ipsec_encryption %s is not supported, left out', e));
	}
	// nothing usable left: the UE's own list, or sec-agree could not succeed
	if (length(algs))
		u.algs = algs;
	else if (p?.ipsec_integrity != null)
		push(u.warn, 'no supported ipsec_integrity in the profile, using the defaults');
	if (length(ealgs))
		u.ealgs = ealgs;
	else if (p?.ipsec_encryption != null)
		push(u.warn, 'no supported ipsec_encryption in the profile, using the defaults');

	let tr = map(list_of(p?.sip_transport), lc);
	if (length(tr)) {
		u.udp = index(tr, 'udp') >= 0;
		u.tcp = index(tr, 'tcp') >= 0;
		if (!u.udp) {
			// ue/reg.uc and ue/call.uc send their requests over UDP
			push(u.warn, 'sip_transport without udp: the UE sends its requests over UDP all the same');
			u.udp = true;
		}
	}

	if (u.alert_delay > ALERT_DELAY_MAX)
		push(u.warn, sprintf('alert_delay_ms %d: a network may cancel the call before our 180 (Telekom: after 5.9 s)',
			u.alert_delay));

	let auth = lc(p?.auth ?? 'akav1-md5');
	if (auth != 'akav1-md5')
		push(u.warn, sprintf('auth %s is not supported, using akav1-md5', p.auth));

	return u;
}
