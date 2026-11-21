// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// The operator profile (`config ims_profile` in /etc/config/wwand_ims) for
// the router's own IMS UE: which one belongs to the SIM, and its values in
// the shape sipd/line_ue.uc, ue/reg.uc and sipd/relay.uc take them.
//
//   let p = PROFILE.select(sections, 'auto' | name, { imsi, iccid })   -> section or null
//   let u = PROFILE.ue_opts(p)   -> { name, t1, t2, expires, algs, ealgs, user_agent,
//                                     pcscf_port, reg_event, udp, tcp, rtp_timeout,
//                                     rtcp_timeout, alert_delay, sms_smsc, sms_psi,
//                                     warn: [ ... ] }
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
		alert_delay: num(p?.alert_delay_ms) ?? ALERT_DELAY,
		sms_smsc: match(p?.sms_smsc ?? '', /^\+?[0-9]{3,20}$/) ? p.sms_smsc : null,
		sms_psi: p?.sms_psi };
	if (p?.sms_smsc != null && !u.sms_smsc)
		push(u.warn, sprintf('sms_smsc %s is not a number, left out', p.sms_smsc));

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

// ---- a profile from what is in use now ------------------------------------------------
//
// snapshot(src) -> { name, options }: a new `config ims_profile` from the
// modem's carrier configuration and what the network gave the UE, for
// LuCI's "clone from current settings". src (sipd's profile_snapshot):
//   { imsi, plmn: { mcc, mnc, mnc_digits, description }, mbn (active
//     carrier config name), ims_apn: { apn, pdp_type } (the IMCN profile),
//     selection: { voice_domain, usage } (NAS), ue: line.status(),
//     prof: line.profile(), smsc, date }
// What is not known is left out, so the built-in default stays.

const EALG_OPTION = { 'null': 'null', 'aes-cbc': 'aes', 'des-ede3-cbc': '3des' };
// libqmi 1.38 QmiNasVoiceDomainPreference / QmiNasUsagePreference
const VOICE_DOMAIN = { '0': 'cs_only', '1': 'ps_only', '2': 'cs_preferred', '3': 'ps_preferred' };
const USAGE = { '1': 'voice_centric', '2': 'data_centric' };
// libqmi 1.38 QmiWdsPdpType (modem_profiles)
const PDP = { '0': 'ipv4', '2': 'ipv6', '3': 'ipv4v6' };

function enum_of(table, v)
{
	return (v != null) ? table[sprintf('%d', +v)] : null;
}

export function snapshot(src)
{
	let o = {};
	let p = src?.plmn;
	let mnc = (p?.mnc != null) ? sprintf('%d', +p.mnc) : null;
	while (mnc != null && length(mnc) < (p.mnc_digits ?? 2))
		mnc = '0' + mnc;
	let plmn = (p?.mcc != null && mnc) ? sprintf('%03d%s', +p.mcc, mnc) : substr(src?.imsi ?? '', 0, 5);
	let who = p?.description ?? (length(plmn) ? plmn : 'operator');

	o.label = sprintf('%s (from the modem and the network%s)', who, src?.date ? ', ' + src.date : '');
	if (length(plmn ?? ''))
		o.match_imsi = [ plmn ];

	// the carrier configuration
	if (src?.mbn)
		o.mbn = src.mbn;
	if (src?.ims_apn?.apn)
		o.ims_apn = src.ims_apn.apn;
	let pdp = enum_of(PDP, src?.ims_apn?.pdp_type);
	if (pdp)
		o.ims_pdp_type = pdp;
	let vd = enum_of(VOICE_DOMAIN, src?.selection?.voice_domain);
	if (vd)
		o.voice_domain = vd;
	let us = enum_of(USAGE, src?.selection?.usage);
	if (us)
		o.usage = us;

	// what the network gave the UE
	let ue = src?.ue, prof = src?.prof ?? {};
	let dom = match(ue?.impu ?? '', /@([^;>]+)/);
	if (dom)
		o.domain = dom[1];
	if (ue?.sec?.alg)
		o.ipsec_integrity = ue.sec.alg;
	if (ue?.sec?.ealg && EALG_OPTION[ue.sec.ealg])
		o.ipsec_encryption = [ EALG_OPTION[ue.sec.ealg] ];
	if (ue?.expires)
		o.reg_expires = sprintf('%d', +ue.expires);
	if (ue?.reg_event)
		o.reg_event = (ue.reg_event == 'active') ? '1' : '0';
	o.auth = 'akav1-md5';

	// the UE's own values in use (the profile it runs on, else its defaults)
	o.sip_t1_ms = sprintf('%d', prof.t1 ?? 500);
	o.sip_t2_s = sprintf('%d', int((prof.t2 ?? 4000) / 1000));
	o.sip_transport = (prof.tcp === false) ? 'udp' : 'udp,tcp';
	if (prof.user_agent)
		o.user_agent = prof.user_agent;
	if (prof.pcscf_port)
		o.pcscf_port = sprintf('%d', prof.pcscf_port);
	if (prof.alert_delay != null)
		o.alert_delay_ms = sprintf('%d', prof.alert_delay);
	if (prof.rtp_timeout != null)
		o.rtp_timeout_s = sprintf('%d', prof.rtp_timeout);
	if (src?.smsc)
		o.sms_smsc = src.smsc;
	if (prof.sms_psi)
		o.sms_psi = prof.sms_psi;

	// VoWiFi: the carrier config's IWLAN settings (ims_iwlan options():
	// { opts, lists })
	for (let k, v in src?.vowifi?.opts ?? {})
		o[k] = v;
	for (let k, v in src?.vowifi?.lists ?? {})
		o[k] = v;

	// a uci section name: letters, digits, underscore
	let name = lc(replace(who, /[^A-Za-z0-9]+/g, '_'));
	name = replace(replace(name, /^_+/, ''), /_+$/, '');
	if (!length(name) || match(name, /^[0-9]/))
		name = 'op_' + name;
	return { name: name, options: o };
}
