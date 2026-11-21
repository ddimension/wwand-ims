// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// Several IMS lines, one per modem: every `config ims_modem` section is a
// line, run by an instance of sipd of its own (files/wwand-ims-sipd.init,
// `sipd.uc --line <section>`). What a line uses is derived from its position
// among the ims_modem sections, so the first one keeps the names a single
// line always had and the others get their own; an option in the section
// wins over the derived value. `wwandctl ims <modem> setup` derives the same.
//
// A SIM can override its line (`config ims_sim`, option iccid — one or a
// list, a prefix matches, the longest wins): access, profile, smsip, epdg,
// vowifi_*, ... — the card's own choice over the modem's. Precedence of a
// value: ims_sim (ICCID) > ims_modem > ims_profile (operator, by IMSI) >
// built-in.

'use strict';

// the line for `want` (a section name or a modem name), or the first one:
// { name, index, im } or null
export function pick(sections, want)
{
	for (let i, s in sections ?? [])
		if (want == null || s['.name'] == want || s.modem == want)
			return { name: s['.name'], index: i, im: s };
	return null;
}

// the line of a modem: by option modem, else a section without one (the
// single-line config of before, which applied to whatever modem)
export function for_modem(sections, modem)
{
	for (let i, s in sections ?? [])
		if (s.modem == modem)
			return { name: s['.name'], index: i, im: s };
	for (let i, s in sections ?? [])
		if (s.modem == null)
			return { name: s['.name'], index: i, im: s };
	return null;
}

function nth(base, i)
{
	return (i == 0) ? base : sprintf('%s%d', base, i);
}

function num(v, dflt)
{
	return (v != null && match(sprintf('%s', v), /^[0-9]+$/)) ? +v : dflt;
}

// what line `i` uses: names, tables, ports, files, the ubus objects
export function resources(im, i, gw)
{
	im ??= {};
	i ??= 0;
	let vrf = im.vrf ?? nth('ims', i);
	return {
		index: i,
		modem: im.modem,
		// the IMS PDN: its interface, VRF (also the firewall zone) and table
		ims_iface: im.ims_iface ?? nth('wwims', i),
		vrf: vrf,
		zone: im.zone ?? vrf,
		table: num(im.table, 30 + 2 * i),
		// VoWiFi: the tunnel's interfaces, table, if_id and charon connection
		vowifi_dev: im.vowifi_dev ?? sprintf('imswifi%d', i),
		vowifi_iface: im.vowifi_iface ?? nth('wwvowifi', i),
		vowifi_table: num(im.vowifi_table, 31 + 2 * i),
		vowifi_if_id: num(im.vowifi_if_id, 7001 + i),
		vowifi_zone: im.vowifi_zone ?? im.zone ?? vrf,
		vowifi_conn: nth('wwand-vowifi', i),
		// the phones' SIP port, the RTP relay's range, the sec-agree SAs' reqids
		sip_port: num(im.sip_port, num(gw?.port, 5060) + i),
		rtp_base: num(im.rtp_base, 40000 + 200 * i),
		rtp_span: num(im.rtp_span, 200),
		reqid_base: 0x1500 + 0x100 * i,
		// the files a line keeps (the first one's names as before)
		bindings: (i == 0) ? '/var/run/wwand-ims-sipd.bindings' : sprintf('/var/run/wwand-ims-sipd.%d.bindings', i),
		history: (i == 0) ? (gw?.call_history ?? '/var/run/wwand-ims-sipd.calls')
		                  : sprintf('%s.%d', gw?.call_history ?? '/var/run/wwand-ims-sipd.calls', i),
		sip_trace: gw?.sip_trace ? ((i == 0) ? gw.sip_trace : sprintf('%s.%d', gw.sip_trace, i)) : null,
		// ubus: every line as wwand-ims.<modem>, the first also as wwand-ims
		objects: (i == 0) ? [ 'wwand-ims', sprintf('wwand-ims.%s', im.modem ?? 'wwmodem0') ]
		                  : [ sprintf('wwand-ims.%s', im.modem ?? sprintf('wwmodem%d', i)) ],
	};
}

function iccids(v)
{
	return (type(v) == 'array') ? v : split(sprintf('%s', v ?? ''), /[ ,]+/);
}

// the ims_sim section for this card, or null (the longest ICCID prefix)
export function sim_for(sims, iccid)
{
	if (!iccid)
		return null;
	let best = null, len = 0;
	for (let s in sims ?? [])
		for (let pre in iccids(s.iccid))
			if (length(pre) && index(iccid, pre) == 0 && length(pre) > len) {
				best = s;
				len = length(pre);
			}
	return best;
}

// the options a SIM overrides; never the ones that name the line itself
const NOT_OVERRIDDEN = { '.name': 1, '.type': 1, '.anonymous': 1, '.index': 1, iccid: 1, modem: 1, label: 1 };

// the line's ims_modem with the SIM's overrides over it
export function effective(im, sim)
{
	let out = { ...(im ?? {}) };
	for (let k, v in sim ?? {})
		if (!NOT_OVERRIDDEN[k])
			out[k] = v;
	return out;
}

// the extensions of a line: option line names it; without one an extension
// belongs to the first line
export function extensions(exts, line_name, line_index)
{
	return filter(exts ?? [], (e) => (e.line != null) ? (e.line == line_name) : (line_index == 0));
}
