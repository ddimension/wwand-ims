// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// VoWiFi from the carrier config: /data/iwlan_s2b_config.xml — parse it and
// turn it into ims_profile options (vowifi_*). Used by `wwandctl ims setup`
// (ctl/ims.uc) and sipd's profile_snapshot (LuCI "Clone current settings").
// An ES module (bytecode in the package): /usr/share/wwand-ims/ims_iwlan.uc.

'use strict';

import * as fs from 'fs';
import * as DIAG from 'ims_diag';

// The carrier MBN carries the modem's own IWLAN (S2b, ePDG) settings as an
// EFS file. Measured in Vodafone DE's (Germany-VoLTE-Vodafone, a Pixel 3A
// MBN, 2026-11-21): <GENERIC_VARIANT><ikev2_info> with ikev2_dh_group_list
// (14, 2, 5 — MODP_2048 first, what Vodafone's ePDG then demanded),
// ikev2_hash_algo_list, esp_auth_algo_list, ikev2_sa_rekey_timer /
// esp_rekey_timer (soft_sec), dpd_info, peer_id; <epdg_addr_info> with
// static_fqdn_enabled. The numbers are the IANA IKEv2 transform ids (RFC
// 7296 3.3.2); what is not named here is left out, charon's own defaults
// follow the MBN's proposal.

const IANA_DH = { '1': 'modp768', '2': 'modp1024', '5': 'modp1536', '14': 'modp2048', '15': 'modp3072',
                  '16': 'modp4096', '17': 'modp6144', '18': 'modp8192', '19': 'ecp256', '20': 'ecp384',
                  '21': 'ecp521', '31': 'curve25519', '32': 'curve448' };
const IANA_INTEG = { '1': 'md5', '2': 'sha1', '5': 'aesxcbc', '12': 'sha256', '13': 'sha384', '14': 'sha512' };
const IANA_ENCR = { '3': '3des', '12': 'aes', '13': 'aesctr', '20': 'aes256gcm16', '19': 'aes256gcm12' };

// the values of <tag> list entries (<algo value="2"/>, <dh_group value="14"/>)
function xml_values(xml, list)
{
	let m = match(xml, regexp('<' + list + '>(.*)</' + list + '>'));
	if (!m)
		return [];
	return map(match(m[1], /value="([0-9]+)"/g) ?? [], (x) => x[1]);
}

function xml_text(xml, tag)
{
	let m = match(xml, regexp('<' + tag + '>[ \t\r\n]*([^<]*)</' + tag + '>'));
	return m ? trim(m[1]) : null;
}

// the GENERIC_VARIANT of an iwlan_s2b_config.xml: what VoWiFi needs
export function parse(xml)
{
	if (!match(xml ?? '', /<IWLAN_S2B_CONFIG>/))
		return null;
	xml = replace(xml, /[\r\n]+/g, ' ');
	let g = match(xml, /<GENERIC_VARIANT>(.*)<\/GENERIC_VARIANT>/);
	g = g ? g[1] : xml;
	let ike = match(g, /<ikev2_info>(.*)<\/ikev2_info>/);
	ike = ike ? ike[1] : g;
	let section = (tag) => { let m = match(ike, regexp('<' + tag + '>(.*)</' + tag + '>')); return m ? m[1] : ''; };
	let peer = section('peer_id');
	let addr = match(g, /<epdg_addr_info>(.*)<\/epdg_addr_info>/);
	addr = addr ? addr[1] : '';
	return {
		dh: xml_values(ike, 'ikev2_dh_group_list'),
		ike_integ: xml_values(ike, 'ikev2_hash_algo_list'),
		ike_encr: xml_values(ike, 'ikev2_encr_algo_list'),
		esp_integ: xml_values(ike, 'esp_auth_algo_list'),
		esp_encr: xml_values(ike, 'esp_encr_algo_list'),
		ike_rekey_s: xml_text(section('ikev2_sa_rekey_timer'), 'soft_sec'),
		esp_rekey_s: xml_text(section('esp_rekey_timer'), 'soft_sec'),
		dpd: xml_text(section('dpd_info'), 'liveness_check_enabled'),
		peer_id_type: xml_text(peer, 'id_type'),
		peer_id: xml_text(peer, 'identifier'),
		static_fqdn: (xml_text(addr, 'static_fqdn_enabled') == 'TRUE') ? xml_text(addr, 'fqdn') : null,
	};
}

// one strongSwan proposal from IANA ids: encryption-integrity-groups
export function proposal(encr, integ, dh)
{
	let e = filter(map(encr, (x) => (x == '12') ? null : IANA_ENCR[x]), (x) => x != null);
	if (index(encr, '12') >= 0 || !length(encr))
		e = [ ...e, 'aes256', 'aes128' ];
	let i = filter(map(integ, (x) => IANA_INTEG[x]), (x) => x != null);
	let d = filter(map(dh, (x) => IANA_DH[x]), (x) => x != null);
	if (!length(i) && !length(d))
		return null;
	return join('-', [ ...uniq(e), ...(length(i) ? i : [ 'sha256', 'sha1' ]), ...d ]);
}

// the ims_profile options from a parsed iwlan config (vowifi_*): the MBN's
// proposal first, charon's defaults after it
export function options(x)
{
	if (!x)
		return {};
	let o = {}, lists = {};
	let ike = proposal(x.ike_encr, x.ike_integ, x.dh);
	if (ike)
		lists.vowifi_proposals = [ ike, 'default' ];
	let esp = length(x.esp_integ) ? proposal(x.esp_encr, x.esp_integ, []) : null;
	if (esp)
		lists.vowifi_esp_proposals = [ esp, 'default' ];
	if (x.ike_rekey_s && +x.ike_rekey_s > 0)
		o.vowifi_rekey_s = x.ike_rekey_s;
	if (x.esp_rekey_s && +x.esp_rekey_s > 0)
		o.vowifi_esp_rekey_s = x.esp_rekey_s;
	if (x.dpd == 'FALSE')
		o.vowifi_dpd_s = '0';
	if (x.peer_id)
		o.vowifi_apn = x.peer_id;
	if (x.static_fqdn)
		o.vowifi_epdg = x.static_fqdn;
	return { opts: o, lists: lists };
}

// the iwlan config of the active carrier config: from a base MBN file
// (--mbn FILE, the file the firmware image holds), else from the modem's
// EFS — over Quectel's AT+QNVFR (through the daemon's AT port; read-only,
// the file as hex; HW: RG502Q 2026-11-21), else over the DIAG port
// (ctl/diag.uc, any Qualcomm modem; not while QLog holds the port)
export const EFS_PATH = '/data/iwlan_s2b_config.xml';
const IWLAN_EFS = EFS_PATH;
function read_diag(call, modem)
{
	let st = call('status', {});
	let port = st?.modems?.[modem]?.diag_port;
	if (!port)
		return { via: 'DIAG', xml: null, why: 'no DIAG port known' };
	if (system('pidof qlog >/dev/null 2>&1') == 0)
		return { via: 'DIAG ' + port, xml: null, why: 'QLog holds the DIAG port' };
	let io = null;
	try { io = require('wwand_io'); } catch (e) { io = null; }
	if (!io)
		return { via: 'DIAG ' + port, xml: null, why: 'no wwand_io' };
	let r = DIAG.efs_read(io, port, IWLAN_EFS);
	return { via: 'DIAG ' + port, xml: r.data, why: r.error ? sprintf('%s: %s', r.error, r.detail) : null };
}
function mcfg_lib()
{
	try { return require('wwand.ims_mcfg'); }
	catch (e) { return require('ims_mcfg'); }
}

// where it comes from: opts.mbn (a base MBN file), else the modem's EFS over
// AT+QNVFR, else DIAG. call(method, args): a ubus call to wwand.
export function read(call, modem, opts)
{
	if (opts.mbn) {
		let L = mcfg_lib();
		let buf = fs.readfile(opts.mbn);
		if (buf == null)
			return { via: 'mbn ' + opts.mbn, xml: null, why: 'cannot read the file' };
		let p = L.parse(buf);
		// several items of the same path (per subscription): the first one
		for (let it in p.items)
			if (it.path == IWLAN_EFS && length(it.data ?? '') > 16)
				return { via: 'mbn ' + opts.mbn, xml: substr(it.data, 1) };
		return { via: 'mbn ' + opts.mbn, xml: null };
	}
	let r = call('modem_at', { modem: modem, command: sprintf('AT+QNVFR="%s"', IWLAN_EFS), timeout: 5000 });
	for (let l in r?.lines ?? r?.response ?? []) {
		let m = match(l, /^\+QNVFR:[ \t]*"?([0-9A-Fa-f]+)"?/);
		if (m) {
			let raw = '';
			for (let i = 0; i + 1 < length(m[1]); i += 2)
				raw += chr(hex(substr(m[1], i, 2)));
			return { via: 'modem EFS (AT+QNVFR)', xml: raw };
		}
	}
	return read_diag(call, modem);
}
