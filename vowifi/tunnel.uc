// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// VoWiFi: the IKEv2 tunnel to the operator's ePDG (3GPP TS 24.302, TS
// 33.402) that carries the IMS traffic of the router's UE over a fixed-line
// WAN instead of the IMS PDN. charon is driven over vici only
// (vowifi/vici.uc): the connection is loaded and started at run time,
// nothing is configured in swanctl.conf.
//
// - The ePDG: epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org (TS 23.003
//   19.4.2.9), unless a profile names one.
// - Our identity: the permanent NAI 0<IMSI>@nai.epc.mnc<MNC>.mcc<MCC>.
//   3gppnetwork.org (TS 23.003 19.3.2), authenticated with EAP-AKA by the
//   USIM (strongSwan's ext-aka plugin -> vowifi/card.uc); IDr, the APN
//   (TS 24.302 7.2.2), only when a profile names one.
// - The inner addresses: virtual IPs asked for in the configuration payload;
//   the P-CSCF addresses: RFC 7651 attributes, which strongSwan's p-cscf
//   plugin only logs ("received P-CSCF server IP …"), so they are taken
//   from vici's log events.
// - The tunnel ends on an XFRM interface (if_id) in the IMS VRF.
//
// Telekom DE (HW, 2026-11-21): MODP_4096 for the key exchange, IDr and an
// EAP-AKA request in the first IKE_AUTH answer, no certificate (EAP-only,
// RFC 5998). The P-CSCF request needs charon.plugins.p-cscf.enable.<CONN>,
// accepting the ePDG's own IDr charon.plugins.epdg-idr.connections — two
// settings vici cannot carry: files/vowifi-strongswan.conf (it names our
// connection only; charon's global settings stay untouched).

'use strict';

export const CONN = 'wwand-vowifi';

function mnc3(mnc)
{
	return sprintf('%03d', +mnc);
}

// MCC and MNC from the IMSI, the MNC length as the home network has it
export function plmn_of(imsi, mnc_len)
{
	if (!match(imsi ?? '', /^[0-9]{6,15}$/))
		return null;
	let n = (mnc_len == 3) ? 3 : 2;
	return { mcc: substr(imsi, 0, 3), mnc: substr(imsi, 3, n) };
}

export function epdg_fqdn(plmn)
{
	return sprintf('epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org', mnc3(plmn.mnc), plmn.mcc);
}

export function nai(imsi, plmn)
{
	return sprintf('0%s@nai.epc.mnc%s.mcc%s.3gppnetwork.org', imsi, mnc3(plmn.mnc), plmn.mcc);
}

// The vici load-conn message (strongSwan's swanctl.conf keys, as a tree).
// o: { imsi, plmn, conn?, epdg?, apn?, if_id, proposals?, esp_proposals?, remote_auth?,
//      rekey_s?, esp_rekey_s?, dpd_s? }
export function conn_config(o)
{
	let id = nai(o.imsi, o.plmn);
	let c = {
		version: '2',
		remote_addrs: [ o.epdg ?? epdg_fqdn(o.plmn) ],
		// the inner addresses come from the ePDG
		vips: [ '0.0.0.0', '::' ],
		if_id_in: sprintf('%d', o.if_id),
		if_id_out: sprintf('%d', o.if_id),
		encap: 'yes',
		mobike: 'no',
		// from the carrier config's iwlan settings where it has them
		// (vowifi_dpd_s, vowifi_rekey_s), else no rekeying (Telekom DE)
		dpd_delay: sprintf('%ds', o.dpd_s ?? 60),
		rekey_time: sprintf('%ds', o.rekey_s ?? 0),
		unique: 'replace',
		send_certreq: 'no',
		local: {
			auth: 'eap-aka',
			id: id,
			eap_id: id,
		},
		remote: {
			// eap-aka: the ePDG proves itself by the mutual EAP-AKA alone
			// (EAP-only, RFC 5998), as Telekom's does (HW 2026-11-21: no
			// certificate; 'pubkey' fails "constraint requires public key
			// authentication"); a profile may ask for pubkey instead
			auth: o.remote_auth ?? 'eap-aka',
			// the IMS APN as IDr (TS 24.302 7.2.2), a profile's vowifi_apn
			// over it, '%any' for none. An ePDG answers with an identity of
			// its own (Telekom DE 'nai.epc.mnc001.mcc262.3gppnetwork.org',
			// Vodafone DE its FQDN; HW 2026-11-21), which charon refuses
			// unless the feed's epdg-idr plugin is on for CONN
			// (files/vowifi-strongswan.conf): Vodafone DE refuses a request
			// without IDr (N(10500) NETWORK_FAILURE)
			id: o.apn ?? 'ims',
		},
		children: {
			ims: {
				local_ts: [ '0.0.0.0/0', '::/0' ],
				remote_ts: [ '0.0.0.0/0', '::/0' ],
				mode: 'tunnel',
				rekey_time: sprintf('%ds', o.esp_rekey_s ?? 0),
				// the controller (vowifi/ctl.uc) brings the tunnel back, not
				// charon: it loads the connection anew first, and only then the
				// IDr goes out again (a peer config the epdg-idr plugin relaxed
				// sends none, which Vodafone DE refuses); a restart of charon's
				// own also left the controller with the old addresses
				dpd_action: 'clear',
				close_action: 'none',
			},
		},
	};
	// what charon offers when nothing else is said: Telekom DE's ePDG asks
	// for MODP_4096 and chose AES-CBC-256/HMAC-SHA2-512 with it (HW,
	// 2026-11-21), so that goes first, charon's defaults after it
	c.proposals = o.proposals ?? [ 'aes256-sha512-modp4096', 'default' ];
	if (o.esp_proposals)
		c.children.ims.esp_proposals = o.esp_proposals;
	// a line's own connection name (several lines: wwand-vowifi<i>)
	return { [o.conn ?? CONN]: c };
}

// a P-CSCF address from one of charon's log lines (p-cscf plugin)
export function pcscf_from_log(msg)
{
	let m = match(msg ?? '', /received P-CSCF server IP ([0-9A-Fa-f:.]+)/);
	return m ? m[1] : null;
}

// our virtual IPs from a list-sa event of the connection: { v4, v6 } (null when none)
export function vips_of(listsa, conn)
{
	let sa = listsa?.[conn ?? CONN];
	let out = { v4: null, v6: null, state: sa?.state ?? null, remote: sa?.['remote-host'] ?? null };
	for (let a in sa?.['local-vips'] ?? []) {
		if (index(a, ':') >= 0)
			out.v6 ??= a;
		else
			out.v4 ??= a;
	}
	return out;
}
