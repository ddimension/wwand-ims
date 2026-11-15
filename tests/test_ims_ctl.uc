// Host tests for `wwandctl ims` (ctl/ims.uc) and the QMI/AT readers of the
// UE line (sipd/line_ue.uc): what the modem answers is parsed, the plans are
// computed; nothing talks to a modem here.
'use strict';

import { eq, ok, done } from './lib/check.uc';
import * as LINE from 'sipd_line_ue';

let CTL = require('ctl_ims');
let T = CTL._t;

// ---- FGI ---------------------------------------------------------------------------

// as the RG650E-EU A05 answers (the firmware writes QNWFCFG)
let fgi = T.fgi_parse([ '+QNWFCFG: "lte_fgi_fdd",2:4:5:6:8:9:10:13:14:15:16:17:18:19:20:21:22:23:25:30:31:102:103:105:106:109:110:111:112:113:114' ]);
eq(length(fgi), 31, 'fgi_parse: the RG650E list');
let pl = T.fgi_plan(fgi);
eq(pl.missing, [ 3, 7 ], 'fgi_plan: 3 and 7 missing');
eq(pl.arg, '2:3:4:5:6:7:8:9:10:13:14:15:16:17:18:19:20:21:22:23:25:30:31:102:103:105:106:109:110:111:112:113:114',
	'fgi_plan: the list to write = the old one plus 3 and 7 (the one HW-tested 2026-11-14)');
eq(T.fgi_plan(pl.list).missing, [], 'fgi_plan: nothing missing afterwards');
eq(T.fgi_parse([ 'ERROR' ]), null, 'fgi_parse: no answer');

eq(T.qcfg_ims([ '+QCFG: "ims",2,0' ]), 2, 'qcfg_ims: mode 2 (off)');
eq(T.qcfg_ims([]), null, 'qcfg_ims: none');

// ---- profiles ------------------------------------------------------------------------

let cg = T.cgdcont_parse([
	'+CGDCONT: 1,"IP","web.vodafone.de","0.0.0.0",0,0,0,0,,,,,,,,,,"",,,,0',
	'+CGDCONT: 2,"IPV4V6","ims","0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0",0,0,0,0,,,,,,,,,,"",,,,0',
	'+CGDCONT: 4,"IPV4V6","sos","0.0.0.0",0,0,0,1',
]);
eq(cg[1], { index: 2, pdp_type: 'ipv4v6', apn: 'ims' }, 'cgdcont_parse: the IMS profile');
eq(T.ims_profile(cg)?.index, 2, 'ims_profile: by APN ims, never sos');
eq(T.ims_profile([ { index: 3, apn: 'sos', imcn: true }, { index: 5, apn: 'ims.iot', imcn: true } ])?.index, 5,
	'ims_profile: the IMCN-marked one (modem_profiles), sos skipped');
eq(T.ims_profile([ { index: 1, apn: 'internet' } ]), null, 'ims_profile: none');
eq([ T.pdp_option('IPV4V6'), T.pdp_option('IPV6'), T.pdp_option('IP'), T.pdp_option('x') ],
	[ 'ipv4v6', 'ipv6', 'ipv4', null ], 'pdp_option: AT+CGDCONT text');
eq([ T.pdp_option(0), T.pdp_option(2), T.pdp_option(3), T.pdp_option(1) ], [ 'ipv4', 'ipv6', 'ipv4v6', null ],
	'pdp_option: the QMI enum of modem_profiles (libqmi QmiWdsPdpType)');
eq(T.setup_sections({ modem: 'm', profile: { index: 2, apn: 'ims', pdp_type: 2 } })[2].opts.pdp_type, 'ipv6',
	'setup: the PDP type from a QMI profile');

// ---- setup plan -----------------------------------------------------------------------

let want = T.setup_sections({ modem: 'wwmodem0', profile: cg[1] });
let byname = {};
for (let w in want)
	byname[w.config + '.' + w.name] = w;
let net = byname['network.wwims'].opts;
eq([ net.apn, net.pdp_type, net.ims, net.profile, net.delegate, net.ip6table ], [ 'ims', 'ipv4v6', '1', '2', '0', '30' ],
	'setup: the IMS PDN from the MBN profile, ims, pinned profile, no delegation, the VRF table');
eq(byname['network.ims'].opts.type, 'vrf', 'setup: the VRF device');
eq(byname['firewall.ims_sip'].opts.dest_port, '5062 5064 5072 5074', 'setup: SIP on both protected port pairs');
eq(byname['firewall.ims_rtp'].opts.dest_port, '40000-40199', 'setup: the relay\'s RTP range');
eq(byname['wwand_ims.ue'].opts.backend, 'ue', 'setup: sipd\'s line is the UE');

eq(T.section_plan(byname['network.wwims'], null).action, 'create', 'section_plan: missing -> create');
eq(T.section_plan(byname['network.wwims'], { ...net, '.type': 'interface' }).action, 'ok', 'section_plan: equal -> ok');
let d = T.section_plan(byname['network.wwims'], { ...net, pdp_type: 'ipv6' });
eq([ d.action, d.diff ], [ 'differs', [ [ 'pdp_type', 'ipv6', 'ipv4v6' ] ] ], 'section_plan: a differing option');
eq(T.section_plan(byname['network.ims'], { type: 'vrf', name: 'ims', table: '30', ports: [ 'wwims' ] }).action, 'ok',
	'section_plan: a list that holds the port');

// ---- the UE line's readers ------------------------------------------------------------------

// the PANI the network accepted on 2026-11-14 (from AT+QENG then)
let cells = { cells: { lte_intra: { plmn: '262/02', tac: 45195, global_cell_id: 13102081, earfcn: 6300 } } };
eq(LINE.pani_of(cells), '3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=26202B08B0C7EC01',
	'pani_of: modem_cells (QMI NAS) gives the same PANI as AT+QENG did');
ok(index(LINE.pani_of({ cells: { lte_intra: { ...cells.cells.lte_intra, earfcn: 38000 } } }), 'TDD') > 0,
	'pani_of: TDD from the EARFCN');
eq(LINE.pani_of({ cells: {} }), null, 'pani_of: no LTE cell');

eq(LINE.pcscf_from_cgcontrdp([
	'+CGCONTRDP: 1,5,"web.vodafone.de","10.1.2.3.255.0.0.0","10.1.2.1"',
	'+CGCONTRDP: 2,6,"ims","42.0.0.32.65.210.152.230.167.42.186.175.21.191.136.10", "254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.1",,,"42.1.8.240.4.0.9.84.0.0.0.0.0.0.0.5","42.1.8.240.4.0.5.36.0.0.0.0.0.0.0.5"',
], 'ims'), [ '2a01:8f0:400:954::5', '2a01:8f0:400:524::5' ], 'pcscf_from_cgcontrdp: the IMS PDN\'s P-CSCFs as IPv6 text');

// home MNC length and the IPv6 shortening
eq(LINE.home_mnc_len({ imsi: '262021234567890', registration: { roaming: false, plmn: { mcc: 262, mnc: 2, mnc_digits: 2 } } }), 2,
	'home_mnc_len: home network, 2 digits');
eq(LINE.home_mnc_len({ imsi: '310410123456789', registration: { roaming: true, plmn: { mcc: 262, mnc: 2, mnc_digits: 2 } } }), 3,
	'home_mnc_len: roaming US card -> 3 by its MCC, not the visited network\'s 2');
eq(LINE.pcscf_from_cgcontrdp([ '+CGCONTRDP: 2,6,"ims","x","y",,,"32.1.13.184.0.0.0.0.0.1.0.0.0.0.0.1"' ], 'ims'),
	[ '2001:db8::1:0:0:1' ], 'v6_dotted: two equal zero runs, only the first shortened');
eq(LINE.pcscf_from_cgcontrdp([ '+CGCONTRDP: 2,6,"ims.mnc002.mcc262.gprs","x","y",,,"42.1.8.240.4.0.9.84.0.0.0.0.0.0.0.5"' ], 'ims'),
	[ '2a01:8f0:400:954::5' ], 'pcscf_from_cgcontrdp: the APN with an operator suffix');

// the P-CSCFs from wwand's status (QMI 0x2E IPv6, 0x23 IPv4), as the RG650E
// reported them on 2026-11-15: the same list as AT+CGCONTRDP, short form
eq(LINE.pcscf_from_status({ ipv6: { pcscf: [ '2a01:8f0:400:955:0:0:0:5', '2a01:8f0:400:565:0:0:0:5' ] } }),
	[ '2a01:8f0:400:955::5', '2a01:8f0:400:565::5' ], 'pcscf_from_status: the IPv6 list in short form');
eq(LINE.pcscf_from_status({ ipv4: { pcscf: [ '10.1.2.3' ] }, ipv6: { pcscf: [ '2001:db8:0:0:0:0:0:5', '2001:db8::5' ] } }),
	[ '2001:db8::5', '10.1.2.3' ], 'pcscf_from_status: IPv6 first, IPv4 after, no duplicates');
eq(LINE.pcscf_from_status({ ipv6: { pcscf: null }, ipv4: null }), [], 'pcscf_from_status: none reported');
eq(LINE.pcscf_from_status(null), [], 'pcscf_from_status: no context');

done();
