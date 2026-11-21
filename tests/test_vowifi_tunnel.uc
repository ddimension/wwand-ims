// Host tests for vowifi/tunnel.uc: the names of TS 23.003, the vici
// connection, what charon's logs and list-sas tell. Made-up identifiers.
'use strict';

import { eq, ok, done } from './lib/check.uc';
import * as TUN from 'vowifi_tunnel';
import * as VICI from 'vowifi_vici';

let p = TUN.plmn_of('262991234567890', 2);
eq(p, { mcc: '262', mnc: '99' }, 'plmn_of: MCC and a 2-digit MNC');
eq(TUN.plmn_of('310150123456789', 3), { mcc: '310', mnc: '150' }, 'plmn_of: a 3-digit MNC');
eq(TUN.plmn_of('x'), null, 'plmn_of: not an IMSI');
eq(TUN.epdg_fqdn(p), 'epdg.epc.mnc099.mcc262.pub.3gppnetwork.org', 'epdg_fqdn: MNC padded to 3 digits');
eq(TUN.nai('262991234567890', p), '0262991234567890@nai.epc.mnc099.mcc262.3gppnetwork.org', 'nai: permanent EAP-AKA identity');

let c = TUN.conn_config({ imsi: '262991234567890', plmn: p, if_id: 42 })[TUN.CONN];
eq([ c.remote_addrs, c.vips, c.if_id_in, c.if_id_out, c.local.auth, c.local.id, c.remote.id, c.remote.auth ],
	[ [ 'epdg.epc.mnc099.mcc262.pub.3gppnetwork.org' ], [ '0.0.0.0', '::' ], '42', '42', 'eap-aka',
	  '0262991234567890@nai.epc.mnc099.mcc262.3gppnetwork.org', '%any', 'eap-aka' ],
	'conn_config: ePDG, virtual IPs, the XFRM interface, EAP-AKA with the NAI, no IDr by default');
eq([ c.children.ims.local_ts, c.children.ims.mode ], [ [ '0.0.0.0/0', '::/0' ], 'tunnel' ], 'conn_config: one child, all traffic');
eq(c.proposals, [ 'aes256-sha512-modp4096', 'default' ], 'conn_config: MODP_4096 first, charon\'s defaults after');
let c2 = TUN.conn_config({ imsi: '262991234567890', plmn: p, if_id: 7, epdg: 'epdg.example.net', apn: 'ims.x',
	proposals: [ 'aes128-sha1-modp1024' ], esp_proposals: [ 'aes128-sha1' ], remote_auth: 'pubkey' })[TUN.CONN];
eq([ c2.remote_addrs, c2.remote.id, c2.proposals, c2.children.ims.esp_proposals, c2.remote.auth ],
	[ [ 'epdg.example.net' ], 'ims.x', [ 'aes128-sha1-modp1024' ], [ 'aes128-sha1' ], 'pubkey' ],
	'conn_config: a profile\'s ePDG, APN, proposals and server authentication');
ok(VICI.decode(VICI.encode(TUN.conn_config({ imsi: '262991234567890', plmn: p, if_id: 42 }))) != null,
	'conn_config: encodes as a vici message');

eq(TUN.pcscf_from_log('received P-CSCF server IP 2001:db8:ff::10'), '2001:db8:ff::10', 'pcscf_from_log: v6');
eq(TUN.pcscf_from_log('received P-CSCF server IP 192.0.2.10'), '192.0.2.10', 'pcscf_from_log: v4');
eq(TUN.pcscf_from_log('installing new virtual IP 10.0.0.2'), null, 'pcscf_from_log: another line');

eq(TUN.vips_of({ [TUN.CONN]: { state: 'ESTABLISHED', 'remote-host': '198.51.100.7',
		'local-vips': [ '10.45.0.2', '2001:db8:aa::2' ] } }),
	{ v4: '10.45.0.2', v6: '2001:db8:aa::2', state: 'ESTABLISHED', remote: '198.51.100.7' }, 'vips_of');
eq(TUN.vips_of({}), { v4: null, v6: null, state: null, remote: null }, 'vips_of: no SA');

done();
