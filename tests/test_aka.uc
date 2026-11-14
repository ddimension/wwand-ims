// Host tests for ue/aka.uc: the USIM AUTHENTICATE over a stand-in card, the
// Digest AKAv1-MD5 nonce, and the identities from the IMSI.
'use strict';

import { eq, ok, done } from './lib/check.uc';
import * as A from 'ue_aka';

let S = require('sipd_sip');

// 3GPP TS 35.208 4.3, Milenage test set 1 (f2-f5 outputs for this RAND/K/OP)
let RAND = hexdec('23553cbe9637a89d218ae64dae47bf35');
let RES  = hexdec('a54211d5e3ba50bf');
let CK   = hexdec('b40ba9a3c58b2a05bbf0d987b21bf8cb');
let IK   = hexdec('f769bcd751044604127672711c6d3441');
// AUTN = (SQN ff9bb4d0b607 xor AK aa689c648370) || AMF b9b9 || MAC-A 4a9ffac354dfafb3
let AUTN = hexdec('55f328b43577b9b94a9ffac354dfafb3');
let AUTS = hexdec('00112233445566778899aabbccdd');

// ---- APDU building ---------------------------------------------------------------

eq(A.cla(0), 0x00, 'cla: basic channel');
eq(A.cla(3), 0x03, 'cla: channel 3 in the first interindustry CLA');
eq(A.cla(4), 0x40, 'cla: channel 4 in the further interindustry CLA');
eq(A.cla(19), 0x4f, 'cla: channel 19');
eq(A.cla(20), null, 'cla: no channel 20');

eq(A.authenticate_apdu(1, RAND, AUTN),
	'0188008122' + '10' + hexenc(RAND) + '10' + hexenc(AUTN) + '00',
	'authenticate_apdu: CLA ch 1, INS 88, P2 81, Lc 0x22, Le 00');
eq(A.authenticate_apdu(1, substr(RAND, 1), AUTN), null, 'authenticate_apdu: short RAND refused');

eq(A.followup(2, 'x', '6135'), '02c0000035', 'followup: 61xx -> GET RESPONSE on the same channel');
eq(A.followup(1, '0188008122aa00', '6c35'), '0188008122aa35', 'followup: 6Cxx -> resend with Le');
eq(A.followup(1, 'x', '9000'), null, 'followup: 9000 is final');

// ---- response parsing ------------------------------------------------------------

let db = 'db08' + hexenc(RES) + '10' + hexenc(CK) + '10' + hexenc(IK);
eq(A.parse_authenticate(db, '9000'), { res: RES, ck: CK, ik: IK }, 'parse: DB without Kc');
eq(A.parse_authenticate(db + '08' + '0102030405060708', '9000').kc, hexdec('0102030405060708'),
	'parse: DB with Kc');
eq(A.parse_authenticate('dc0e' + hexenc(AUTS), '9000'), { sync: true, auts: AUTS }, 'parse: DC is a sync failure');
eq(A.parse_authenticate('', '9862'), { error: 'mac' }, 'parse: 9862 is a MAC failure');
eq(A.parse_authenticate('db08a542', '9000'), { error: 'short' }, 'parse: truncated');
eq(A.parse_authenticate('', '6a82'), { error: 'status', sw: '6a82' }, 'parse: other status words');

// ---- authenticate() over a stand-in card ------------------------------------------

// answers like a T=0 card behind a modem that does not fetch the response:
// 61xx first, the data on GET RESPONSE. `mode` picks the card's verdict.
function fake_card(mode)
{
	let log = { opened: [], sent: [], closed: [] };
	let pending = null;

	let card = {
		log: log,
		open: (aid, cb) => { push(log.opened, aid); cb(null, 2); },
		close: (ch, cb) => { push(log.closed, ch); cb(null); },
		send: (ch, apdu, cb) => {
			push(log.sent, apdu);
			if (mode == 'open-fails')
				return cb('boom', null);
			if (substr(apdu, 2, 2) == '88') {
				if (mode == 'mac')
					return cb(null, '9862');
				pending = (mode == 'sync') ? 'dc0e' + hexenc(AUTS) : db;
				return cb(null, sprintf('61%02x', length(pending) / 2));
			}
			if (substr(apdu, 2, 2) == 'c0')
				return cb(null, pending + '9000');
			cb(null, '6d00');
		},
	};
	return card;
}

let c = fake_card('ok'), got = null, gerr = null;
A.authenticate(c, null, RAND, AUTN, (e, r) => { gerr = e; got = r; });
eq(gerr, null, 'authenticate: no error');
eq(got, { res: RES, ck: CK, ik: IK }, 'authenticate: RES/CK/IK after GET RESPONSE');
eq(c.log.opened, [ A.AID_USIM ], 'authenticate: opens the USIM by default');
eq(length(c.log.sent), 2, 'authenticate: AUTHENTICATE + GET RESPONSE');
eq(substr(c.log.sent[1], 0, 10), sprintf('02c00000%02x', length(db) / 2), 'authenticate: GET RESPONSE on channel 2');
eq(c.log.closed, [ 2 ], 'authenticate: channel closed');

c = fake_card('sync');
A.authenticate(c, null, RAND, AUTN, (e, r) => { gerr = e; got = r; });
eq(got, { sync: true, auts: AUTS }, 'authenticate: sync failure gives AUTS');
eq(c.log.closed, [ 2 ], 'authenticate: channel closed after a sync failure');

c = fake_card('mac');
A.authenticate(c, null, RAND, AUTN, (e, r) => { gerr = e; got = r; });
eq(gerr, { error: 'mac' }, 'authenticate: MAC failure is an error');
eq(c.log.closed, [ 2 ], 'authenticate: channel closed after a MAC failure');

c = fake_card('open-fails');
A.authenticate(c, A.AID_ISIM, RAND, AUTN, (e, r) => { gerr = e; got = r; });
eq(gerr?.error, 'send', 'authenticate: transport error reported');
eq(c.log.opened, [ A.AID_ISIM ], 'authenticate: the AID passed is used');
eq(c.log.closed, [ 2 ], 'authenticate: channel closed after a transport error');

// ---- the wwand ubus card ----------------------------------------------------------

let calls = [];
let ubus_call = (obj, method, args, cb) => {
	push(calls, [ obj, method, args ]);
	if (args.op == 'open')
		return cb(null, { channel: 3, select_response: '9000' });
	if (args.op == 'send')
		return cb(null, { response: '9000' });
	cb(null, {});
};
let wc = A.wwand_card(ubus_call, 'wwmodem0', 2);
wc.open(A.AID_USIM, (e, ch) => eq([ e, ch ], [ null, 3 ], 'wwand_card: open yields the channel'));
wc.send(3, '00', (e, r) => eq([ e, r ], [ null, '9000' ], 'wwand_card: send yields the response'));
wc.close(3, (e) => eq(e, null, 'wwand_card: close'));
eq(calls[0], [ 'wwand', 'modem_apdu', { modem: 'wwmodem0', slot: 2, op: 'open', aid: A.AID_USIM } ],
	'wwand_card: modem_apdu open with modem, slot, aid');
eq(calls[1][2], { modem: 'wwmodem0', slot: 2, op: 'send', channel: 3, apdu: '00' }, 'wwand_card: send args');
eq(calls[2][2], { modem: 'wwmodem0', slot: 2, op: 'close', channel: 3 }, 'wwand_card: close args');

let nocalls = [];
A.wwand_card((o, m, a, cb) => { push(nocalls, a); cb(null, {}); }, 'wwmodem1').open('aa', (e) =>
	eq(e, 'no channel', 'wwand_card: an answer without a channel is an error'));
eq(nocalls[0].slot, null, 'wwand_card: no slot -> wwand picks the active one');

// ---- Digest AKAv1-MD5 ------------------------------------------------------------

let server_data = 'srv';
let nonce = b64enc(RAND + AUTN + server_data);
eq(A.nonce_split(nonce), { rand: RAND, autn: AUTN, server_data: server_data }, 'nonce_split');
eq(A.nonce_split(b64enc('short')), null, 'nonce_split: too short');
eq(A.auts_param(AUTS), b64enc(AUTS), 'auts_param is base64');

// the password is RES as bytes: HA1 = MD5(user:realm:RES), RFC 3310 3.3
let pw = A.akav1_password(RES);
let id = A.identities('262021234567890', 2);
let ha1 = S.md5(sprintf('%s:%s:%s', id.impi, id.realm, pw));
eq(length(ha1), 32, 'akav1: HA1 over binary RES is an MD5');
eq(S.md5_pure(sprintf('%s:%s:%s', id.impi, id.realm, pw)), ha1, 'akav1: pure and native MD5 agree on binary input');

// ---- identities ------------------------------------------------------------------

eq(A.home_domain('262021234567890', 2), 'ims.mnc002.mcc262.3gppnetwork.org', 'home_domain: 2-digit MNC padded');
eq(A.home_domain('310150123456789', 3), 'ims.mnc150.mcc310.3gppnetwork.org', 'home_domain: 3-digit MNC');
eq(A.home_domain('901280000000001', 2), 'ims.mnc028.mcc901.3gppnetwork.org', 'home_domain: GDSP 90128');
eq(A.home_domain('26202', 2), null, 'home_domain: not an IMSI');
eq(A.home_domain('262021234567890', 4), null, 'home_domain: MNC length is 2 or 3');
eq(A.identities('262021234567890', 2), {
	domain: 'ims.mnc002.mcc262.3gppnetwork.org',
	impi: '262021234567890@ims.mnc002.mcc262.3gppnetwork.org',
	impu: 'sip:262021234567890@ims.mnc002.mcc262.3gppnetwork.org',
	realm: 'ims.mnc002.mcc262.3gppnetwork.org',
}, 'identities without ISIM');

done();
