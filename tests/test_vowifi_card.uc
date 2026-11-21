// Host tests for vowifi/card.uc, the card behind strongSwan's ext-aka
// plugin: the IMSI from the NAI, the modem for it, and one AUTHENTICATE
// over a stand-in for wwand's APDU channel. All identifiers are made-up
// example values.
'use strict';

import { eq, ok, done } from './lib/check.uc';
import * as CARD from 'vowifi_card';

eq(CARD.imsi_of('0262991234567890@nai.epc.mnc099.mcc262.3gppnetwork.org'), '262991234567890', 'imsi_of: permanent NAI');
eq(CARD.imsi_of('262991234567890'), '262991234567890', 'imsi_of: a bare IMSI');
eq(CARD.imsi_of('anonymous@nai.epc'), null, 'imsi_of: no IMSI');

let ST = { modems: { m0: { imsi: '262991234567890' }, m1: { imsi: '262011111111111' } } };
eq(CARD.modem_of(ST, '262011111111111'), 'm1', 'modem_of: by IMSI');
eq(CARD.modem_of(ST, '262019999999999'), null, 'modem_of: none has it');
eq(CARD.modem_of({ modems: { m0: {} } }, '262019999999999'), 'm0', 'modem_of: the one modem, IMSI not read yet');

let RAND = '00112233445566778899aabbccddeeff', AUTN = 'ffeeddccbbaa99887766554433221100';
// a card that answers AUTHENTICATE with DB RES(8) CK(16) IK(16), or DC AUTS(14)
let world = (answer) => {
	let w = { apdus: [] };
	w.call = (obj, method, args, cb) => {
		if (method == 'status')
			return cb(null, ST);
		if (args.op == 'open')
			return cb(null, { channel: 1 });
		if (args.op == 'close')
			return cb(null, {});
		push(w.apdus, args.apdu);
		cb(null, { response: answer });
	};
	return w;
};
let db = 'db080102030405060708' + '10' + '1111111111111111111111111111111' + '1' + '10' + '22222222222222222222222222222222' + '9000';
let w = world(db), got;
CARD.run([ 'aka', '0262991234567890@nai.epc', RAND, AUTN ], w.call, (c, l, e) => { got = [ c, l, e ]; });
eq(got, [ 0, [ 'RES 0102030405060708', 'CK 11111111111111111111111111111111', 'IK 22222222222222222222222222222222' ], null ],
	'run: RES, CK, IK');
eq(substr(lc(w.apdus[0]), 0, 10), '0188008122', 'run: AUTHENTICATE 3G context on the logical channel');
w = world('dc0e' + '0a0b0c0d0e0f00010203040506ff' + '9000');
CARD.run([ 'aka', '0262991234567890@nai.epc', RAND, AUTN ], w.call, (c, l, e) => { got = [ c, l, e ]; });
eq(got, [ 0, [ 'AUTS 0a0b0c0d0e0f00010203040506ff' ], null ], 'run: synchronisation failure -> AUTS');
w = world('9862');
CARD.run([ 'aka', '0262991234567890@nai.epc', RAND, AUTN ], w.call, (c, l, e) => { got = [ c, l, e ]; });
ok(got[0] == 1 && !length(got[1]) && index(got[2], 'mac') >= 0, 'run: MAC failure -> exit 1');
CARD.run([ 'aka', '0262019999999999@nai.epc', RAND, AUTN ], w.call, (c, l, e) => { got = [ c, l, e ]; });
ok(got[0] == 1 && index(got[2], 'no modem') >= 0, 'run: no modem with that IMSI');
CARD.run([ 'aka', '0262991234567890@nai.epc', 'zz', AUTN ], w.call, (c, l, e) => { got = [ c, l, e ]; });
eq(got[0], 1, 'run: bad RAND');

done();
