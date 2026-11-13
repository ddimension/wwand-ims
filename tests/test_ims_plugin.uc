// Host tests for plugins/ims.uc: the schemas against hand-built wire buffers
// (libqmi 1.38 layouts), and the ops over a fake QMI client.
'use strict';

import { eq, ok, done } from './lib/check.uc';
import * as struct from 'struct';
import * as tlv from 'wwand.codec.tlv';

let P = require('ims_plugin');

let T = (t, v) => struct.pack('<BH', t, length(v)) + v;
let u8 = (v) => struct.pack('<B', v);
let u16 = (v) => struct.pack('<H', v);
let u32 = (v) => struct.pack('<I', v);

// ---- wire decoding --------------------------------------------------------

// IMSA Get IMS Registration Status: 0x12 status u32, 0x11 error u16,
// 0x13 message (whole-TLV string), 0x14 technology u32
let reg = tlv.unpack(P.IMSA.messages.GET_REG_STATUS.resp,
	T(0x12, u32(2)) + T(0x11, u16(0)) + T(0x13, 'ok') + T(0x14, u32(1)));
eq(reg.status, 2, 'imsa reg: status registered');
eq(reg.tech, 1, 'imsa reg: technology wwan');
eq(reg.err_msg, 'ok', 'imsa reg: error message string');

// IMSA Get IMS Services Status: sms 0x10, voice 0x11, their techs 0x13/0x14
let svc = tlv.unpack(P.IMSA.messages.GET_SERVICES_STATUS.resp,
	T(0x10, u32(2)) + T(0x11, u32(0)) + T(0x13, u32(1)) + T(0x14, u32(1)));
eq([ svc.sms, svc.voice, svc.sms_tech ], [ 2, 0, 1 ], 'imsa services: sms available, voice unavailable');

// the indication numbers its TLVs one lower than the response (libqmi:
// "IMS Registration Status Changed" 0x11 status, 0x10 error code)
let ind = tlv.unpack(P.IMSA.messages.REG_STATUS_IND.ind, T(0x11, u32(0)) + T(0x10, u16(403)));
eq([ ind.status, ind.err_code ], [ 0, 403 ], 'imsa reg ind: status and error code');

// NAS Get System Info: 0x29 IMS voice support u8, 0x2A LTE voice domain u32;
// the other TLVs of the message are left raw
let sys = tlv.unpack(P.NAS.messages.GET_SYSTEM_INFO.resp,
	T(0x14, u8(1)) + T(0x29, u8(0)) + T(0x2A, u32(1)));
eq([ sys.ims_voice, sys.voice_domain ], [ 0, 1 ], 'nas system info: ims voice support and voice domain');

// Voice All Call Status 0x01: u8 count, then 7 u8 per call; 0x10 remote
// party: u8 count, then id, presentation, u8-prefixed number
let calls = tlv.unpack(P.VOICE.messages.ALL_CALL_STATUS_IND.ind,
	T(0x01, u8(1) + u8(1) + u8(1) + u8(0) + u8(1) + u8(4) + u8(0) + u8(0)) +
	T(0x10, u8(1) + u8(1) + u8(0) + u8(13) + '+491701234567'));
let list = P.calls_of(calls);
eq(list, [ { id: 1, state: 'origination', direction: 'mo', mode: 'lte', number: '+491701234567' } ],
	'voice call status: one MO call over LTE, number joined by id');

// Dial Call request: 0x01 the number as a whole-TLV string
eq(tlv.pack(P.VOICE.messages.DIAL_CALL.req, { number: '+4912' }), T(0x01, '+4912'),
	'voice dial: number TLV');
eq(tlv.pack(P.VOICE.messages.DIAL_CALL.req, { number: '+4912', call_type: 2 }), T(0x01, '+4912') + T(0x10, u8(2)),
	'voice dial: call type TLV 0x10 as u8');

// PDC Load Config: 0x01 = type u32 (SOFTWARE = 1), u8-prefixed id, total
// size u32, u16-prefixed chunk; then 0x10 token u32 (libqmi 1.38)
let cid = P.hex_to_bin('a1b2');
eq(cid, chr(0xa1, 0xb2), 'pdc: hex id to bytes');
eq(tlv.pack(P.PDC.messages.LOAD_CONFIG.req, { chunk: P.pdc_chunk('ABC', cid, 0), token: 7 }),
	T(0x01, u32(1) + u8(2) + chr(0xa1, 0xb2) + u32(3) + u16(3) + 'ABC') + T(0x10, u32(7)),
	'pdc load config: chunk TLV layout, type software');

// a file over one chunk: 1024 bytes, then the rest, total size in both
let big = '';
for (let i = 0; i < 1500; i++)
	big += 'x';
let c0 = P.pdc_chunk(big, cid, 0), c1 = P.pdc_chunk(big, cid, 1024);
eq([ c0.chunk_len, c0.total, c1.chunk_len, c1.total ], [ 1024, 1500, 476, 1500 ],
	'pdc load config: 1024-byte chunks, total size in each');

// Load Config indication: 0x01 result u16, 0x10 token, 0x11 received,
// 0x12 remaining, 0x13 frame reset
let li = tlv.unpack(P.PDC.messages.LOAD_CONFIG_IND.ind,
	T(0x01, u16(0)) + T(0x10, u32(7)) + T(0x11, u32(1024)) + T(0x12, u32(476)));
eq([ li.result, li.token, li.received, li.remaining ], [ 0, 7, 1024, 476 ], 'pdc load ind: fields');

eq(tlv.pack(P.PDC.messages.ACTIVATE_CONFIG.req, { config_type: 1, token: 9 }),
	T(0x01, u32(1)) + T(0x10, u32(9)), 'pdc activate: type and token');

// ---- ops over a fake client ---------------------------------------------------

let answers = {
	GET_REG_STATUS: { status: 2, tech: 1 },
	GET_SERVICES_STATUS: { sms: 2, voice: 0, sms_tech: 1 },
	GET_SERVICES_ENABLED: { reg: 1, voice: 1, sms: 1 },
	GET_SYSTEM_INFO: { ims_voice: 0, voice_domain: 0 },
	GET_ALL_CALL_INFO: { calls: [] },
	DIAL_CALL: { id: 3 },
};
let sent = [], opened = [], released = 0;

// answers are held and delivered later, like real QMI responses: a fake that
// answers inside request() hid a closure bug that crashed the daemon
let pending = [];
let flush = () => {
	while (length(pending)) {
		let p = shift(pending);
		p();
	}
};
let fake = (schema) => ({
	schema: schema,
	on: () => null,
	request: (name, args, cb) => {
		push(sent, name);
		push(pending, () => cb(null, answers[name] ?? {}));
	},
});

let inst = P.create({
	log: () => null,
	qmi_client: (ref, schema, cb) => { push(opened, schema.service); cb(null, fake(schema)); },
	qmi_release: () => released++,
});

let st = null;
inst.ops.status('m0', {}, {}, (e, r) => st = r);
flush();
eq(opened, [ 0x21, 0x12, 0x03, 0x09 ], 'ops: the four clients, IMSA IMS NAS Voice');
eq(st.registration.status, 'registered', 'status: registration');
eq(st.services.voice, 'unavailable', 'status: voice service');
eq(st.network.ims_voice, 0, 'status: network ims voice support');
eq(inst.status('m0').text, 'registered, voice unavailable', 'status row from the cache');

let dial = null;
inst.ops.dial('m0', {}, { number: '+491701234567' }, (e, r) => dial = r);
flush();
eq(dial, { id: 3, raw: null }, 'dial: call id from the response');
eq(length(opened), 4, 'dial: the clients are reused, not reopened');

let badt = null;
inst.ops.dial('m0', {}, { number: '+491701234567', call_type: 'video' }, (e) => badt = e);
eq(badt, { error: 'invalid_call_type' }, 'dial: an unknown call type is refused');

let bad = null;
inst.ops.dial('m0', {}, { number: '12;ATH' }, (e) => bad = e);
eq(bad, { error: 'invalid_number' }, 'dial: a number with other characters is refused');

// a modem reset under the kept clients: the first answer is `cancelled`,
// the plugin opens new clients once and asks again
answers.GET_ALL_CALL_INFO = null;
let cancel_once = true;
let fake_req = fake;
let calls_r = null;
let inst2 = P.create({
	log: () => null,
	qmi_client: (ref, schema, cb) => { push(opened, schema.service); cb(null, {
		on: () => null,
		request: (name, args, cb2) => push(pending, () => {
			if (name == 'GET_ALL_CALL_INFO' && cancel_once) {
				cancel_once = false;
				return cb2({ error: 'cancelled' }, null);
			}
			cb2(null, (name == 'GET_ALL_CALL_INFO') ? { calls: [] } : {});
		}),
	}); },
	qmi_release: () => released++,
});
opened = [];
inst2.ops.calls('m1', {}, {}, (e, r) => calls_r = r);
flush();
eq(calls_r, { calls: [] }, 'stale clients: answered after one reopen');
eq(length(opened), 8, 'stale clients: four new clients opened');

released = 0;
inst.stop();
eq(released, 4, 'stop: every client released');

done();
