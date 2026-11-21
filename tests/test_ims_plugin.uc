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
eq(P.calls_of({ calls: [ { id: 9, state: 4, direction: 1, mode: 6 } ] })[0].mode, 'undetermined', 'call mode 6 is named undetermined (Gobi API: Unknown)');
eq(list, [ { id: 1, state: 'origination', direction: 'mo', mode: 'lte', number: '+491701234567',
             end_reason: null } ],
	'voice call status: one MO call over LTE, number joined by id');

// 0x14 call end reason (Gobi API): u8 count, then per call id u8 + reason u16
let ended = tlv.unpack(P.VOICE.messages.ALL_CALL_STATUS_IND.ind,
	T(0x01, u8(1) + u8(1) + u8(9) + u8(0) + u8(1) + u8(4) + u8(0) + u8(0)) +
	T(0x14, u8(1) + u8(1) + u16(21)));
eq(P.calls_of(ended)[0].end_reason, 21, 'voice call status: end reason joined by id, as a number');

// Dial Call request: 0x01 the number as a whole-TLV string
eq(tlv.pack(P.VOICE.messages.DIAL_CALL.req, { number: '+4912' }), T(0x01, '+4912'),
	'voice dial: number TLV');
eq(tlv.pack(P.VOICE.messages.DIAL_CALL.req, { number: '+4912', call_type: 2 }), T(0x01, '+4912') + T(0x10, u8(2)),
	'voice dial: call type TLV 0x10 as u8');
// audio/video attributes as the stock RIL sends them: 64-bit masks, TX|RX
eq(tlv.pack(P.VOICE.messages.DIAL_CALL.req, { number: '+4912', audio: 3, video: 0 }),
	T(0x01, '+4912') + T(0x18, u32(3) + u32(0)) + T(0x19, u32(0) + u32(0)),
	'voice dial: audio 0x18 and video 0x19 attributes as u64');

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

// Delete Config 0x25 (libqmi): 0x01 type, 0x10 token, 0x11 u8-counted id; its
// indication (8T IDL, not libqmi): 0x01 result u16, 0x10 token
eq(tlv.pack(P.PDC.messages.DELETE_CONFIG.req, { config_type: 1, token: 3, id: [ 0xa9, 0x1c ] }),
	T(0x01, u32(1)) + T(0x10, u32(3)) + T(0x11, '\x02\xa9\x1c'), 'pdc delete: type, token, counted id');
let di = tlv.unpack(P.PDC.messages.DELETE_CONFIG_IND.ind, T(0x01, u16(0)) + T(0x10, u32(3)));
eq([ di.result, di.token ], [ 0, 3 ], 'pdc delete ind: result and token');

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
let handlers = {};
let fake = (schema) => ({
	schema: schema,
	on: (name, fn) => { handlers[name] = fn; },
	request: (name, args, cb) => {
		push(sent, name);
		push(pending, () => cb(null, answers[name] ?? {}));
	},
});

let events = [], sipd_calls = [], sipd_answer = { ok: true, parts: 1, refs: [ 3 ], via: 'ims' };
let inst = P.create({
	log: () => null,
	event: (type, data) => push(events, [ type, data ]),
	sipd_call: (method, args, cb) => { push(sipd_calls, [ method, args ]); cb(null, sipd_answer); },
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

// a sipd UE report (wwand.ims.ue) adds our own registration as a second row
inst.report_ue({ modem: 'm0', backend: 'ue', state: 'registered',
                 impu: 'sip:+4915550000001@ims.mnc002.mcc262.3gppnetwork.org',
                 pcscf: '2a01:8f0:400:955::5', calls: 1 });
let rows = inst.status('m0');
eq(type(rows), 'array', 'UE present: status returns both rows as an array');
eq(rows[0], { label: 'IMS UE', text: 'registered +4915550000001 via 2a01:8f0:400:955::5, 1 call(s)',
              level: 'ok' }, 'UE row: number, P-CSCF and active calls');
eq(rows[1].label, 'IMS', 'the modem-IMS row is kept as the second row');
// a UE report for another modem does not show on this one
inst.report_ue({ modem: 'mX', state: 'registered' });
eq(length(inst.status('m0')), 2, 'a UE report for another modem is not mixed in');
// a de-registered UE still shows, so the drop is visible
inst.report_ue({ modem: 'm0', state: 'down' });
eq(inst.status('m0')[0], { label: 'IMS UE', text: 'down', level: 'warn' }, 'UE row: down is shown, not hidden');

// a UE over VoWiFi: its tunnel in a row of its own, after the UE's
inst.report_ue({ modem: 'm0', state: 'registered', impu: 'sip:+4915550000001@ims.example.net', pcscf: '2001:db8:ff::5',
                 access: 'vowifi', vowifi: { state: 'up', epdg: 'epdg.example.net', v6: '2001:db8:aa::2', pcscf: [ '2001:db8:ff::5', '2001:db8:ff::6' ] } });
rows = inst.status('m0');
eq(rows[0].text, 'registered +4915550000001 over VoWiFi via 2001:db8:ff::5', 'UE row: registered over VoWiFi');
eq(rows[1], { label: 'VoWiFi', text: 'up to epdg.example.net, inner 2001:db8:aa::2, 2 P-CSCF', level: 'ok' },
	'VoWiFi row: up, the ePDG, the inner address, the P-CSCFs');
inst.report_ue({ modem: 'm0', state: 'down', vowifi: { state: 'down', epdg: 'epdg.example.net', error: 'charon: IKE SA down', tries: 2 } });
eq(inst.status('m0')[1], { label: 'VoWiFi', text: 'down: charon: IKE SA down (2 failed attempts)', level: 'warn' },
	'VoWiFi row: down with the reason and the attempts');
inst.report_ue({ modem: 'm0', state: 'down', vowifi: { state: 'connecting', epdg: 'epdg.example.net' } });
eq(inst.status('m0')[1].text, 'connecting to epdg.example.net', 'VoWiFi row: connecting');
inst.report_ue({ modem: 'm0', state: 'down' });
eq(inst.status('m0')[1].label, 'IMS', 'no VoWiFi in the report (IMS PDN): no VoWiFi row');
inst.report_ue({ modem: 'm0', state: 'registered', impu: 'sip:+4915550000001@ims.example.net', pcscf: '2001:db8:ff::5', access: 'volte' });
eq(inst.status('m0')[0].text, 'registered +4915550000001 over VoLTE via 2001:db8:ff::5', 'UE row: registered over VoLTE');
inst.report_ue({ modem: 'm0', state: 'down', access: 'vowifi' });
eq(inst.status('m0')[0].text, 'down (VoWiFi)', 'UE row: down, and over which way it tries');

// SMS over IMS: the plugin takes wwand's modem_sms_send while the UE has smsip on and is registered
let sms_r = null, sms_e = null;
let sms_cb = (e, r) => { sms_e = e; sms_r = r; };
eq(inst.sms_send('m0', {}, '+4915550000003', 'hi', sms_cb), false, 'sms_send: UE down -> the modem sends');
inst.report_ue({ modem: 'm0', backend: 'ue', state: 'registered', smsip: false });
eq(inst.sms_send('m0', {}, '+4915550000003', 'hi', sms_cb), false, 'sms_send: smsip off -> the modem sends');
inst.report_ue({ modem: 'm0', backend: 'ue', state: 'registered', smsip: true });
eq(inst.sms_send('m0', {}, '+4915550000003', 'hi', sms_cb), true, 'sms_send: smsip on, registered -> taken');
eq([ sipd_calls[0], sms_e, sms_r ], [ [ 'sms_send', { modem: 'm0', number: '+4915550000003', text: 'hi' } ],
	null, { parts: 1, refs: [ 3 ], via: 'ims' } ], 'sms_send: through sipd, its answer without ok');
sipd_answer = { ok: false, error: 'rp_error', cause: 42 };
inst.sms_send('m0', {}, '+4915550000003', 'hi', sms_cb);
eq([ sms_e, sms_r ], [ { error: 'rp_error', cause: 42 }, null ], 'sms_send: sipd\'s error as the error');
eq(inst.sms_send('mX', {}, '+4915550000003', 'hi', sms_cb), false, 'sms_send: another modem -> not taken');
inst.report_ue({ modem: 'm0', state: 'down' });

// indications become ubus events for the SIP side
handlers.ALL_CALL_STATUS_IND({ calls: [ { id: 2, state: 2, type: 0, direction: 2, mode: 4, mpty: 0, als: 0 } ],
                               remote: [ { id: 2, pi: 0, number: '+4930123' } ] });
eq(events[length(events) - 1], [ 'wwand.ims.call', { modem: 'm0', calls: [
	{ id: 2, state: 'incoming', direction: 'mt', mode: 'lte', number: '+4930123', end_reason: null } ] } ],
	'event: an incoming call is published as wwand.ims.call');
handlers.REG_STATUS_IND({ status: 0 });
eq(events[length(events) - 1], [ 'wwand.ims.registration', { modem: 'm0', status: 'not_registered', voice: 'unavailable' } ],
	'event: a registration change is published');

let dial = null;
inst.ops.dial('m0', {}, { number: '+491701234567' }, (e, r) => dial = r);
flush();
eq(dial, { id: 3, raw: null }, 'dial: call id from the response');
eq(length(opened), 4, 'dial: the clients are reused, not reopened');

let badt = null;
inst.ops.dial('m0', {}, { number: '+491701234567', call_type: 'video' }, (e) => badt = e);
eq(badt, { error: 'invalid_call_type' }, 'dial: an unknown call type is refused');

// volte_enable sends only what it is given (volte defaults to 1)
let vreq = null;
let inst_v = P.create({
	log: () => null,
	qmi_client: (ref, schema, cb) => cb(null, {
		on: () => null,
		request: (name, args, cb2) => { if (name == 'SET_SERVICE_ENABLE') vreq = args; cb2(null, {}); },
	}),
	qmi_release: () => null,
});
let vres = null;
inst_v.ops.volte_enable('m2', {}, { wifi: 1 }, (e, r) => vres = r);
eq(vreq, { volte: 1, wifi: 1 }, 'volte_enable: only volte and the given wifi switch are sent');
eq(tlv.pack(P.IMS.messages.SET_SERVICE_ENABLE.req, vreq), T(0x10, u8(1)) + T(0x14, u8(1)),
	'volte_enable: VoLTE 0x10 and VoWiFi 0x14 TLVs (libqmi 1.38)');

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

// tick: keeps the clients open without any op, and reopens them after a
// modem reset (the teardown marks them destroyed)
answers.GET_ALL_CALL_INFO = { calls: [] };
answers.GET_SERVICES_STATUS = { sms: 2, voice: 2, sms_tech: 1, voice_tech: 1 };
let clients3 = [], events3 = [], opened3 = 0;
let inst3 = P.create({
	log: () => null,
	event: (type, data) => push(events3, [ type, data ]),
	qmi_client: (ref, schema, cb) => {
		opened3++;
		let c = fake(schema);
		push(clients3, c);
		cb(null, c);
	},
	qmi_release: () => null,
});
inst3.tick('m3', {});
flush();
eq(opened3, 4, 'tick: opens the four clients with no op called');
eq(inst3.status('m3').text, 'registered, voice available', 'tick: the state is read once on open');
inst3.tick('m3', {});
flush();
eq(opened3, 4, 'tick: open clients are kept');

handlers.ALL_CALL_STATUS_IND({ calls: [ { id: 4, state: 3, type: 0, direction: 1, mode: 4, mpty: 0, als: 0 } ] });
for (let c in clients3)
	c.destroyed = true;
answers.GET_REG_STATUS = { status: 0 };
events3 = [];
inst3.tick('m3', {});
eq(events3[0], [ 'wwand.ims.call', { modem: 'm3', calls: [] } ],
	'tick after a reset: the call that was up is reported gone');
flush();
eq(opened3, 8, 'tick after a reset: four new clients');
eq(inst3.status('m3').text, 'not_registered, voice available', 'tick after a reset: the state is read anew');
answers.GET_REG_STATUS = { status: 2, tech: 1 };

// a modem without IMSA is asked again (the refusal is local) and logged
// once; once IMS is switched on there, the next tick opens the clients
let asked4 = 0, logs4 = [], has_imsa = false;
let inst4 = P.create({
	log: (lv, msg) => push(logs4, msg),
	qmi_client: (ref, schema, cb) => {
		asked4++;
		(has_imsa || schema.service != 0x21) ? cb(null, fake(schema)) : cb({ error: 'service_unavailable' }, null);
	},
	qmi_release: () => null,
});
inst4.tick('m4', {});
inst4.tick('m4', {});
eq(asked4, 2, 'tick: a modem without IMSA is asked on every tick');
eq(length(filter(logs4, (m) => index(m, 'no IMS') >= 0)), 1, 'tick: and logged once');
eq(inst4.status('m4'), null, 'tick: and has no status row');
has_imsa = true;
inst4.tick('m4', {});
flush();
eq(inst4.status('m4')?.text, 'registered, voice available', 'tick: IMSA switched on later is picked up');

// a refused VoLTE switch on open is logged, the open still completes
let logs6 = [], st6 = null;
let inst6 = P.create({
	log: (lv, msg) => push(logs6, msg),
	qmi_client: (ref, schema, cb) => cb(null, {
		on: () => null,
		request: (name, args, cb2) => (name == 'SET_SERVICE_ENABLE')
			? cb2({ error: 'qmi', code: 71 }, null) : cb2(null, answers[name] ?? {}),
	}),
	qmi_release: () => null,
});
inst6.ops.status('m6', {}, {}, (e, r) => st6 = r);
ok(length(filter(logs6, (m) => index(m, 'volte enable refused (71)') >= 0)) == 1,
	'open: a refused VoLTE switch is logged with its QMI error');
eq(st6?.registration?.status, 'registered', 'open: and the op still answers');

// no client before the modem is READY: its service list is not read yet,
// and a refusal then must not count as "no IMS"
let state7 = 'INIT_TRANSPORT', asked7 = 0;
let inst7 = P.create({
	log: () => null,
	modem_of: (ref) => ({ modem: { state: state7 } }),
	qmi_client: (ref, schema, cb) => { asked7++; cb({ error: 'service_unavailable' }, null); },
	qmi_release: () => null,
});
inst7.tick('m7', {});
eq(asked7, 0, 'tick: nothing is opened before the modem is READY');
state7 = 'READY';
inst7.tick('m7', {});
eq(asked7, 1, 'tick: opened once the modem is READY');

let asked5 = 0;
let inst5 = P.create({
	log: () => null,
	qmi_client: (ref, schema, cb) => { asked5++; cb({ error: 'not_ready' }, null); },
	qmi_release: () => null,
});
inst5.tick('m5', {});
inst5.tick('m5', {});
eq(asked5, 2, 'tick: a modem that is not ready is asked again');

released = 0;
inst.stop();
eq(released, 4, 'stop: every client released');

done();
