// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// wwand plugin: the modem's own IMS stack, read and driven over QMI.
//
// The modem registers with the operator's IMS and carries the call; this
// plugin only asks it how that stands and places/ends calls. It opens its
// clients through deps.qmi_client, on the modem's own channel, so the daemon
// keeps the control device and nothing has to stop (a remote SIM served by
// wwand-rsim stays up).
//
// Every message and TLV below is anchored to libqmi 1.38
// (data/qmi-service-{imsa,ims,voice,nas}.json, enums in
// src/libqmi-glib/qmi-enums-{imsa,nas,voice}.h). Nothing here comes from
// any other source.
//
//   ubus call wwand modem_plugin '{"modem":"wwmodem0","plugin":"ims","op":"status"}'
//   ... "op":"dial","args":{"number":"+49..."}   /  "op":"hangup","args":{"id":1}
//   ... "op":"calls"

'use strict';

import * as uloop from 'uloop';
import * as ubus from 'ubus';
import * as fs from 'fs';

// Our own IMS UE runs in sipd (backend 'ue', sipd/line_ue.uc), not in this
// daemon. It broadcasts its state on the ubus event `wwand.ims.ue`; create()
// caches the latest per modem and status() renders it, so our registration
// shows next to the modem's in `wwandctl status`.
const UE_EVENT = 'wwand.ims.ue';

// render a cached sipd UE report (the event payload) into a status row
function ue_status_row(j)
{
	if (type(j) != 'object')
		return null;
	let num = match(j.impu ?? '', /sip:(\+?[0-9]+)@/)?.[1];
	let active = +(j.calls ?? 0);
	// the way to the IMS (sipd's `access`): VoWiFi over the ePDG tunnel,
	// VoLTE over the modem's IMS PDN
	let way = { vowifi: 'VoWiFi', volte: 'VoLTE' }[j.access];
	let text = (j.state == 'registered')
		? sprintf('registered%s%s%s%s', num ? ' ' + num : '',
		          way ? ' over ' + way : '',
		          j.pcscf ? ' via ' + j.pcscf : '',
		          active ? sprintf(', %d call(s)', active) : '')
		: sprintf('%s%s', j.state ?? 'down', way ? ' (' + way + ')' : '');
	return { label: 'IMS UE', text: text,
	         level: (j.state == 'registered') ? 'ok' : 'warn' };
}

// the VoWiFi tunnel of a sipd UE report (its `vowifi` member), as a row
function vowifi_status_row(j)
{
	let v = (type(j) == 'object') ? j.vowifi : null;
	if (type(v) != 'object')
		return null;
	let inner = join(' ', filter([ v.v6, v.v4 ], (x) => x));
	let text;
	if (v.state == 'up')
		text = sprintf('up to %s%s%s', v.epdg ?? '?', length(inner) ? ', inner ' + inner : '',
			length(v.pcscf ?? []) ? sprintf(', %d P-CSCF', length(v.pcscf)) : '');
	else if (v.state == 'connecting')
		text = sprintf('connecting to %s', v.epdg ?? '?');
	else
		text = sprintf('%s%s%s', v.state ?? 'down', v.error ? ': ' + v.error : '',
			+(v.tries ?? 0) ? sprintf(' (%d failed attempts)', +v.tries) : '');
	return { label: 'VoWiFi', text: text, level: (v.state == 'up') ? 'ok' : 'warn' };
}

// ---- schemas (libqmi 1.38)---------------------------------------------

// IMSA, service 0x21
const IMSA = {
	service: 0x21,
	messages: {
		GET_REG_STATUS: {
			id: 0x0020,
			req: {},
			resp: {
				err_code: { t: 0x11, f: 'u16' },
				status:   { t: 0x12, f: 'u32' },	// QmiImsaImsRegistrationStatus
				err_msg:  { t: 0x13, f: 'string' },
				tech:     { t: 0x14, f: 'u32' },	// QmiImsaRegistrationTechnology
			},
		},
		GET_SERVICES_STATUS: {
			id: 0x0021,
			req: {},
			resp: {
				sms:        { t: 0x10, f: 'u32' },	// QmiImsaServiceStatus
				voice:      { t: 0x11, f: 'u32' },
				vt:         { t: 0x12, f: 'u32' },
				sms_tech:   { t: 0x13, f: 'u32' },	// QmiImsaRegistrationTechnology
				voice_tech: { t: 0x14, f: 'u32' },
				vt_tech:    { t: 0x15, f: 'u32' },
				ut:         { t: 0x16, f: 'u32' },
				ut_tech:    { t: 0x17, f: 'u32' },
			},
		},
		REGISTER_INDICATIONS: {
			id: 0x0022,
			req: {
				reg:      { t: 0x10, f: 'u8' },
				services: { t: 0x11, f: 'u8' },
			},
			resp: {},
		},
		REG_STATUS_IND: {
			id: 0x0023,
			ind: {
				err_code: { t: 0x10, f: 'u16' },
				status:   { t: 0x11, f: 'u32' },
				err_msg:  { t: 0x12, f: 'string' },
				tech:     { t: 0x13, f: 'u32' },
			},
		},
		// libqmi: "Bind" 0x0033, input 0x10 Binding (u32), since 1.36
		BIND: {
			id: 0x0033,
			req: { binding: { t: 0x10, f: 'u32' } },
			resp: {},
		},
		SERVICES_STATUS_IND: {
			id: 0x0024,
			ind: {
				sms:        { t: 0x10, f: 'u32' },
				voice:      { t: 0x11, f: 'u32' },
				vt:         { t: 0x12, f: 'u32' },
				sms_tech:   { t: 0x13, f: 'u32' },
				voice_tech: { t: 0x14, f: 'u32' },
				vt_tech:    { t: 0x15, f: 'u32' },
			},
		},
	},
};

// IMS settings, service 0x12: what the modem has switched on
const IMS = {
	service: 0x12,
	messages: {
		// libqmi: "Bind" 0x0098, input 0x01 Binding (u32), since 1.36
		BIND: {
			id: 0x0098,
			req: { binding: { t: 0x01, f: 'u32' } },
			resp: {},
		},
		GET_SERVICES_ENABLED: {
			id: 0x0090,
			req: {},
			resp: {
				voice:     { t: 0x11, f: 'u8' },
				vt:        { t: 0x12, f: 'u8' },
				voice_wifi: { t: 0x15, f: 'u8' },
				reg:       { t: 0x18, f: 'u8' },
				ut:        { t: 0x19, f: 'u8' },
				sms:       { t: 0x1A, f: 'u8' },
				ussd:      { t: 0x1C, f: 'u8' },
			},
		},
		// Set IMS Services Enabled Setting 0x008F (libqmi 1.38
		// qmi-service-ims.json, since 1.38): volte 0x10, vt 0x11, wifi 0x14,
		// ims_service 0x18, ut 0x19, sms 0x1A, ussd 0x1C. Without volte=1 the
		// modem refuses every MO call before any radio activity, with Dial
		// Call InvalidArgument (HW-observed on the RG650E, GDSP SIM,
		// 2026-11-13): a box without an Android RIL never sends it.
		SET_SERVICE_ENABLE: {
			id: 0x008F,
			req: {
				volte:       { t: 0x10, f: 'u8' },
				vt:          { t: 0x11, f: 'u8' },
				wifi:        { t: 0x14, f: 'u8' },
				ims_service: { t: 0x18, f: 'u8' },
				ut:          { t: 0x19, f: 'u8' },
				sms:         { t: 0x1A, f: 'u8' },
				ussd:        { t: 0x1C, f: 'u8' },
			},
			resp: {},
		},
	},
};

// NAS, service 0x03: only the two Get System Info TLVs that say whether the
// network offers voice over IMS (the MME's "IMS voice over PS session
// supported" from the attach/TAU accept)
const NAS = {
	service: 0x03,
	messages: {
		GET_SYSTEM_INFO: {
			id: 0x004D,
			req: {},
			resp: {
				ims_voice:   { t: 0x29, f: 'u8' },
				voice_domain: { t: 0x2A, f: 'u32' },	// QmiNasLteVoiceDomain
			},
		},
		// Get IMS Preference 0x0073 (Gobi API 2013-07-31, QMIEnum.h
		// eQMI_NAS_GET_IMS_PREFERENCE // 115; GobiConnectionMgmtAPIStructs.h
		// sNASGetIMSPreferenceResponse_IMSPreferenceInfo): TLV 0x10 = radio
		// interface (u8) + 64-bit mask, voice bit 0, SMS bit 1. What the call
		// manager thinks IMS may carry, as opposed to what IMSA reports.
		GET_IMS_PREF: {
			id: 0x0073,
			req: {},
			resp: { pref: { t: 0x10, f: { sys_mode: 'u8', call_types: 'u64' } } },
		},
		// Get System Selection Preference 0x0034 (libqmi 1.38 qmi-service-nas.json):
		// 0x18 service domain, 0x1F usage setting, 0x20 voice domain pref
		GET_SSP: {
			id: 0x0034,
			req: {},
			resp: {
				srv_domain:   { t: 0x18, f: 'u32' },
				usage:        { t: 0x1F, f: 'u32' },
				voice_domain: { t: 0x20, f: 'u32' },
			},
		},
	},
};

// Voice, service 0x09
const CALL_INFO_F = { n: 'u8', of: {
	id: 'u8', state: 'u8', type: 'u8', direction: 'u8', mode: 'u8', mpty: 'u8', als: 'u8',
} };
const REMOTE_F = { n: 'u8', of: { id: 'u8', pi: 'u8', number: 'lstring' } };

const VOICE = {
	service: 0x09,
	messages: {
		INDICATION_REGISTER: {
			id: 0x0003,
			req: { call_events: { t: 0x13, f: 'u8' } },
			resp: {},
		},
		// Beyond libqmi 1.38's 0x01 number, the Gobi API (2013-07-31,
		// GobiConnectionMgmtAPIStructs.h, VoiceCallOriginate = service 9 /
		// message 32) defines 0x10 call type (u8, eQMIVoiceCallTypes; also
		// what oFono's QMI voice driver sends), 0x18 audio attribute and 0x19
		// video attribute (64-bit masks: bit 0 TX, bit 1 RX). A stock Android
		// RIL dials with audio 3 (TX|RX) and video 0 (OnePlus 8T, OOS 14,
		// research/op8t-20261113).
		DIAL_CALL: {
			id: 0x0020,
			req:  { number: { t: 0x01, f: 'string' }, call_type: { t: 0x10, f: 'u8' },
			        audio: { t: 0x18, f: 'u64' }, video: { t: 0x19, f: 'u64' } },
			resp: { id: { t: 0x10, f: 'u8' } },
		},
		END_CALL: {
			id: 0x0021,
			req:  { id: { t: 0x01, f: 'u8' } },
			resp: { id: { t: 0x10, f: 'u8' } },
		},
		ANSWER_CALL: {
			id: 0x0022,
			req:  { id: { t: 0x01, f: 'u8' } },
			resp: { id: { t: 0x10, f: 'u8' } },
		},
		// 0x14 call end reason: not in libqmi 1.38; the Gobi API
		// (2013-07-31, GobiConnectionMgmtAPIStructs.h
		// sVoiceAllCallStatusIndication_CallEndReason) has it as a count
		// and per call { id u8, reason u16 }. The reason values of that
		// 2013 table are not trusted for current firmware: passed on as
		// numbers, never named.
		ALL_CALL_STATUS_IND: {
			id: 0x002E,
			ind: {
				calls:  { t: 0x01, f: CALL_INFO_F },
				remote: { t: 0x10, f: REMOTE_F },
				ends:   { t: 0x14, f: { n: 'u8', of: { id: 'u8', reason: 'u16' } } },
			},
		},
		GET_ALL_CALL_INFO: {
			id: 0x002F,
			req: {},
			resp: {
				calls:  { t: 0x10, f: CALL_INFO_F },
				remote: { t: 0x11, f: REMOTE_F },
			},
		},
	},
};

// PDC, service 0x24: only the two messages the wwand core leaves out on
// purpose (it lists, reads and selects; see its codec/schema/pdc.uc). Loading
// a carrier configuration belongs here, in a plugin that is not for upstream.
//
// libqmi QmiPdcConfigurationType: PLATFORM = 0, SOFTWARE = 1. Carrier MBNs
// (mcfg_sw) are SOFTWARE, and that is the type qmicli --pdc-load-config sends.
// A load with 0 asks the modem for a platform (mcfg_hw) config.
const PDC_TYPE_SOFTWARE = 1;
const PDC_CHUNK = 1024;		// qmicli's LOAD_CONFIG_CHUNK_SIZE

const PDC = {
	service: 0x24,
	messages: {
		// without it the modem acknowledges every request and never indicates
		REGISTER: {
			id: 0x0020,
			req:  { enable: { t: 0x10, f: 'u8' } },
			resp: {},
		},
		// libqmi "Load Config" 0x26, input 0x01 Config Chunk: type u32, id
		// (u8-prefixed bytes), total size u32, chunk (u16-prefixed bytes);
		// 0x10 token. The id is the SHA-1 of the whole file (qmicli), which is
		// also what List Configs then reports for it.
		LOAD_CONFIG: {
			id: 0x0026,
			req: {
				chunk: { t: 0x01, f: {
					type: 'u32', id_len: 'u8', id: 'bytes',
					total: 'u32', chunk_len: 'u16', data: 'bytes',
				} },
				token: { t: 0x10, f: 'u32' },
			},
			resp: {},
		},
		LOAD_CONFIG_IND: {
			id: 0x0026,
			ind: {
				token:       { t: 0x10, f: 'u32' },
				result:      { t: 0x01, f: 'u16' },
				received:    { t: 0x11, f: 'u32' },
				remaining:   { t: 0x12, f: 'u32' },
				frame_reset: { t: 0x13, f: 'u8' },
			},
		},
		// libqmi "Activate Config" 0x27: 0x01 config type u32, 0x10 token.
		// Applies the selected config; the modem resets to do it.
		ACTIVATE_CONFIG: {
			id: 0x0027,
			req: {
				config_type: { t: 0x01, f: 'u32' },
				token:       { t: 0x10, f: 'u32' },
			},
			resp: {},
		},
		ACTIVATE_CONFIG_IND: {
			id: 0x0027,
			ind: {
				result: { t: 0x01, f: 'u16' },
				token:  { t: 0x10, f: 'u32' },
			},
		},
		// libqmi "Delete Config" 0x25: 0x01 config type u32, 0x10 token, 0x11
		// id (u8-counted bytes). Removes a loaded config from the modem's
		// store. libqmi defines no indication for it; the OnePlus 8T's IDL
		// (research/op8t-20261113/idl-libqmiservices.json, PDC ind 0x0025)
		// has one: 0x01 result (2-byte enum), 0x10 token
		// (docs/qmi-beyond-libqmi.md).
		DELETE_CONFIG: {
			id: 0x0025,
			req: {
				config_type: { t: 0x01, f: 'u32' },
				token:       { t: 0x10, f: 'u32' },
				id:          { t: 0x11, f: { n: 'u8', of: 'u8' } },
			},
			resp: {},
		},
		// "Get Config" 0x30: reads a stored config back, one frame per
		// request. NOT in libqmi 1.38; from the Qualcomm IDL
		// (persistent_device_configuration_v01, QMI_PDC_GET_CONFIG; the
		// OnePlus 8T's libqmiservices.so has the same ids and widths): req
		// 0x01 config type u32, 0x10 token u32, 0x11 config id (u8-counted,
		// max 124), 0x12 subscription u32, 0x13 frame index u32; ind 0x01
		// error u16, 0x10 token, 0x11 frame index (0xFFFFFFFF = the last),
		// 0x12 the frame (u16-counted, max 32768) (docs/qmi-beyond-libqmi.md).
		GET_CONFIG: {
			id: 0x0030,
			req: {
				config_type: { t: 0x01, f: 'u32' },
				token:       { t: 0x10, f: 'u32' },
				id:          { t: 0x11, f: { n: 'u8', of: 'u8' } },
				sub:         { t: 0x12, f: 'u32' },
				frame:       { t: 0x13, f: 'u32' },
			},
			resp: {},
		},
		GET_CONFIG_IND: {
			id: 0x0030,
			ind: {
				result: { t: 0x01, f: 'u16' },
				token:  { t: 0x10, f: 'u32' },
				frame:  { t: 0x11, f: 'u32' },
				data:   { t: 0x12, f: { len: 'u16', data: 'bytes' } },
			},
		},
		DELETE_CONFIG_IND: {
			id: 0x0025,
			ind: {
				result: { t: 0x01, f: 'u16' },
				token:  { t: 0x10, f: 'u32' },
			},
		},
	},
};

// one Load Config request: the chunk at `off` of the file `data`
function pdc_chunk(data, id, off)
{
	let n = length(data) - off;

	if (n > PDC_CHUNK)
		n = PDC_CHUNK;

	return {
		type: PDC_TYPE_SOFTWARE, id_len: length(id), id: id,
		total: length(data), chunk_len: n, data: substr(data, off, n),
	};
}

function hex_to_bin(h)
{
	let out = '';

	for (let i = 0; i + 1 < length(h); i += 2)
		out += chr(hex(substr(h, i, 2)));

	return out;
}

// ---- enum names (libqmi 1.38 qmi-enums-*.h) -----------------------------

const REG_STATUS = [ 'not_registered', 'registering', 'registered', 'limited' ];
const SERVICE    = [ 'unavailable', 'limited', 'available' ];
const REG_TECH   = [ 'wlan', 'wwan', 'iwlan' ];
const LTE_VOICE  = [ 'none', 'ims' ];		// libqmi names only these two
const CALL_STATE = [ 'unknown', 'origination', 'incoming', 'conversation', 'cc_in_progress',
                     'alerting', 'hold', 'waiting', 'disconnecting', 'end', 'setup' ];
const CALL_DIR   = [ 'unknown', 'mo', 'mt' ];
// 0..4 as libqmi 1.38 names them; 5..7 from the Gobi API
// (eQMIVoiceCallModes). The Gobi API calls 6 "Unknown", which libqmi uses
// for 0, so 6 is named 'undetermined' here: the normal state while call
// control runs, before the modem picks a domain (stock RIL capture,
// research/op8t-20261113).
const CALL_MODE  = [ 'unknown', 'cdma', 'gsm', 'umts', 'lte', 'tdscdma', 'undetermined', 'wlan' ];
const CALL_TYPE  = { voice: 0, voice_ip: 2 };	// QmiVoiceCallType

// TLVs libqmi does not define, as hex, for the log: measured, not decoded
function raw_of(d)
{
	let out = {};

	for (let t, v in (d?._raw ?? {}))
		out[t] = join('', map(split(v, ''), (c) => sprintf('%02x', ord(c))));

	return length(keys(out)) ? out : null;
}

function name_of(table, v)
{
	return (v == null) ? null : (table[v] ?? sprintf('%d', v));
}

// one call list from the Voice call TLVs: the number joined by call id
function calls_of(d)
{
	let nums = {}, ends = {};

	for (let r in (d?.remote ?? []))
		nums[sprintf('%d', r.id)] = r.number;
	for (let e in (d?.ends ?? []))
		ends[sprintf('%d', e.id)] = e.reason;

	return map(d?.calls ?? [], (c) => ({
		id: c.id,
		state: name_of(CALL_STATE, c.state),
		direction: name_of(CALL_DIR, c.direction),
		// lte = the call runs over IMS; gsm/umts = it went to CS
		mode: name_of(CALL_MODE, c.mode),
		number: nums[sprintf('%d', c.id)] ?? null,
		end_reason: ends[sprintf('%d', c.id)] ?? null,
	}));
}

function create(deps)
{
	let log = deps.log;
	// per modem: { imsa, ims, nas, voice, reg, services, calls, opening }
	let st = {};

	// ubus events for the SIP side (sipd): the plugin API has no event
	// hook, so the plugin keeps its own bus connection. deps.event replaces
	// it in tests.
	//   wwand.ims.call          { modem, calls: [ … ] }   every call change
	//   wwand.ims.registration  { modem, status, voice }  IMS state change
	let bus = null;
	let emit = (type, data) => {
		if (deps.event)
			return deps.event(type, data);
		try {
			if (!bus)
				bus = ubus.connect();
			bus?.event(type, data);
		}
		catch (e) {
			bus = null;
		}
	};

	// sipd's own IMS UE (backend 'ue') reports its state on `wwand.ims.ue`; keep
	// the latest per modem, with the local arrival time so a gone sipd ages out.
	// note_ue is also the test seam (tests have no bus, so they feed it directly).
	let ue_cache = {};
	let note_ue = (data) => {
		if (type(data) == 'object' && data.modem != null)
			ue_cache[data.modem] = { at: time(), data: data };
	};
	let ue_report = (ref) => {
		let e = ue_cache[ref];
		if (!e || (time() - e.at) > 30)	// no heartbeat for 30 s: sipd is gone
			return null;
		return ue_status_row(e.data);
	};
	let vowifi_report = (ref) => {
		let e = ue_cache[ref];
		if (!e || (time() - e.at) > 30)
			return null;
		return vowifi_status_row(e.data);
	};
	try {
		if (!bus)
			bus = ubus.connect();
		bus?.listener(UE_EVENT, (t, data) => note_ue(data));
	}
	catch (e) {
		bus = null;
	}

	let state_of = (ref) => {
		if (!st[ref])
			st[ref] = { calls: [], waiters: [] };
		return st[ref];
	};

	// several requests at once, one answer: { name: [err, data] }
	let all = (reqs, cb) => {
		let out = {}, left = length(reqs);

		if (!left)
			return cb(out);

		// one function call per request: a `for (let r in ...)` closure does
		// NOT get its own binding per pass in ucode, so callbacks that run
		// later (every real QMI answer) would all see the last request
		let ask = (name, cl, msg) => cl.request(msg, {}, (e, d) => {
			out[name] = [ e, d ];
			if (--left == 0)
				cb(out);
		});

		for (let r in reqs)
			ask(r[0], r[1], r[2]);
	};

	// the QMI error code where there is one (client.uc: { error: 'qmi', code })
	let err_of = (e) => e ? (e.code ?? e.error ?? 'error') : null;

	// indications: kept so status() can answer without I/O
	let install = (ref, s, done) => {
		s.imsa.on('REG_STATUS_IND', (d) => {
			s.reg = { ...(s.reg ?? {}), ...d };
			emit('wwand.ims.registration', { modem: ref, status: name_of(REG_STATUS, s.reg.status),
				voice: name_of(SERVICE, s.services?.voice) });
			log('info', sprintf('ims %s: registration %s%s', ref, name_of(REG_STATUS, d.status) ?? '?',
				d.err_code ? sprintf(' (error %d%s)', d.err_code, d.err_msg ? ': ' + d.err_msg : '') : ''));
		});
		s.imsa.on('SERVICES_STATUS_IND', (d) => {
			s.services = { ...(s.services ?? {}), ...d };
			emit('wwand.ims.registration', { modem: ref, status: name_of(REG_STATUS, s.reg?.status),
				voice: name_of(SERVICE, s.services.voice) });
			log('info', sprintf('ims %s: services sms %s, voice %s', ref,
				name_of(SERVICE, s.services.sms) ?? '?', name_of(SERVICE, s.services.voice) ?? '?'));
		});
		s.voice.on('ALL_CALL_STATUS_IND', (d) => {
			s.calls = calls_of(d);
			emit('wwand.ims.call', { modem: ref, calls: s.calls });
			let raw = raw_of(d);
			if (raw)
				log('info', sprintf('ims %s: call status raw %J', ref, raw));
			for (let c in s.calls)
				log('info', sprintf('ims %s: call %d %s %s over %s%s', ref, c.id, c.direction,
					c.state, c.mode, c.number ? ' ' + c.number : ''));
		});

		// Unbound, IMSA and IMS answer every read with InvalidOperation (70)
		// (HW-observed on the RG650E-EU, 2026-11-13). libqmi documents the
		// binding as a plain u32 and not its values; try 0, then 1, and keep
		// what the modem took.
		let bind = (cl, name, then) => {
			let tryv;
			tryv = (v) => cl.request('BIND', { binding: v }, (e) => {
				if (!e) {
					s.bound = s.bound ?? {};
					s.bound[name] = v;
					log('info', sprintf('ims %s: %s bound with %d', ref, name, v));
					return then();
				}
				if (v == 0)
					return tryv(1);
				log('warn', sprintf('ims %s: %s bind refused (%s)', ref, name, e.code ?? e.error));
				then();
			});
			tryv(0);
		};

		bind(s.imsa, 'imsa', () => bind(s.ims, 'ims', () => {
			s.imsa.request('REGISTER_INDICATIONS', { reg: 1, services: 1 }, () => null);
			// The switch is kept by the modem across a reset: set to 0, IMS
			// does not even register after one; set to 1, calls ring with no
			// further write (HW-observed on the RG650E, 2026-11-13). It is
			// written on every open anyway, so a box where the modem never
			// had it (no Android RIL ever sent it) or where something
			// cleared it recovers without anyone noticing.
			// only the VoLTE switch: the other services stay as the
			// carrier configuration has them
			s.ims.request('SET_SERVICE_ENABLE', { volte: 1 }, (e) => log(e ? 'warn' : 'info', sprintf('ims %s: volte enable %s', ref,
				e ? sprintf('refused (%s)', err_of(e)) : 'sent')));
			// The indications report changes only: on new clients (a daemon
			// start, the reopen after a modem reset) nothing arrives while the
			// state holds, and status() would show nothing, or the state from
			// before the reset. Read it once here.
			all([ [ 'reg', s.imsa, 'GET_REG_STATUS' ], [ 'svc', s.imsa, 'GET_SERVICES_STATUS' ] ], (r) => {
				if (!r.reg[0])
					s.reg = r.reg[1];
				if (!r.svc[0])
					s.services = r.svc[1];
				done();
			});
		}));
		s.voice.request('INDICATION_REGISTER', { call_events: 1 }, () => null);
	};

	// Open the four clients once per modem and keep them: the indications
	// (registration, service and call changes) only arrive on a client that
	// stays. cb(err, s).
	let open = (ref, cb) => {
		let s = state_of(ref);

		if (s.ready)
			return cb(null, s);

		push(s.waiters, cb);
		if (s.opening)
			return;
		s.opening = true;

		let got = {}, todo = [ [ 'imsa', IMSA ], [ 'ims', IMS ], [ 'nas', NAS ], [ 'voice', VOICE ] ];
		let step;

		let notify = (err) => {
			s.opening = false;
			s.ready = !err;
			let w = s.waiters;
			s.waiters = [];
			for (let f in w)
				f(err, err ? null : s);
		};

		// answered only once the clients are bound: a read before that
		// gets InvalidOperation
		let finish = (err) => {
			if (err) {
				for (let k, c in got)
					deps.qmi_release(ref, c);
				return notify(err);
			}

			for (let k, c in got)
				s[k] = c;
			install(ref, s, () => notify(null));
		};

		step = (i) => {
			if (i >= length(todo))
				return finish(null);

			deps.qmi_client(ref, todo[i][1], (err, cl) => {
				if (err)
					return finish({ error: 'qmi_client', service: todo[i][0], detail: err });
				got[todo[i][0]] = cl;
				step(i + 1);
			});
		};
		step(0);
	};

	// A modem reset closes the channel under the clients we keep, and every
	// request on them then ends as `cancelled` (HW-observed after a modem
	// reset on the RG650E, 2026-11-13). Drop them and open new ones, once.
	let stale = (e) => e?.error == 'cancelled';
	// The same reset seen without asking: the modem's teardown marks every
	// plugin client `destroyed` (wwand modem.uc extra_client). tick() looks
	// at this, so no QMI traffic is needed to notice.
	let dead = (s) => length(filter([ 'imsa', 'ims', 'nas', 'voice' ], (k) => s[k]?.destroyed)) > 0;
	// What was read on the old clients describes a modem that has since
	// restarted, so it goes with them. A call that was up is gone with the
	// reset, and sipd learns that from an empty call list (it ends every
	// call the list does not hold): without it the LAN phone stays in a
	// call nobody will end.
	let drop = (ref) => {
		let s = st[ref];

		if (!s)
			return;
		for (let k in [ 'imsa', 'ims', 'nas', 'voice' ])
			if (s[k]) {
				deps.qmi_release(ref, s[k]);
				s[k] = null;
			}
		s.ready = false;
		s.reg = null;
		s.services = null;
		if (length(filter(s.calls ?? [], (c) => c.state != 'end'))) {
			s.calls = [];
			emit('wwand.ims.call', { modem: ref, calls: [] });
		}
	};
	// body(s, done): done(err, result) or done(null, null, true) for stale
	let use = (ref, cb, body) => {
		let attempt;

		attempt = (n) => open(ref, (err, s) => {
			if (err)
				return cb(err);
			body(s, (e, r, was_stale) => {
				if (was_stale && n == 0) {
					drop(ref);
					return attempt(1);
				}
				cb(e, r);
			});
		});
		attempt(0);
	};

	// A PDC client of our own, only for the length of one op: PDC answers on
	// indications that carry the request's token, so the client keeps a
	// waiter table. cb(err, { ask, close }).
	let pdc_open = (ref, cb) => deps.qmi_client(ref, PDC, (err, cl) => {
		if (err)
			return cb({ error: 'qmi_client', service: 'pdc', detail: err });

		let waits = {}, token = 0;
		let deliver = (d) => {
			let key = sprintf('%u', d?.token ?? 0);
			let w = waits[key];

			if (!w)
				return;
			delete waits[key];
			w.timer.cancel();
			// the operation's verdict is on the indication, not the ack
			(d.result != null && d.result != 0)
				? w.cb({ error: 'pdc', code: d.result }, d)
				: w.cb(null, d);
		};

		cl.on('LOAD_CONFIG_IND', deliver);
		cl.on('ACTIVATE_CONFIG_IND', deliver);
		cl.on('DELETE_CONFIG_IND', deliver);
		cl.on('GET_CONFIG_IND', deliver);

		let close = () => {
			for (let k, w in waits)
				w.timer.cancel();
			waits = {};
			deps.qmi_release(ref, cl);
		};
		let ask = (name, args, ms, done) => {
			let key = sprintf('%u', ++token);

			waits[key] = {
				cb: done,
				timer: uloop.timer(ms, () => {
					delete waits[key];
					done({ error: 'pdc_timeout', op: name });
				}),
			};
			cl.request(name, { ...args, token: token }, (e) => {
				// a refused request gets no indication
				if (e && waits[key]) {
					waits[key].timer.cancel();
					delete waits[key];
					done(e);
				}
			});
		};

		cl.request('REGISTER', { enable: 1 }, (e) => {
			if (e) {
				close();
				return cb({ error: 'pdc_register', detail: err_of(e) });
			}
			cb(null, { ask: ask, close: close });
		});
	});

	// sipd's ubus object, asked asynchronously; deps.sipd_call is the test seam
	let sipd_call = deps.sipd_call ?? ((method, args, cb) => {
		if (!bus)
			try { bus = ubus.connect(); } catch (e) { bus = null; }
		if (!bus)
			return cb({ error: 'ubus' }, null);
		bus.defer('wwand-ims', method, args, (rc, res) => {
			if (rc != 0)
				return cb({ error: 'ubus', detail: rc }, null);
			cb(null, res);
		});
	});

	return {
		// test seam: feed a sipd UE report as if it arrived on `wwand.ims.ue`
		report_ue: note_ue,

		// wwand's modem_sms_send: over IMS while sipd's UE has SMS over IP on
		// (ims_modem option smsip) and is registered; else the modem sends it
		sms_send: (ref, ext, number, text, cb) => {
			let e = ue_cache[ref];
			if (!e || (time() - e.at) > 30 || !e.data?.smsip || e.data?.state != 'registered')
				return false;
			sipd_call('sms_send', { modem: ref, number: number, text: text }, (err, res) => {
				if (err)
					return cb(err, null);
				if (res?.ok === false) {
					let r = { ...res };
					delete r.ok;
					return cb(r, null);
				}
				let r = { ...(res ?? {}) };
				delete r.ok;
				cb(null, r);
			});
			return true;
		},
		// Keeps the clients open, so the indications (and with them the
		// wwand.ims.* events sipd rings phones on) run from the daemon start
		// and come back after a modem reset, without anyone calling an op.
		// A modem without IMS (no IMSA in its service list, or NCM) is asked
		// again on every tick, and logged once: the list is re-read on every
		// modem start, and a modem gains IMSA when IMS is switched on there
		// (AT+QCFG="ims",1 on the EG25-G, HW-observed 2026-11-13). The refusal
		// is local (wwand modem.uc extra_client checks the list it read), so
		// asking costs no QMI traffic.
		tick: (ref, ext) => {
			let s = st[ref];

			if (s?.opening || (s?.ready && !dead(s)))
				return;
			// at once, not when the modem is back: the call-gone event must
			// not wait for a modem that may take a minute to return
			if (s?.ready) {
				log('info', sprintf('ims %s: the modem restarted under the clients, opening new ones once it is ready', ref));
				drop(ref);
			}
			// Before READY the modem has not read its service list yet, and
			// every client is refused as service_unavailable: taken as final,
			// that would switch IMS off for good on every daemon start
			// (HW-observed on the RG650E, 2026-11-13: the first tick ran
			// before the modem's init).
			if (deps.modem_of && deps.modem_of(ref)?.modem?.state != 'READY')
				return;
			open(ref, (err) => {
				let why = err?.detail?.error;
				let s2 = state_of(ref);

				if (why == 'service_unavailable' || why == 'unsupported') {
					if (s2.no_ims != why)
						log('info', sprintf('ims %s: no IMS on this modem (%s: %s)', ref, err.service, why));
					s2.no_ims = why;
				}
				else if (!err && s2.no_ims) {
					log('info', sprintf('ims %s: IMS is available now', ref));
					s2.no_ims = null;
				}
			});
		},

		status: (ref) => {
			let s = st[ref];
			let rows = [];

			// our own UE (sipd backend 'ue'), if it is running on this modem
			let ue = ue_report(ref);
			if (ue)
				push(rows, ue);
			// its VoWiFi tunnel, when the UE reaches the IMS that way
			let vw = vowifi_report(ref);
			if (vw)
				push(rows, vw);

			// the modem's own IMS stack, when it is on (off in the UE design)
			if (s?.reg) {
				let reg = name_of(REG_STATUS, s.reg.status) ?? '?';
				let voice = name_of(SERVICE, s.services?.voice);
				let calls = filter(s.calls ?? [], (c) => c.state != 'end');

				push(rows, { label: 'IMS',
				             text: sprintf('%s%s%s', reg,
				                           voice ? ', voice ' + voice : '',
				                           length(calls) ? sprintf(', %d call(s)', length(calls)) : ''),
				             level: (s.reg.status == 2) ? 'ok' : 'warn' });
			}

			// one row stays a bare object (what plugins_status and the old
			// callers expect); only when both the UE and the modem-IMS row are
			// present do we hand back the array form plugins_status also takes
			return length(rows) > 1 ? rows : (rows[0] ?? null);
		},

		ops: {
			// what the modem's IMS stack says now
			status: (ref, ext, args, cb) => use(ref, cb, (s, done) => {
				all([ [ 'reg', s.imsa, 'GET_REG_STATUS' ], [ 'svc', s.imsa, 'GET_SERVICES_STATUS' ],
				      [ 'en', s.ims, 'GET_SERVICES_ENABLED' ], [ 'sys', s.nas, 'GET_SYSTEM_INFO' ],
				      [ 'calls', s.voice, 'GET_ALL_CALL_INFO' ] ], (r) => {
					// a QMI error answer still decodes to an (empty) object: only the
					// error says it failed
					let ok_of = (x) => x[0] ? null : x[1];
					let reg = ok_of(r.reg), svc = ok_of(r.svc), en = ok_of(r.en), sys = ok_of(r.sys);

					for (let k, x in r)
						if (stale(x[0]))
							return done(null, null, true);

					if (reg)
						s.reg = reg;
					if (svc)
						s.services = svc;
					if (ok_of(r.calls))
						s.calls = calls_of(r.calls[1]);

					done(null, {
						registration: reg ? {
							status: name_of(REG_STATUS, reg.status),
							technology: name_of(REG_TECH, reg.tech),
							error_code: reg.err_code ?? null,
							error_message: reg.err_msg ?? null,
						} : { error: err_of(r.reg[0]) },
						services: svc ? {
							sms: name_of(SERVICE, svc.sms), sms_tech: name_of(REG_TECH, svc.sms_tech),
							voice: name_of(SERVICE, svc.voice), voice_tech: name_of(REG_TECH, svc.voice_tech),
							video: name_of(SERVICE, svc.vt),
							ut: name_of(SERVICE, svc.ut),
						} : { error: err_of(r.svc[0]) },
						enabled: en ? {
							registration: en.reg, voice: en.voice, video: en.vt, voice_wifi: en.voice_wifi,
							sms: en.sms, ut: en.ut, ussd: en.ussd,
						} : { error: err_of(r.en[0]) },
						network: sys ? {
							ims_voice: sys.ims_voice,
							lte_voice_domain: name_of(LTE_VOICE, sys.voice_domain),
						} : { error: err_of(r.sys[0]) },
						calls: ok_of(r.calls) ? s.calls : { error: err_of(r.calls[0]) },
					});
				});
			}),

			// why the call manager might refuse a VoLTE origination
			diag: (ref, ext, args, cb) => use(ref, cb, (s, done) =>
				all([ [ 'pref', s.nas, 'GET_IMS_PREF' ], [ 'ssp', s.nas, 'GET_SSP' ] ], (r) => {
					for (let k, x in r)
						if (stale(x[0]))
							return done(null, null, true);

					let one = (x, f) => x[0] ? { error: err_of(x[0]) } : f(x[1]);

					done(null, {
						ims_pref: one(r.pref, (d) => d.pref ? {
							sys_mode: d.pref.sys_mode,
							call_types: sprintf('0x%x', d.pref.call_types),
							voice: !!(d.pref.call_types & 1), sms: !!(d.pref.call_types & 2),
						} : { absent: true, raw: raw_of(d) }),
						selection: one(r.ssp, (d) => ({
							srv_domain: d.srv_domain, usage: d.usage, voice_domain: d.voice_domain,
						})),
					});
				})),

			calls: (ref, ext, args, cb) => use(ref, cb, (s, done) =>
				s.voice.request('GET_ALL_CALL_INFO', {}, (e, d) => {
					if (stale(e))
						return done(null, null, true);
					if (e)
						return done({ error: err_of(e) });
					s.calls = calls_of(d);
					done(null, { calls: s.calls });
				})),

			dial: (ref, ext, args, cb) => {
				let num = args?.number;

				if (type(num) != 'string' || !match(num, /^\+?[0-9*#]{3,32}$/))
					return cb({ error: 'invalid_number' });

				let ct = null;

				if (args?.call_type != null) {
					ct = CALL_TYPE[args.call_type];
					if (ct == null)
						return cb({ error: 'invalid_call_type' });
				}

				use(ref, cb, (s, done) => {
					s.voice.request('DIAL_CALL', { number: num, call_type: ct, audio: 3, video: 0 }, (e, d) => {
						if (stale(e))
							return done(null, null, true);

						let raw = raw_of(d);

						log('info', sprintf('ims %s: dial %s%s -> %s%s', ref, num,
							(ct != null) ? ' type ' + args.call_type : '',
							e ? sprintf('error %s', err_of(e)) : sprintf('call %d', d?.id),
							raw ? sprintf(' raw %J', raw) : ''));
						e ? done({ error: err_of(e), raw: raw }) : done(null, { id: d?.id, raw: raw });
					});
				});
			},

			answer: (ref, ext, args, cb) => use(ref, cb, (s, done) =>
				s.voice.request('ANSWER_CALL', { id: +(args?.id ?? 1) }, (e, d) =>
					stale(e) ? done(null, null, true)
					         : e ? done({ error: err_of(e) }) : done(null, { id: d?.id }))),

			// Tell the call manager that VoLTE is allowed (SET_IMS_SERVICE_ENABLE
			// _CONFIG, the message a RIL sends when the framework enables
			// voice). The modem's default on a data-only build is volte off;
			// without this, every dial is refused before any radio activity.
			// Set IMS Services Enabled Setting (0x008F, libqmi 1.38) by hand.
			// Only what is passed is sent, so the MBN keeps everything else;
			// volte defaults to 1. wifi is the VoWiFi switch (TLV 0x14), the
			// one a stock RIL sets from the framework's WFC toggle (OnePlus 8T,
			// research/op8t-20261113, section 6); whether a module calls over
			// WLAN at all is a property of its firmware.
			//   args: { volte, wifi, reg, ut, sms, ussd }   (0 or 1 each)
			volte_enable: (ref, ext, args, cb) => use(ref, cb, (s, done) => {
				let req = { volte: args?.volte ?? 1 };
				let names = { wifi: 'wifi', reg: 'ims_service', ut: 'ut', sms: 'sms', ussd: 'ussd' };

				for (let a, f in names)
					if (args?.[a] != null)
						req[f] = args[a] ? 1 : 0;

				s.ims.request('SET_SERVICE_ENABLE', req, (e, d) => {
					if (stale(e))
						return done(null, null, true);
					if (e)
						return done({ error: err_of(e), raw: raw_of(d) });
					log('info', sprintf('ims %s: service enable %J', ref, req));
					done(null, req);
				});
			}),

			hangup: (ref, ext, args, cb) => use(ref, cb, (s, done) =>
				s.voice.request('END_CALL', { id: +(args?.id ?? 1) }, (e, d) =>
					stale(e) ? done(null, null, true)
					         : e ? done({ error: err_of(e) }) : done(null, { id: d?.id }))),

			// Load a carrier MBN file into the modem's config store (PDC Load
			// Config, as qmicli --pdc-load-config). It is then listed by
			// modem_carrier_config "list" under its SHA-1 and selected with
			// "set" + mbn_activate. args: { path }
			mbn_load: (ref, ext, args, cb) => {
				let path = args?.path;

				if (type(path) != 'string' || substr(path, 0, 1) != '/')
					return cb({ error: 'invalid_path' });

				let data = fs.readfile(path);

				if (data == null)
					return cb({ error: 'read_failed', detail: fs.error() });
				if (length(data) < 64 || length(data) > 4 * 1024 * 1024)
					return cb({ error: 'invalid_size', size: length(data) });

				let digest = require('digest');
				let id_hex = digest.sha1(data);
				let id = hex_to_bin(id_hex);

				pdc_open(ref, (err, p) => {
					if (err)
						return cb(err);

					let off = 0, n = 0, send;
					let fin = (e, r) => {
						p.close();
						log(e ? 'warn' : 'info', sprintf('ims %s: mbn load %s (%s): %s', ref, path, id_hex,
							e ? sprintf('%J at %d of %d', e, off, length(data)) : 'done'));
						e ? cb({ ...e, id: id_hex, offset: off, size: length(data) }) : cb(null, r);
					};

					send = () => {
						let c = pdc_chunk(data, id, off);

						off += c.chunk_len;
						n++;
						p.ask('LOAD_CONFIG', { chunk: c }, 10000, (e, d) => {
							if (e)
								return fin(e);
							if (d?.frame_reset)
								return fin({ error: 'frame_reset' });
							if (d?.remaining == 0)
								return fin(null, { id: id_hex, size: length(data), chunks: n });
							if (off >= length(data))
								return fin({ error: 'modem_wants_more', remaining: d?.remaining });
							send();
						});
					};
					send();
				});
			},

			// Read a stored carrier config back into a file (PDC Get Config,
			// frame by frame). args: { id (hex), path }. The file's SHA-1 is
			// then the id again: that is the check.
			mbn_read: (ref, ext, args, cb) => {
				let id = args?.id, path = args?.path;

				if (type(id) != 'string' || !match(id, /^([0-9a-fA-F][0-9a-fA-F])+$/))
					return cb({ error: 'invalid_id' });
				if (type(path) != 'string' || substr(path, 0, 1) != '/')
					return cb({ error: 'invalid_path' });
				pdc_open(ref, (err, p) => {
					if (err)
						return cb(err);
					let bytes = map(split(hex_to_bin(id), ''), (c) => ord(c));
					let parts = [], size = 0, next;
					let fin = (e, r) => {
						p.close();
						log(e ? 'warn' : 'info', sprintf('ims %s: mbn read %s: %s', ref, id,
							e ? sprintf('%J after %d frames', e, length(parts)) : sprintf('%d bytes', size)));
						e ? cb({ ...e, frames: length(parts) }) : cb(null, r);
					};
					let req = { config_type: PDC_TYPE_SOFTWARE };
					if (args.sub != null)
						req.sub = +args.sub;
					else
						req.id = bytes;
					next = () => p.ask('GET_CONFIG', { ...req, frame: length(parts) }, 10000, (e, d) => {
						log('debug', sprintf('ims %s: mbn read frame %d: %s, %d bytes', ref, length(parts),
							e ? sprintf('%J', e) : sprintf('index %J', d?.frame), length(d?.data?.data ?? '')));
						if (e)
							return fin(e);
						let chunk = d?.data?.data ?? '';
						if (d?.data?.len != null && d.data.len != length(chunk))
							return fin({ error: 'short_frame', len: d.data.len, got: length(chunk) });
						push(parts, chunk);
						size += length(chunk);
						if (size > 4 * 1024 * 1024)
							return fin({ error: 'too_large' });
						if (d?.frame == 0xffffffff || !length(chunk)) {
							let data = join('', parts);
							let sha = require('digest').sha1(data);
							if (!require('fs').writefile(path, data))
								return fin({ error: 'write_failed', path: path });
							return fin(null, { id: id, path: path, size: size, frames: length(parts), sha1: sha, match: sha == lc(id) });
						}
						next();
					});
					next();
				});
			},

			// Remove a loaded carrier config from the modem's store (PDC Delete
			// Config). args: { id } (hex, as modem_carrier_config lists it). The
			// caller makes sure it is neither active nor pending: the modem
			// decides what deleting the running config does. A modem that
			// sends no indication for it is taken at its acknowledgement.
			mbn_delete: (ref, ext, args, cb) => {
				let id = args?.id;

				if (type(id) != 'string' || !match(id, /^([0-9a-fA-F][0-9a-fA-F])+$/))
					return cb({ error: 'invalid_id' });
				pdc_open(ref, (err, p) => {
					if (err)
						return cb(err);
					let bytes = map(split(hex_to_bin(id), ''), (c) => ord(c));
					p.ask('DELETE_CONFIG', { config_type: PDC_TYPE_SOFTWARE, id: bytes }, 5000, (e) => {
						p.close();
						log(e ? 'warn' : 'info', sprintf('ims %s: mbn delete %s: %s', ref, id, e ? sprintf('%J', e) : 'ok'));
						if (e?.error == 'pdc_timeout')
							return cb(null, { id: id, indication: false });
						e ? cb(e) : cb(null, { id: id, indication: true });
					});
				});
			},

			// Apply the selected carrier config (PDC Activate Config). The
			// modem resets to do it, so the indication may never come: a
			// timeout here means "sent", and modem_carrier_config "get" after
			// the reset tells whether it took.
			mbn_activate: (ref, ext, args, cb) => pdc_open(ref, (err, p) => {
				if (err)
					return cb(err);

				p.ask('ACTIVATE_CONFIG', { config_type: PDC_TYPE_SOFTWARE }, 5000, (e) => {
					p.close();
					// the clients we keep die with the reset
					drop(ref);
					log('info', sprintf('ims %s: mbn activate: %s', ref, e ? sprintf('%J', e) : 'ok'));
					if (e?.error == 'pdc_timeout')
						return cb(null, { sent: true, indication: false });
					e ? cb(e) : cb(null, { sent: true, indication: true });
				});
			}),
		},
		read_ops: [ 'status', 'calls', 'diag' ],

		stop: () => {
			for (let ref in keys(st))
				drop(ref);
			return false;
		},
	};
}

return {
	// for the tests: the schemas and the call-list builder
	IMSA: IMSA, IMS: IMS, NAS: NAS, VOICE: VOICE, PDC: PDC, calls_of: calls_of,
	pdc_chunk: pdc_chunk, hex_to_bin: hex_to_bin,

	name: 'ims',
	options: [],
	create: create,
};
