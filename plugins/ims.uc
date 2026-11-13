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
import * as fs from 'fs';

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
		// Vendor IDL (ip_multimedia_subsystem_application_v01.c): Get IMS
		// Block Status 0x0037, 0x10/0x11/0x12 failure on WWAN/WLAN/C-IWLAN
		// (aggregates; kept raw)
		GET_BLOCK_STATUS: {
			id: 0x0037,
			req: {},
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
		// Vendor IDL (ip_multimedia_subsystem_settings_v01.c): Get QIPCall
		// Config 0x0037, 0x12 mobile_data_enabled, 0x13 volte_enabled
		GET_QIPCALL: {
			id: 0x0037,
			req: {},
			resp: {
				vt:          { t: 0x11, f: 'u8' },
				mobile_data: { t: 0x12, f: 'u8' },
				volte:       { t: 0x13, f: 'u8' },
			},
		},
		// Same IDL: Set IMS Service Enable Config 0x008F — the AP-side switch
		// that tells the call manager VoLTE is allowed (the IDL default is
		// DISABLED; the RIL sends it when the framework enables voice). A
		// device without a RIL never did, and the modem then refuses MO calls
		// instead of routing them to IMS. TLV numbering starts at 0x10
		// (result = 0x02): volte 0x10, vt 0x11, mobile_data 0x12, wifi 0x14,
		// ims_service 0x18, ut 0x19, sms 0x1A, ussd 0x1C — the GET 0x0090
		// tail (reg/ut/sms/ussd) is HW-verified on the RG650E.
		SET_SERVICE_ENABLE: {
			id: 0x008F,
			req: {
				volte:       { t: 0x10, f: 'u8' },
				vt:          { t: 0x11, f: 'u8' },
				mobile_data: { t: 0x12, f: 'u8' },
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
		// Vendor IDL (network_access_service_v01.c): Get IMS Preference
		// Status 0x0073, 0x10 ims_pref = sys_mode (1-byte enum) + call-type
		// mask u64 (VOICE 0x01, SMS 0x02). What the call manager thinks IMS
		// may carry, as opposed to what IMSA reports.
		GET_IMS_PREF: {
			id: 0x0073,
			req: {},
			resp: { pref: { t: 0x10, f: { sys_mode: 'u8', call_types: 'u64' } } },
		},
		// Get System Selection Preference 0x0034 (libqmi and vendor IDL):
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
		// Vendor IDL voice_v02 0x0044: bind the client to a subscription
		// (PRIMARY 0 / SECONDARY 1 / TERTIARY 2), mandatory field subs_type.
		// On a DSDS modem an unbound voice client has no user context, and
		// the dial dies in the modem's own bridge with InvalidArgument (48).
		BIND_SUBSCRIPTION: {
			id: 0x0044,
			req: { subs_type: { t: 0x01, f: 'u8' } },
			resp: {},
		},
		// 0x10 call type: not in libqmi 1.38's Dial Call, but oFono's QMI
		// voice driver sends it there as a u8 (qmimodem "implement voice
		// calls", Alexander Couzens, 2017-07-25, as carried in pmaports);
		// the values are libqmi's QmiVoiceCallType (VOICE 0, VOICE_IP 2)
		DIAL_CALL: {
			id: 0x0020,
			req:  { number: { t: 0x01, f: 'string' }, call_type: { t: 0x10, f: 'u8' } },
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
		ALL_CALL_STATUS_IND: {
			id: 0x002E,
			ind: {
				calls:  { t: 0x01, f: CALL_INFO_F },
				remote: { t: 0x10, f: REMOTE_F },
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
const CALL_MODE  = [ 'unknown', 'cdma', 'gsm', 'umts', 'lte' ];
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
	let nums = {};

	for (let r in (d?.remote ?? []))
		nums[sprintf('%d', r.id)] = r.number;

	return map(d?.calls ?? [], (c) => ({
		id: c.id,
		state: name_of(CALL_STATE, c.state),
		direction: name_of(CALL_DIR, c.direction),
		// lte = the call runs over IMS; gsm/umts = it went to CS
		mode: name_of(CALL_MODE, c.mode),
		number: nums[sprintf('%d', c.id)] ?? null,
	}));
}

function create(deps)
{
	let log = deps.log;
	// per modem: { imsa, ims, nas, voice, reg, services, calls, opening }
	let st = {};

	let state_of = (ref) => {
		if (!st[ref])
			st[ref] = { calls: [], waiters: [] };
		return st[ref];
	};

	// indications: kept so status() can answer without I/O
	let install = (ref, s, done) => {
		s.imsa.on('REG_STATUS_IND', (d) => {
			s.reg = { ...(s.reg ?? {}), ...d };
			log('info', sprintf('ims %s: registration %s%s', ref, name_of(REG_STATUS, d.status) ?? '?',
				d.err_code ? sprintf(' (error %d%s)', d.err_code, d.err_msg ? ': ' + d.err_msg : '') : ''));
		});
		s.imsa.on('SERVICES_STATUS_IND', (d) => {
			s.services = { ...(s.services ?? {}), ...d };
			log('info', sprintf('ims %s: services sms %s, voice %s', ref,
				name_of(SERVICE, s.services.sms) ?? '?', name_of(SERVICE, s.services.voice) ?? '?'));
		});
		s.voice.on('ALL_CALL_STATUS_IND', (d) => {
			s.calls = calls_of(d);
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
			// The IDL default is volte DISABLED; a device without a RIL never
			// enables it, and the call manager then refuses MO calls instead
			// of routing them to IMS. The write is idempotent and takes effect
			// at the next registration — re-apply on every open, so a modem
			// reset cannot leave the box without it.
			s.ims.request('SET_SERVICE_ENABLE', {
				volte: 1, mobile_data: 1, ims_service: 1, ut: 1, sms: 1, ussd: 1,
			}, (e) => log(e ? 'warn' : 'info', sprintf('ims %s: volte enable %s', ref,
				e ? sprintf('refused (%s)', err_of(e)) : 'sent')));
			done();
		}));
		s.voice.request('INDICATION_REGISTER', { call_events: 1 }, () => null);
		// the voice client must own a subscription on a DSDS modem, or every
		// dial dies inside the modem's QMI/AT bridge (InvalidArgument)
		s.voice.request('BIND_SUBSCRIPTION', { subs_type: 0 }, (e) =>
			log(e ? 'warn' : 'info', sprintf('ims %s: voice subs bind %s', ref,
				e ? sprintf('refused (%s)', err_of(e)) : 'primary 0')));
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

	// A modem reset closes the channel under the clients we keep, and every
	// request on them then ends as `cancelled` (HW-observed after a modem
	// reset on the RG650E, 2026-11-13). Drop them and open new ones, once.
	let stale = (e) => e?.error == 'cancelled';
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

	return {
		status: (ref) => {
			let s = st[ref];

			if (!s?.reg)
				return null;

			let reg = name_of(REG_STATUS, s.reg.status) ?? '?';
			let voice = name_of(SERVICE, s.services?.voice);
			let calls = filter(s.calls ?? [], (c) => c.state != 'end');

			return { label: 'IMS',
			         text: sprintf('%s%s%s', reg,
			                       voice ? ', voice ' + voice : '',
			                       length(calls) ? sprintf(', %d call(s)', length(calls)) : ''),
			         level: (s.reg.status == 2) ? 'ok' : 'warn' };
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
				all([ [ 'pref', s.nas, 'GET_IMS_PREF' ], [ 'ssp', s.nas, 'GET_SSP' ],
				      [ 'qip', s.ims, 'GET_QIPCALL' ], [ 'block', s.imsa, 'GET_BLOCK_STATUS' ] ], (r) => {
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
						qipcall: one(r.qip, (d) => ({
							volte: d.volte, mobile_data: d.mobile_data, vt: d.vt,
						})),
						block: one(r.block, (d) => ({ raw: raw_of(d) })),
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
					s.voice.request('DIAL_CALL', { number: num, call_type: ct }, (e, d) => {
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
			volte_enable: (ref, ext, args, cb) => use(ref, cb, (s, done) => {
				let on = args?.volte ?? 1;

				s.ims.request('SET_SERVICE_ENABLE', {
					volte: on, mobile_data: args?.mobile_data ?? 1,
					ims_service: args?.reg ?? 1, ut: args?.ut ?? 1,
					sms: args?.sms ?? 1, ussd: args?.ussd ?? 1,
				}, (e, d) => {
					if (stale(e))
						return done(null, null, true);
					if (e)
						return done({ error: err_of(e), raw: raw_of(d) });
					log('info', sprintf('ims %s: volte enabled: %d', ref, on));
					done(null, { volte: on });
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
