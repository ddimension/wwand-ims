// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// A client of strongSwan's vici interface (charon's control socket,
// src/libcharon/plugins/vici/README.md of strongSwan 6.0.7). wwand-ims-vowifi
// drives charon through it alone: connections, the start and end of the
// tunnel, what it learnt — no swanctl.conf, no ipsec.conf.
//
// Transport: each packet is a 32-bit network-order length and the bytes.
// Packet: a type octet, for the named ones an 8-bit-length name, then the
// message. Message: elements SECTION_START (1, name), SECTION_END (2),
// KEY_VALUE (3, name, 16-bit-length value), LIST_START (4, name),
// LIST_ITEM (5, value), LIST_END (6).
//
// In ucode: a message is an object; a nested object is a section, an array
// of scalars a list, anything else a key/value (as a string, vici knows only
// strings). Decoding gives the same shape back. Object key order is kept,
// and vici cares (proposals, the order of local/remote rounds).
//
//   VICI.encode(obj) -> bytes            VICI.decode(bytes) -> obj | null
//   VICI.packet(type, name, obj) -> the framed bytes
//   let c = VICI.create({ socket, uloop, path, log, on_close })
//     on_close(why): charon closed the connection (restarted, crashed); the
//     next request connects again and registers the listeners anew
//   c.request(cmd, msg, cb(err, res))    one at a time, queued
//   c.stream(cmd, msg, event, on_item, cb)   a command that answers with
//                                       events first (list-sas: 'list-sa')
//   c.listen(event, fn(msg))             register for an event
//   c.close()

'use strict';

export const T = {
	CMD_REQUEST: 0, CMD_RESPONSE: 1, CMD_UNKNOWN: 2, EVENT_REGISTER: 3, EVENT_UNREGISTER: 4,
	EVENT_CONFIRM: 5, EVENT_UNKNOWN: 6, EVENT: 7,
};
const E = { SECTION_START: 1, SECTION_END: 2, KEY_VALUE: 3, LIST_START: 4, LIST_ITEM: 5, LIST_END: 6 };

function u16(n) { return chr((n >> 8) & 255, n & 255); }
function u32(n) { return chr((n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255); }

function name8(n)
{
	n = sprintf('%s', n);
	if (length(n) > 255)
		die(sprintf('vici: name too long: %s', substr(n, 0, 40)));
	return chr(length(n)) + n;
}

function value16(v)
{
	v = (type(v) == 'bool') ? (v ? 'yes' : 'no') : sprintf('%s', v);
	if (length(v) > 65535)
		die('vici: value too long');
	return u16(length(v)) + v;
}

export function encode(obj)
{
	let out = '';
	for (let k, v in obj ?? {}) {
		if (v == null)
			continue;
		if (type(v) == 'object')
			out += chr(E.SECTION_START) + name8(k) + encode(v) + chr(E.SECTION_END);
		else if (type(v) == 'array') {
			out += chr(E.LIST_START) + name8(k);
			for (let x in v)
				out += chr(E.LIST_ITEM) + value16(x);
			out += chr(E.LIST_END);
		}
		else
			out += chr(E.KEY_VALUE) + name8(k) + value16(v);
	}
	return out;
}

export function decode(s)
{
	let root = {}, stack = [ root ], list = null, p = 0, n = length(s ?? '');
	let byte = () => (p < n) ? ord(s, p++) : null;
	let name = () => {
		let l = byte();
		if (l == null || p + l > n)
			return null;
		let v = substr(s, p, l);
		p += l;
		return v;
	};
	let value = () => {
		if (p + 2 > n)
			return null;
		let l = (ord(s, p) << 8) | ord(s, p + 1);
		p += 2;
		if (p + l > n)
			return null;
		let v = substr(s, p, l);
		p += l;
		return v;
	};

	while (p < n) {
		let t = byte(), cur = stack[length(stack) - 1];
		if (t == E.SECTION_START) {
			let k = name();
			if (k == null || list)
				return null;
			cur[k] = {};
			push(stack, cur[k]);
		}
		else if (t == E.SECTION_END) {
			if (length(stack) < 2 || list)
				return null;
			pop(stack);
		}
		else if (t == E.KEY_VALUE) {
			let k = name(), v = (k != null) ? value() : null;
			if (v == null || list)
				return null;
			cur[k] = v;
		}
		else if (t == E.LIST_START) {
			let k = name();
			if (k == null || list)
				return null;
			list = cur[k] = [];
		}
		else if (t == E.LIST_ITEM) {
			let v = value();
			if (v == null || !list)
				return null;
			push(list, v);
		}
		else if (t == E.LIST_END) {
			if (!list)
				return null;
			list = null;
		}
		else
			return null;
	}
	return (length(stack) == 1 && !list) ? root : null;
}

export function packet(type, name, obj)
{
	let body = chr(type) + ((name != null) ? name8(name) : '') + ((obj != null) ? encode(obj) : '');
	return u32(length(body)) + body;
}

// one packet's bytes (without the length) -> { type, name, msg }
export function parse_packet(b)
{
	if (!length(b ?? ''))
		return null;
	let t = ord(b, 0), p = 1, nm = null;
	if (t == T.CMD_REQUEST || t == T.EVENT_REGISTER || t == T.EVENT_UNREGISTER || t == T.EVENT) {
		let l = ord(b, 1);
		if (l == null || 2 + l > length(b))
			return null;
		nm = substr(b, 2, l);
		p = 2 + l;
	}
	let msg = (p < length(b)) ? decode(substr(b, p)) : {};
	return (msg != null) ? { type: t, name: nm, msg: msg } : null;
}

// ---- the client ---------------------------------------------------------------------

export function create(o)
{
	let self = { closed: false };
	let log = o.log ?? (() => null);
	let socket = o.socket, uloop = o.uloop;
	let sock = null, handle = null, rx = '';
	let queue = [], cur = null;	// cur: { kind, name, cb, event, on_item }
	let listeners = {};

	let fail_all = (err) => {
		let q = cur ? [ cur, ...queue ] : queue;
		cur = null;
		queue = [];
		for (let x in q)
			x.cb?.(err, null);
	};

	let drop = (why) => {
		let had = (sock != null);
		handle?.delete();
		handle = null;
		sock?.close();
		sock = null;
		rx = '';
		if (why)
			log('warn', sprintf('vici: %s', why));
		fail_all({ error: 'vici', detail: why ?? 'closed' });
		// charon went away under us (not our own close): tell the owner
		if (had && why && !self.closed)
			o.on_close?.(why);
	};

	let next, on_packet;

	let send = (bytes) => {
		if (!sock || !sock.send(bytes)) {
			drop(sprintf('send failed: %s', socket.error() ?? '?'));
			return false;
		}
		return true;
	};

	let open = () => {
		if (sock)
			return true;
		sock = socket.create(socket.AF_UNIX, socket.SOCK_STREAM);
		if (!sock || !sock.connect({ path: o.path ?? '/var/run/charon.vici' })) {
			let e = socket.error();
			sock?.close();
			sock = null;
			return false;
		}
		handle = uloop.handle(sock, () => {
			let d = sock?.recv(65536);
			if (d == null || d == '')
				return drop('charon closed the connection');
			rx += d;
			while (length(rx) >= 4) {
				let l = (ord(rx, 0) << 24) | (ord(rx, 1) << 16) | (ord(rx, 2) << 8) | ord(rx, 3);
				if (length(rx) < 4 + l)
					break;
				let pk = parse_packet(substr(rx, 4, l));
				rx = substr(rx, 4 + l);
				if (pk)
					on_packet(pk);
				else
					log('warn', 'vici: a packet that does not parse');
			}
		}, uloop.ULOOP_READ);
		// the events asked for before the connection was (re)opened: first,
		// ahead of what waits, so no event of a new charon goes unheard
		let regs = map(keys(listeners), (ev) => ({ kind: 'register', name: ev, cb: null }));
		queue = [ ...regs, ...queue ];
		return true;
	};

	next = () => {
		if (cur || !length(queue) || self.closed)
			return;
		if (!open())
			return fail_all({ error: 'vici', detail: 'charon not reachable' });
		cur = shift(queue);
		if (cur.kind == 'register' || cur.kind == 'stream_reg')
			send(packet(T.EVENT_REGISTER, cur.name));
		else if (cur.kind == 'unregister')
			send(packet(T.EVENT_UNREGISTER, cur.name));
		else
			send(packet(T.CMD_REQUEST, cur.name, cur.msg));
	};

	on_packet = (pk) => {
		if (pk.type == T.EVENT) {
			if (cur?.kind == 'stream' && pk.name == cur.event)
				return cur.on_item?.(pk.msg);
			for (let fn in listeners[pk.name] ?? [])
				fn(pk.msg);
			return;
		}
		let c = cur;
		if (!c)
			return log('debug', sprintf('vici: an answer (%d) to nothing', pk.type));
		cur = null;
		if (pk.type == T.CMD_RESPONSE) {
			// the stream's events are not wanted any more: unregistered as the
			// next item, so its EVENT_CONFIRM is not taken for another's answer
			// (unless someone listens to that event for good)
			if (c.kind == 'stream' && !listeners[c.event])
				unshift(queue, { kind: 'unregister', name: c.event, cb: null });
			c.cb?.(null, pk.msg);
		}
		else if (pk.type == T.CMD_UNKNOWN)
			c.cb?.({ error: 'vici_unknown_command', command: c.name }, null);
		else if (pk.type == T.EVENT_CONFIRM) {
			if (c.kind == 'stream_reg') {
				// registered for the stream's events: now the command
				cur = c.then;
				send(packet(T.CMD_REQUEST, cur.name, cur.msg));
				return;
			}
			c.cb?.(null, {});
		}
		else if (pk.type == T.EVENT_UNKNOWN)
			c.cb?.({ error: 'vici_unknown_event', event: c.name }, null);
		next();
	};

	self.request = function(cmd, msg, cb) {
		push(queue, { kind: 'cmd', name: cmd, msg: msg ?? {}, cb: cb });
		next();
	};

	// a command whose result comes as events of `event` before its response
	self.stream = function(cmd, msg, event, on_item, cb) {
		let then = { kind: 'stream', name: cmd, msg: msg ?? {}, event: event, on_item: on_item, cb: cb };
		push(queue, { kind: 'stream_reg', name: event, then: then, cb: (err) => cb?.(err, null) });
		next();
	};

	self.listen = function(event, fn) {
		let first = !listeners[event];
		listeners[event] ??= [];
		push(listeners[event], fn);
		// registered now on an open connection; a closed one registers all
		// listeners when it opens (open())
		if (first && sock) {
			push(queue, { kind: 'register', name: event, cb: null });
			next();
		}
		else if (first && open())
			next();
	};

	self.close = function() {
		self.closed = true;
		listeners = {};
		drop(null);
	};

	return self;
}
