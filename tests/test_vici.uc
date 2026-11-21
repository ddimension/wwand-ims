// Host tests for vowifi/vici.uc: the message codec against the encoding
// example of strongSwan's vici README (6.0.7), the packet layer, and the
// client against a stand-in for charon's socket.
'use strict';

import { eq, ok, done } from './lib/check.uc';
import * as VICI from 'vowifi_vici';

let bytes = (a) => join('', map(a, (x) => (type(x) == 'string') ? x : chr(x)));

// README "Encoding example": key1 = value1, section1 { sub-section { key2 = value2 }, list1 = [ item1, item2 ] }
let README = bytes([ 3, 4, 'key1', 0, 6, 'value1',
	1, 8, 'section1', 1, 11, 'sub-section', 3, 4, 'key2', 0, 6, 'value2', 2,
	4, 5, 'list1', 5, 0, 5, 'item1', 5, 0, 5, 'item2', 6, 2 ]);
let obj = { key1: 'value1', section1: { 'sub-section': { key2: 'value2' }, list1: [ 'item1', 'item2' ] } };
eq(hexenc(VICI.encode(obj)), hexenc(README), 'encode: the README example, byte for byte');
eq(VICI.decode(README), obj, 'decode: the README example');
eq(VICI.decode(VICI.encode({ a: 1, b: true, c: false, d: null })), { a: '1', b: 'yes', c: 'no' },
	'encode: numbers and booleans as vici strings, null left out');
eq(keys(VICI.decode(VICI.encode({ z: '1', a: '2', m: '3' }))), [ 'z', 'a', 'm' ], 'key order kept');
eq(VICI.decode(bytes([ 1, 3, 'abc' ])), null, 'decode: an unclosed section');
eq(VICI.decode(bytes([ 4, 1, 'l', 3, 1, 'k', 0, 1, 'v', 6 ])), null, 'decode: a key/value inside a list');
eq(VICI.decode(bytes([ 3, 4, 'key1', 0, 9, 'value1' ])), null, 'decode: a value longer than the message');
eq(VICI.decode(''), {}, 'decode: an empty message');

let pk = VICI.packet(VICI.T.CMD_REQUEST, 'version', null);
eq(hexenc(pk), hexenc(bytes([ 0, 0, 0, 9, 0, 7, 'version' ])), 'packet: CMD_REQUEST, its name, no message');
eq(VICI.parse_packet(substr(pk, 4)), { type: 0, name: 'version', msg: {} }, 'parse_packet: back');
eq(VICI.parse_packet(bytes([ 1, 3, 1, 'k', 0, 1, 'v' ])), { type: 1, name: null, msg: { k: 'v' } },
	'parse_packet: an unnamed CMD_RESPONSE with a message');

// ---- the client ------------------------------------------------------------------------

function charon()
{
	let w = { sent: [], handler: null, inbox: '', connected: null };
	w.socket = {
		AF_UNIX: 1, SOCK_STREAM: 1, error: () => 'none',
		create: () => ({
			connect: (a) => { w.connected = a.path; return true; },
			send: (b) => { push(w.sent, VICI.parse_packet(substr(b, 4))); return true; },
			recv: () => { let d = w.inbox; w.inbox = ''; return d; },
			close: () => null,
		}),
	};
	w.uloop = { ULOOP_READ: 1, handle: (s, fn) => { w.handler = fn; return { delete: () => null }; } };
	// charon answers: one or more packets at once, possibly split
	w.say = (...pks) => {
		w.inbox = join('', pks);
		w.handler();
	};
	return w;
}

let w = charon();
let c = VICI.create({ socket: w.socket, uloop: w.uloop, path: '/var/run/charon.vici' });
let got = [];
c.request('version', null, (e, r) => push(got, [ 'version', e, r ]));
c.request('load-conn', { epdg: { version: '2' } }, (e, r) => push(got, [ 'load', e, r ]));
eq([ w.connected, length(w.sent), w.sent[0].name ], [ '/var/run/charon.vici', 1, 'version' ],
	'client: connects, one command at a time');
w.say(VICI.packet(VICI.T.CMD_RESPONSE, null, { daemon: 'charon', version: '6.0.7' }));
eq(got[0], [ 'version', null, { daemon: 'charon', version: '6.0.7' } ], 'client: the answer to the first');
eq([ w.sent[1].name, w.sent[1].msg ], [ 'load-conn', { epdg: { version: '2' } } ], 'client: then the second');
w.say(VICI.packet(VICI.T.CMD_RESPONSE, null, { success: 'yes' }));
eq(got[1], [ 'load', null, { success: 'yes' } ], 'client: its answer');

// two packets in one read, and one split across two reads
got = [];
c.request('a', null, (e, r) => push(got, r));
c.request('b', null, (e, r) => push(got, r));
let two = VICI.packet(VICI.T.CMD_RESPONSE, null, { n: '1' }) + VICI.packet(VICI.T.CMD_RESPONSE, null, { n: '2' });
w.say(substr(two, 0, 7));
eq(got, [], 'client: half a packet is kept');
w.say(substr(two, 7));
eq(got, [ { n: '1' }, { n: '2' } ], 'client: the rest, and the next one in the same read');

// an unknown command
c.request('nosuch', null, (e, r) => push(got, e));
w.say(VICI.packet(VICI.T.CMD_UNKNOWN, null, null));
eq(got[2], { error: 'vici_unknown_command', command: 'nosuch' }, 'client: CMD_UNKNOWN as an error');

// a stream: register for the event, the command, its events, the response, unregister
w.sent = [];
let items = [], res = null;
c.stream('list-sas', { ike: 'epdg' }, 'list-sa', (m) => push(items, m), (e, r) => { res = r; });
eq([ w.sent[0].type, w.sent[0].name ], [ VICI.T.EVENT_REGISTER, 'list-sa' ], 'stream: registers for its event');
w.say(VICI.packet(VICI.T.EVENT_CONFIRM, null, null));
eq([ w.sent[1].type, w.sent[1].name, w.sent[1].msg ], [ VICI.T.CMD_REQUEST, 'list-sas', { ike: 'epdg' } ],
	'stream: then the command');
w.say(VICI.packet(VICI.T.EVENT, 'list-sa', { epdg: { state: 'ESTABLISHED' } }),
	VICI.packet(VICI.T.CMD_RESPONSE, null, {}));
eq([ items, res ], [ [ { epdg: { state: 'ESTABLISHED' } } ], {} ], 'stream: its events, then the response');
eq([ w.sent[2].type, w.sent[2].name ], [ VICI.T.EVENT_UNREGISTER, 'list-sa' ], 'stream: unregisters after');
let after = null;
c.request('version', null, (e, r) => { after = r; });
eq(length(w.sent), 3, 'stream: the next command waits for the unregister to be confirmed');
w.say(VICI.packet(VICI.T.EVENT_CONFIRM, null, null));
eq(w.sent[3].name, 'version', 'stream: then goes out');
w.say(VICI.packet(VICI.T.CMD_RESPONSE, null, { v: '1' }));
eq(after, { v: '1' }, 'stream: and gets its own answer, not the unregister\'s');

// events to a listener
let logs = [];
c.listen('log', (m) => push(logs, m.msg));
eq([ w.sent[4].type, w.sent[4].name ], [ VICI.T.EVENT_REGISTER, 'log' ], 'listen: registers');
w.say(VICI.packet(VICI.T.EVENT_CONFIRM, null, null),
	VICI.packet(VICI.T.EVENT, 'log', { group: 'CFG', msg: 'received P-CSCF server IP 2001:db8::5' }));
eq(logs, [ 'received P-CSCF server IP 2001:db8::5' ], 'listen: the event reaches it');

// charon goes away: what waits fails, the owner hears of it
let lost = null, closed = null;
w = charon();
c = VICI.create({ socket: w.socket, uloop: w.uloop, on_close: (why) => { closed = why; } });
c.listen('log', (m) => null);
w.say(VICI.packet(VICI.T.EVENT_CONFIRM, null, null));
c.request('version', null, (e, r) => { lost = e; });
w.inbox = '';
w.handler();
eq([ lost?.error, closed ], [ 'vici', 'charon closed the connection' ], 'client: charon gone -> the waiting command fails, on_close');
// the next request connects again and registers the listener anew
w.sent = [];
c.request('version', null, (e, r) => null);
eq([ w.sent[0]?.type, w.sent[0]?.name ], [ VICI.T.EVENT_REGISTER, 'log' ], 'client: after a reconnect the listeners come first');
w.say(VICI.packet(VICI.T.EVENT_CONFIRM, null, null));
eq(w.sent[1]?.name, 'version', 'client: then the request');
c.close();
eq(closed, 'charon closed the connection', 'client: our own close is not reported');

done();
