// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 André Valentin <avalentin@marcant.net>
// `wwandctl ims`: the modem and router side of the router's own IMS UE
// (wwand-ims, sipd backend `ue`). A wwandctl command from an optional package,
// installed at /usr/share/ucode/wwand/ctl/ims.uc; wwandctl hands it
// { call, call_ok, status, resolve_modem }.
//
//   wwandctl ims [modem] check            what the UE needs from the modem and the router
//   wwandctl ims [modem] fix [--no-reset] [--keep-modem-ims]
//                                         the modem settings (Quectel)
//   wwandctl ims [modem] setup [--apply] [--force] [--iface wwims] [--table 30]
//                                         the IMS PDN, its VRF, the firewall zone and
//                                         sipd's line, from the modem's carrier config
//                                         (also as `wwand-ims-setup`)
//   wwandctl ims [modem] mbn [list]       the carrier configs (MBNs) the modem holds
//   wwandctl ims [modem] mbn patch [--base FILE] [--fgi 3,7] [--item PATH=HEX]...
//                                  [--out FILE] [--upload [--replace]]
//                                         the VoLTE FGIs (or any EFS item) into an MBN
//   wwandctl ims [modem] mbn upload FILE [--replace] [--no-activate]
//                                         load it as a new config, select and activate
//                                         it; --replace then deletes the one it replaces
//
// `mbn patch` is the vendor way to the FGIs (research/rg650e-245/NOTES.md,
// 2026-11-15): the carrier MBN carries /nv/item_files/modem/lte/rrc/efs/
// lte_fgi_r8, as 20 Qualcomm MBNs on a OnePlus 8T do, all with FGI 3 and 7
// on. The base is --base FILE, or the active config read back over QMI
// (PDC Get Config; not possible over a USB modem's 4 KB control channel,
// see fetch_active). The result keeps the base's name; it is loaded under its SHA-1
// (PDC Load Config through the ims plugin). The base's signature is not
// renewed (ctl/mcfg.uc): the RG650E A05 applies such a file.
//
// `fix`, research/rg650e-245/NOTES.md (2026-11-14):
// - LTE FGI 3 and 7 (RLC UM): a Quectel data module (RG650E) ships with them
//   off. To the eNB that is a UE without VoLTE: no QCI 1 bearer, every call
//   ends in 503 "ASR: BEARER_RELEASED". AT+QNWCFG="lte_fgi_fdd" takes the
//   list of enabled FGIs; the modem reads it at boot, so a reset follows.
// - the modem's own IMS off (AT+QCFG="ims",2): else it registers the same
//   identity next to our UE.
// Both are Quectel AT commands: there is no QMI message for either in
// libqmi 1.38. What QMI has is used (wwand's modem_cells, modem_profiles,
// modem_carrier_config); AT only where it has not.

'use strict';

let fs = require('fs');

// the LTE feature group indicators a VoLTE UE must set (TS 36.331 B.1:
// FGI 7 "can only be set to 0 if the UE does neither support VoLTE nor MCPTT";
// FGI 3 is RLC UM with the short sequence numbers QCI 1 uses)
const FGI_VOLTE = [ 3, 7 ];

// the protected SIP port pairs sipd's UE uses (sipd/line_ue.uc PAIRS) and
// its RTP relay range (ims_modem rtp_base / rtp_span defaults)
const SIP_PORTS = '5062 5064 5072 5074';
const RTP_PORTS = '40000-40199';

// ---- parsing (host-tested) ---------------------------------------------------------

// +QNWFCFG: "lte_fgi_fdd",2:4:5:...   (the firmware answers QNWFCFG, sic)
function fgi_parse(lines)
{
	for (let l in lines ?? []) {
		let m = match(l, /^\+QNWF?CFG: *"lte_fgi_(fdd|tdd)", *([0-9:]*)/);
		if (m)
			return map(filter(split(m[2], ':'), (x) => length(x)), (x) => +x);
	}
	return null;
}

function fgi_plan(list)
{
	let missing = filter(FGI_VOLTE, (f) => index(list ?? [], f) < 0);
	let all = sort([ ...(list ?? []), ...missing ], (a, b) => a - b);
	return { missing: missing, list: all, arg: join(':', all) };
}

// +QCFG: "ims",<mode>,<state>   mode 0 = per MBN, 1 = on, 2 = off
function qcfg_ims(lines)
{
	for (let l in lines ?? []) {
		let m = match(l, /^\+QCFG: *"ims", *([0-9]+)/);
		if (m)
			return +m[1];
	}
	return null;
}

// +CGDCONT: <cid>,"<type>","<apn>",...   the fallback where modem_profiles is missing
function cgdcont_parse(lines)
{
	let out = [];
	for (let l in lines ?? []) {
		let m = match(l, /^\+CGDCONT: *([0-9]+), *"([^"]*)", *"([^"]*)"/);
		if (m)
			push(out, { index: +m[1], pdp_type: lc(m[2]), apn: m[3] });
	}
	return out;
}

// an IPv6 address in colon form, longest zero run shortened (RFC 5952), for a
// clean --pcscf: wwand's QMI P-CSCF list comes uncompressed (2a01:…:0:0:0:5)
function v6_short(a)
{
	if (index(a ?? '', ':') < 0 || index(a, '::') >= 0)
		return a;
	for (let z in [ ':0:0:0:0:0:0:0:', ':0:0:0:0:0:0:', ':0:0:0:0:0:', ':0:0:0:0:', ':0:0:0:', ':0:0:' ])
		if (index(':' + a + ':', z) >= 0) {
			let s = replace(':' + a + ':', z, '::', 1);
			return replace(replace(s, /^:([^:])/, '$1'), /([^:]):$/, '$1');
		}
	return a;
}

// the profile the carrier config made for IMS: the one marked IMCN, else the
// one named ims (never the emergency `sos`)
function ims_profile(profiles)
{
	let ok = filter(profiles ?? [], (p) => !match(lc(p.apn ?? ''), /^sos/));
	for (let p in ok)
		if (p.imcn === true || p.imcn == 1)
			return p;
	for (let p in ok)
		if (match(lc(p.apn ?? ''), /^ims(\.|$)/))
			return p;
	return null;
}

// a modem profile's PDP type as the interface option: AT+CGDCONT's text, or
// modem_profiles' QMI enum (libqmi 1.38 QmiWdsPdpType: 0 IPv4, 1 PPP,
// 2 IPv6, 3 IPv4 or IPv6)
function pdp_option(t)
{
	if (type(t) == 'int')
		return { '0': 'ipv4', '2': 'ipv6', '3': 'ipv4v6' }[sprintf('%d', t)];
	t = lc(replace(t ?? '', /[^A-Za-z0-9]/g, ''));
	if (t == 'ipv4v6')
		return 'ipv4v6';
	if (t == 'ipv6')
		return 'ipv6';
	if (t == 'ip' || t == 'ipv4')
		return 'ipv4';
	return null;
}

// the uci sections the UE needs: { config, name, type, opts, lists } each
function setup_sections(o)
{
	let ifc = o.iface ?? 'wwims', vrf = o.vrf ?? 'ims', table = sprintf('%d', o.table ?? 30);
	let rtp = o.rtp ?? RTP_PORTS;
	let p = o.profile;
	let net = { proto: 'wwand', modem: o.modem, device: ifc, mux_id: 'auto', apn: p.apn,
	            ims: '1', ip4table: table, ip6table: table, peerdns: '0', delegate: '0' };
	let pdp = pdp_option(p.pdp_type);
	if (pdp)
		net.pdp_type = pdp;
	if (p.index != null)
		net.profile = sprintf('%d', p.index);

	return [
		{ config: 'network', name: vrf, type: 'device',
		  opts: { type: 'vrf', name: vrf, table: table }, lists: { ports: [ ifc ] } },
		{ config: 'network', name: vrf + '_vrf', type: 'interface', opts: { proto: 'none', device: vrf } },
		{ config: 'network', name: ifc, type: 'interface', opts: net },
		{ config: 'firewall', name: vrf, type: 'zone',
		  opts: { name: vrf, input: 'REJECT', output: 'ACCEPT', forward: 'REJECT' },
		  lists: { network: [ ifc ], device: [ vrf ] } },
		{ config: 'firewall', name: vrf + '_esp', type: 'rule',
		  opts: { name: 'IMS-ESP', src: vrf, proto: 'esp', target: 'ACCEPT' } },
		{ config: 'firewall', name: vrf + '_sip', type: 'rule',
		  opts: { name: 'IMS-SIP', src: vrf, proto: 'tcp udp', dest_port: SIP_PORTS, target: 'ACCEPT' } },
		{ config: 'firewall', name: vrf + '_rtp', type: 'rule',
		  opts: { name: 'IMS-RTP', src: vrf, proto: 'udp', dest_port: rtp, target: 'ACCEPT' } },
		{ config: 'firewall', name: vrf + '_icmp', type: 'rule',
		  opts: { name: 'IMS-ICMP', src: vrf, proto: 'icmp ipv6-icmp', target: 'ACCEPT' } },
		{ config: 'wwand_ims', name: 'ue', type: 'ims_modem',
		  opts: { modem: o.modem, backend: 'ue', ims_iface: ifc, vrf: vrf } },
	];
}

// what to do with one section against what is there:
// { action: 'create'|'ok'|'differs', diff: [ [opt, have, want] ] }
function section_plan(want, have)
{
	if (have == null)
		return { action: 'create', diff: [] };
	let diff = [];
	for (let k, v in want.opts)
		if (have[k] != v)
			push(diff, [ k, have[k], v ]);
	for (let k, v in want.lists ?? {}) {
		let h = have[k];
		h = (type(h) == 'array') ? h : (h != null ? split(h, ' ') : []);
		for (let x in v)
			if (index(h, x) < 0)
				push(diff, [ k, join(' ', h), join(' ', v) ]);
	}
	return { action: length(diff) ? 'differs' : 'ok', diff: diff };
}

const L3MDEV_HOTPLUG = '/etc/hotplug.d/iface/25-wwand-ims-l3mdev';
const L3MDEV_SCRIPT = `#!/bin/sh
# wwand-ims: the l3mdev FIB rules (VRF lookups) come once per netns, at the
# first VRF device; every netifd restart flushes them. Put them back.
[ "$ACTION" = ifup ] || exit 0
ip link show type vrf 2>/dev/null | grep -q . || exit 0
for f in -4 -6; do
	ip $f rule show pref 1000 | grep -q l3mdev ||
		ip $f rule add pref 1000 l3mdev protocol kernel
done
`;

// ---- the modem ------------------------------------------------------------------------

// a call that may fail: a method an older wwand lacks (modem_profiles) is a
// fallback case here, where ctx.call would end wwandctl
let bus = null;
function try_call(method, args)
{
	bus ??= require('ubus').connect();
	return bus?.call('wwand', method, args ?? {});
}

function at(ctx, modem, cmd)
{
	let r = try_call('modem_at', { modem: modem, command: cmd, timeout: 5000 });
	return (r == null || r.ok === false) ? null : (r.response ?? []);
}

// Turn the modem's own IMS off so our UE can take the IMS PDN. Try QMI first
// (the ims plugin's SET_SERVICE_ENABLE 0x008F, ims_service=0 + volte=0: works
// on any Qualcomm modem, takes effect at once, no reset), then the Quectel AT
// (AT+QCFG="ims",2: persistent, read at boot, so it survives the reset the FGI
// change needs). Both where both apply — QMI alone would be undone by that
// reset. Never dies: on a modem that answers neither, the caller continues.
// `modem_ims` is the current AT+QCFG value (null if unknown). Returns
// { via: [...], reset, already_at }.
function disable_modem_ims(ctx, modem, m, modem_ims)
{
	let via = [], reset = false;

	let q = plugin(modem, 'volte_enable', { reg: 0, volte: 0 });
	if (q != null && q.ok !== false && q.error == null)
		push(via, 'qmi');

	if (is_quectel(m) && modem_ims != 2 && at(ctx, modem, 'AT+QCFG="ims",2') != null) {
		push(via, 'at');
		reset = true;
	}
	return { via: via, reset: reset, already_at: is_quectel(m) && modem_ims == 2 };
}

// Enable the VoLTE LTE FGIs. There is NO QMI message for the FGIs; the vendor
// way is the carrier MBN (`wwandctl ims mbn patch`, a command of its own, not a
// QMI stand-in here, docs/qmi-beyond-libqmi.md). So the only automatic route is
// the Quectel AT (AT+QNWCFG="lte_fgi_fdd", read at boot, so a reset follows).
// Kept as try-QMI-then-AT for the day a QMI message exists. Never dies. Returns
// { via, reset, already, note, error, before, after }.
function enable_fgi(ctx, modem, m)
{
	// 1) QMI: none today
	// 2) AT (Quectel)
	if (!is_quectel(m))
		return { note: 'no QMI FGI message, and not a Quectel module: set the FGIs with `wwandctl ims mbn patch --upload`' };
	let before = fgi_parse(at(ctx, modem, 'AT+QNWCFG="lte_fgi_fdd"'));
	if (before == null)
		return { error: 'the modem does not answer AT+QNWCFG="lte_fgi_fdd" (firmware without it?)' };
	let p = fgi_plan(before);
	if (!length(p.missing))
		return { via: 'at', already: true, before: before };
	if (at(ctx, modem, sprintf('AT+QNWCFG="lte_fgi_fdd",%s', p.arg)) == null)
		return { error: 'AT+QNWCFG="lte_fgi_fdd" refused', before: before };
	let after = fgi_parse(at(ctx, modem, 'AT+QNWCFG="lte_fgi_fdd"'));
	if (length(fgi_plan(after ?? []).missing))
		return { error: sprintf('the FGI list did not take: %s', join(':', after ?? [])), before: before };
	return { via: 'at', reset: true, missing: p.missing, before: before, after: after };
}

function is_quectel(m)
{
	return match(lc(m?.manufacturer ?? m?.vendor ?? ''), /quectel/) != null ||
	       match(m?.model ?? '', /^(RG|RM|EG|EC|EM|BG|AG)[0-9]/) != null;
}

// the stored profiles: QMI (modem_profiles) where wwand has it, else AT+CGDCONT
function profiles(ctx, modem)
{
	let r = try_call('modem_profiles', { modem: modem });
	if (r?.ok !== false && type(r?.profiles) == 'array')
		return { via: 'qmi', list: r.profiles };
	return { via: 'at', list: cgdcont_parse(at(ctx, modem, 'AT+CGDCONT?')) };
}

// the active carrier config by name (QMI PDC through modem_carrier_config)
function carrier_config(ctx, modem)
{
	let g = try_call('modem_carrier_config', { modem: modem, op: 'get' });
	if (g?.ok === false || !g?.active)
		return null;
	let l = try_call('modem_carrier_config', { modem: modem, op: 'list' });
	for (let c in l?.configs ?? l?.list ?? [])
		if (c.id == g.active)
			return { id: g.active, name: c.description ?? c.name, pending: g.pending };
	return { id: g.active, name: null, pending: g.pending };
}

function state(ctx, modem, m)
{
	let s = { quectel: is_quectel(m) };
	if (s.quectel) {
		s.fgi = fgi_parse(at(ctx, modem, 'AT+QNWCFG="lte_fgi_fdd"'));
		s.modem_ims = qcfg_ims(at(ctx, modem, 'AT+QCFG="ims"'));
	}
	s.mbn = carrier_config(ctx, modem);
	s.profiles = profiles(ctx, modem);
	s.ims = ims_profile(s.profiles.list);
	return s;
}

// ---- MBN: patch and upload (ctl/mcfg.uc) ---------------------------------------------

function mcfg_lib()
{
	try { return require('wwand.ims_mcfg'); }
	catch (e) { return require('ims_mcfg'); }
}

// "3,7" / "3:7" -> [ 3, 7 ]
function num_list(s)
{
	return map(filter(split(s ?? '', /[,:]/), (x) => length(x)), (x) => +x);
}

// the FGIs to write: what the base has, plus the wanted ones (FGIs 1-32)
function fgi_merge(have, want)
{
	let all = uniq([ ...(have ?? []), ...(want ?? []) ]);
	return sort(filter(all, (f) => f >= 1 && f <= 32), (a, b) => a - b);
}

function plugin(modem, op, args)
{
	return try_call('modem_plugin', { modem: modem, plugin: 'ims', op: op, args: args ?? {} });
}

function configs(modem)
{
	let g = try_call('modem_carrier_config', { modem: modem, op: 'get' });
	let l = try_call('modem_carrier_config', { modem: modem, op: 'list' });
	return { active: g?.active, pending: g?.pending, list: l?.configs ?? l?.list ?? [] };
}

// the active config's file, read back from the modem over QMI (PDC Get
// Config through the ims plugin) and checked: its SHA-1 is the config id.
// On a USB modem (qmi_wwan) this fails. The modem sends the config in
// frames of 4096 data bytes. Each frame's indication is 4133 bytes with its
// headers, and qmi_wwan registers cdc-wdm with a 4096-byte buffer. The read
// stops at 4096 bytes and the last 37 never come (HW, RG650E on the
// Chateau, 2026-11-15: a raw 4096-byte read with QMUX length 0x1024). A
// PCIe/MHI modem (32 KB control MTU) or QRTR is not limited so.
function fetch_active(modem, id, dst)
{
	if (!id)
		die('no active carrier config reported: pass --base FILE');
	let r = plugin(modem, 'mbn_read', { id: id, path: dst });
	if (r?.match === true)
		return sprintf('the modem (QMI PDC Get Config, %d frames)', r.frames);
	die(sprintf('the active config %s cannot be read back over QMI here (%s).\n' +
		'PDC Get Config sends 4096-byte frames in 4133-byte messages; a USB modem\'s control channel (qmi_wwan/cdc-wdm) takes 4096.\n' +
		'Pass --base FILE: the vendor MBN of that config (from the firmware package) or a saved copy.',
		id, r?.match === false ? sprintf('the data read has SHA-1 %s', r.sha1) : sprintf('%J', r)));
}

function cmd_mbn_list(modem)
{
	let c = configs(modem);
	if (!length(c.list))
		die('the modem lists no carrier configs (PDC)');
	for (let x in c.list)
		printf('%s %s %7d  %s\n', x.id == c.active ? '*' : (x.id == c.pending ? '+' : ' '),
			x.id, x.size ?? 0, x.description ?? x.name ?? '?');
	printf('\n* active%s\n', c.pending ? ', + pending (after a reset)' : '');
}

function cmd_mbn_upload(ctx, modem, m, file, opts)
{
	let fs = require('fs'), d = require('digest');
	let data = fs.readfile(file);
	if (data == null)
		die(sprintf('cannot read %s', file));
	let id = d.sha1(data);
	let c = configs(modem);
	let prev = c.active;

	if (length(filter(c.list, (x) => x.id == id)))
		printf('%s: already loaded as %s\n', file, id);
	else {
		printf('loading %s (%d bytes) as %s\n', file, length(data), id);
		let r = plugin(modem, 'mbn_load', { path: file });
		if (r == null || r.ok === false || r.error)
			die(sprintf('load refused: %J', r));
		if (!length(filter(configs(modem).list, (x) => x.id == id)))
			die('loaded, but the modem does not list it');
	}

	if (prev == id && !c.pending)
		printf('it is the active config already\n');
	else {
		let s = try_call('modem_carrier_config', { modem: modem, op: 'set', id: id });
		if (s == null || s.ok === false)
			die(sprintf('select refused: %J', s));
		printf('selected\n');
		if (opts.no_activate)
			return printf('not activated: it takes effect at the next modem reset\n');
		let a = plugin(modem, 'mbn_activate', {});
		if (a == null || a.ok === false || a.error)
			die(sprintf('activate refused: %J', a));
		printf('activated; the modem resets, waiting for it');
		let now = null;
		for (let i = 0; i < 60 && now != id; i++) {
			system('sleep 5');
			printf('.');
			now = configs(modem).active;
		}
		printf('\n');
		if (now != id)
			die(sprintf('the modem did not come back with %s active (active: %s)', id, now ?? 'none'));
		printf('active: %s\n', id);
	}

	if (is_quectel(m)) {
		let f = fgi_parse(at(ctx, modem, 'AT+QNWCFG="lte_fgi_fdd"'));
		if (f != null)
			printf('LTE FGI now: %s (3 and 7 %s)\n', join(':', f), length(fgi_plan(f).missing) ? 'MISSING' : 'on');
	}

	if (opts.replace) {
		if (!prev || prev == id)
			return printf('--replace: nothing to delete\n');
		let r = plugin(modem, 'mbn_delete', { id: prev });
		if (r == null || r.ok === false || r.error)
			die(sprintf('delete of %s refused: %J', prev, r));
		let gone = !length(filter(configs(modem).list, (x) => x.id == prev));
		printf('replaced: %s %s\n', prev, gone ? 'deleted' : 'still listed (the modem kept it)');
		printf('  undo: wwandctl ims %s mbn upload <the original file>%s\n', modem,
			opts.base ? sprintf(' (%s)', opts.base) : '');
	}
}

function cmd_mbn_patch(ctx, modem, m, opts)
{
	let fs = require('fs'), d = require('digest'), M = mcfg_lib();
	let c = configs(modem);
	let base = opts.base, from = base;
	if (!base) {
		base = '/tmp/wwand-ims-base.mbn';
		from = fetch_active(modem, c.active, base);
	}
	let buf = fs.readfile(base);
	if (buf == null)
		die(sprintf('cannot read %s', base));
	let p = M.parse(buf);
	printf('base %s: "%s", %d items, %d bytes, id %s\n', from, p.name ?? '?', length(p.items), length(buf), d.sha1(buf));

	let changes = [];
	for (let it in opts.items) {
		let kv = match(it, /^(\/[^=]+)=([0-9a-fA-F]*)$/);
		if (!kv || length(kv[2]) % 2)
			die(sprintf('--item %s: PATH=HEX expected', it));
		push(changes, [ kv[1], M.set_item(p, kv[1], M.hex2bin(kv[2])) ]);
	}
	if (opts.fgi || !length(opts.items)) {
		let want = opts.fgi ?? FGI_VOLTE;
		let have = M.fgi_of(p);
		let src = 'the MBN';
		let list = have?.list;
		if (list == null && is_quectel(m)) {
			list = filter(fgi_parse(at(ctx, modem, 'AT+QNWCFG="lte_fgi_fdd"')) ?? [], (f) => f <= 32);
			src = 'the modem (AT+QNWCFG)';
		}
		if (list == null || !length(list))
			die('the base FGIs are unknown (no lte_fgi_r8 in the MBN, no AT answer): pass --item PATH=HEX');
		let all = fgi_merge(list, want);
		printf('LTE FGI (lte_fgi_r8): from %s %s\n', src, join(':', list));
		printf('                      to %s\n', join(':', all));
		push(changes, [ M.FGI_R8, M.set_item(p, M.FGI_R8, M.fgi_data(have?.prefix ?? M.rrc_prefix(p), all)) ]);
	}
	for (let ch in changes)
		printf('  %-55s %s\n', ch[0], ch[1]);
	if (!length(filter(changes, (ch) => ch[1] != 'unchanged')))
		return printf('nothing to change\n');

	let out = M.build(p, d);
	let dst = opts.out ?? '/tmp/wwand-ims-patched.mbn';
	if (!fs.writefile(dst, out.buf))
		die(sprintf('cannot write %s', dst));
	printf('wrote %s: %d bytes, id %s (%s digests renewed, the signature is the base\'s)\n',
		dst, length(out.buf), d.sha1(out.buf), out.algo);
	if (opts.upload)
		return cmd_mbn_upload(ctx, modem, m, dst, opts);
	printf('upload: wwandctl ims %s mbn upload %s [--replace]\n', modem, dst);
}

function cmd_mbn(ctx, modem, m, args)
{
	let sub = args[0] ?? 'list';
	let opts = { items: [] };
	let file = null;
	for (let i = 1; i < length(args); i++) {
		switch (args[i]) {
		case '--base': opts.base = args[++i]; break;
		case '--out': opts.out = args[++i]; break;
		case '--fgi': opts.fgi = num_list(args[++i]); break;
		case '--item': push(opts.items, args[++i]); break;
		case '--upload': opts.upload = true; break;
		case '--replace': opts.replace = true; break;
		case '--no-activate': opts.no_activate = true; break;
		default:
			if (sub == 'upload' && file == null && substr(args[i], 0, 2) != '--')
				file = args[i];
			else
				die(sprintf('unknown option %s', args[i]));
		}
	}
	switch (sub) {
	case 'list':   return cmd_mbn_list(modem);
	case 'patch':  return cmd_mbn_patch(ctx, modem, m, opts);
	case 'upload':
		if (!file)
			die('usage: wwandctl ims [modem] mbn upload FILE [--replace] [--no-activate]');
		return cmd_mbn_upload(ctx, modem, m, file, opts);
	default:
		die('usage: wwandctl ims [modem] mbn [list] | patch [--base FILE] [--fgi 3,7] [--item PATH=HEX] [--out FILE] [--upload [--replace]] | upload FILE [--replace] [--no-activate]');
	}
}

// ---- commands ---------------------------------------------------------------------------

function cmd_check(ctx, modem, st, m)
{
	let s = state(ctx, modem, m);
	let bad = 0;
	let line = (what, val, ok, hint) => {
		if (!ok)
			bad++;
		printf('  %-30s %s%s\n', what, val, (!ok && hint) ? '   -> ' + hint : '');
	};

	printf('modem %s: %s %s, firmware %s\n', modem, m?.manufacturer ?? '?', m?.model ?? '?', m?.revision ?? m?.firmware ?? '?');
	if (s.quectel) {
		let p = fgi_plan(s.fgi);
		line('LTE FGI 3 and 7 (VoLTE)', s.fgi == null ? 'unknown (no answer)' :
			(length(p.missing) ? sprintf('missing %s', join(', ', p.missing)) : 'on'),
			s.fgi != null && !length(p.missing), sprintf('wwandctl ims %s fix, or mbn patch --upload', modem));
		line('modem\'s own IMS', s.modem_ims == null ? 'unknown' :
			sprintf('%d (%s)', s.modem_ims, { '0': 'per MBN', '1': 'on', '2': 'off' }[sprintf('%d', s.modem_ims)] ?? '?'),
			s.modem_ims == 2, sprintf('wwandctl ims %s fix', modem));
	}
	else
		printf('  %-30s %s\n', 'FGI / modem IMS', 'not a Quectel module: not checked (the UE needs VoLTE FGIs and the modem\'s IMS off)');

	printf('  %-30s %s\n', 'carrier config (MBN)', s.mbn ? sprintf('%s%s', s.mbn.name ?? s.mbn.id,
		s.mbn.pending ? ' (a switch is pending: reset)' : '') : 'unknown');
	line(sprintf('IMS profile (%s)', s.profiles.via), s.ims ?
		sprintf('%d "%s" %s%s', s.ims.index, s.ims.apn, pdp_option(s.ims.pdp_type) ?? sprintf('%J', s.ims.pdp_type),
			s.ims.imcn ? ', IMCN' : '') : 'none found',
		s.ims != null, 'the carrier config has no IMS profile');

	// the IMS PDN: a proto wwand interface with option ims '1' on this modem
	let found = null;
	try {
		require('uci').cursor().foreach('network', 'interface', (x) => {
			if (!found && x.proto == 'wwand' && x.ims == '1' && (x.modem == null || x.modem == modem))
				found = [ x['.name'], st.contexts?.[x['.name']] ];
		});
	} catch (e) { found = null; }
	line('IMS PDN interface', found ? sprintf('%s %s', found[0], found[1]?.state ?? 'not in wwand') : 'none',
		found != null && found[1]?.state == 'CONNECTED', found ? 'is it up? (ifup ' + found[0] + ')' : 'wwand-ims-setup');

	printf('\n%s\n', bad ? sprintf('%d item(s) to fix', bad) : 'ready for the IMS UE');
	exit(bad ? 2 : 0);
}

function cmd_fix(ctx, modem, m, opts)
{
	let st = state(ctx, modem, m);
	let reset = false;

	// --- VoLTE FGIs: QMI if there ever is one, else the Quectel AT ---
	let f = enable_fgi(ctx, modem, m);
	if (f.error)
		printf('LTE FGI: %s (continuing)\n', f.error);
	else if (f.note)
		printf('LTE FGI: %s\n', f.note);
	else if (f.already)
		printf('LTE FGI 3 and 7: already on\n');
	else {
		printf('LTE FGI: enabled %s (via %s)\n', join(', ', f.missing), f.via);
		printf('  before: %s\n  after:  %s\n', join(':', f.before), join(':', f.after));
		printf('  undo:   AT+QNWCFG="lte_fgi_fdd",%s and a modem reset\n', join(':', f.before));
		if (f.reset)
			reset = true;
	}

	// --- the modem's own IMS off: QMI first, then the Quectel AT ---
	if (opts.keep_modem_ims)
		printf('modem\'s own IMS: left as is (--keep-modem-ims)\n');
	else {
		let d = disable_modem_ims(ctx, modem, m, st.modem_ims);
		if (d.reset)
			reset = true;
		if (length(d.via))
			printf('modem\'s own IMS: disabled via %s (our UE registers instead)%s\n',
			       join(' + ', d.via), index(d.via, 'at') < 0 ? ' — QMI only, not persistent across a modem reboot' : '');
		else if (d.already_at)
			printf('modem\'s own IMS: already off\n');
		else
			printf('modem\'s own IMS: could not disable over QMI or AT (continuing; see `wwandctl ims %s check`)\n', modem);
	}

	if (!reset)
		return printf('done (no reset needed)\n');
	if (opts.no_reset)
		return printf('the modem reads these at boot: reset it (wwandctl reset %s) before the UE registers\n', modem);
	printf('resetting the modem (it reads these at boot)\n');
	ctx.call_ok('modem_reset', { modem: modem });
	printf('reset sent; the interfaces come back on their own\n');
}

function cmd_setup(ctx, modem, m, opts)
{
	let uci = require('uci');
	// --confdir: work on a copy of /etc/config (a test of --apply)
	let dir = opts.confdir ?? '/etc/config';
	// uci cannot set into a config file that does not exist
	if (opts.apply && !fs.stat(dir + '/wwand_ims'))
		fs.writefile(dir + '/wwand_ims', '');
	let cur = opts.confdir ? uci.cursor(opts.confdir) : uci.cursor();
	let s = state(ctx, modem, m);
	// the relay range the firewall must open: sipd's rtp_base / rtp_span
	let rb = 40000, rs = 200;
	cur.foreach('wwand_ims', 'ims_modem', (x) => { rb = +(x.rtp_base ?? rb); rs = +(x.rtp_span ?? rs); });

	if (!s.ims)
		die(sprintf('no IMS profile in the modem\'s carrier config (profiles via %s: %J)', s.profiles.via,
			map(s.profiles.list, (p) => sprintf('%d %s', p.index, p.apn))));

	printf('carrier config %s: IMS profile %d, APN "%s", %s (via %s)\n', s.mbn?.name ?? s.mbn?.id ?? '?',
		s.ims.index, s.ims.apn, pdp_option(s.ims.pdp_type) ?? sprintf('%J', s.ims.pdp_type), s.profiles.via);

	let want = setup_sections({ modem: modem, profile: s.ims, iface: opts.iface, table: opts.table,
	                            rtp: sprintf('%d-%d', rb, rb + rs - 1) });
	let todo = [];
	for (let w in want) {
		// sipd reads the first ims_modem section, whatever its name: that one
		if (w.type == 'ims_modem')
			cur.foreach(w.config, w.type, (x) => { if (!w.found) { w.name = x['.name']; w.found = true; } });
		let have = cur.get_all(w.config, w.name);
		if (have && have['.type'] != w.type)
			die(sprintf('%s.%s exists as a %s, not a %s: rename it or pass --iface', w.config, w.name, have['.type'], w.type));
		let pl = section_plan(w, have);
		printf('  %-10s %-14s %s\n', w.config, w.name, pl.action == 'differs'
			? 'differs: ' + join(', ', map(pl.diff, (d) => sprintf('%s %J -> %J', d[0], d[1], d[2]))) : pl.action);
		if (pl.action == 'create' || (pl.action == 'differs' && opts.force))
			push(todo, w);
	}
	let hook = opts.confdir != null || fs.stat(L3MDEV_HOTPLUG) != null;
	printf('  %-25s %s\n', 'l3mdev hotplug', hook ? 'ok' : 'create');

	if (!opts.apply) {
		printf('\na dry run: `wwand-ims-setup --apply` writes it%s\n',
			length(filter(want, (w) => section_plan(w, cur.get_all(w.config, w.name)).action == 'differs'))
				? ' (sections that differ only with --force)' : '');
		return;
	}

	let failed = [];
	for (let w in todo) {
		let have = cur.get_all(w.config, w.name);
		if (!have && !cur.set(w.config, w.name, w.type))
			push(failed, sprintf('%s.%s', w.config, w.name));
		for (let k, v in w.opts)
			if (!cur.set(w.config, w.name, k, v))
				push(failed, sprintf('%s.%s.%s', w.config, w.name, k));
		// lists: what is there stays, the missing entries are added
		for (let k, v in w.lists ?? {}) {
			let h = have?.[k];
			h = (type(h) == 'array') ? h : (h != null ? split(h, ' ') : []);
			if (!cur.set(w.config, w.name, k, uniq([ ...h, ...v ])))
				push(failed, sprintf('%s.%s.%s', w.config, w.name, k));
		}
	}
	if (length(failed))
		die(sprintf('uci refused %s (nothing committed)', join(', ', failed)));
	if (!length(todo) && hook)
		return printf('\nnothing to write\n');
	for (let c in uniq(map(todo, (w) => w.config)))
		if (!cur.commit(c))
			die(sprintf('uci commit %s failed', c));
	if (!hook) {
		fs.writefile(L3MDEV_HOTPLUG, L3MDEV_SCRIPT);
		system(sprintf('chmod 755 %s', L3MDEV_HOTPLUG));
	}
	printf('\nwritten (%d section(s)). Then:\n', length(todo));
	printf('  wwandctl ims %s fix                         the modem side, if `check` says so\n', modem);
	printf('  setsid /etc/init.d/network restart          (detached over ssh)\n');
	printf('  /etc/init.d/firewall reload; /etc/init.d/wwand-ims-sipd restart\n');
}

// ---- test call: our own UE registers and dials a number, echo on -------------------
// Runs the proven UE driver (tools/ims-register.uc, installed with wwand-ims):
// register over the IMS PDN, dial the number, count/echo the RTP, hang up.

const UE_DRIVER = '/usr/share/wwand-ims/ims-register.uc';
const UE_LIB    = '/usr/share/wwand-ims';

// the sipd ims_modem section: iface / vrf / apn / mnc_len defaults
function ims_modem_cfg()
{
	let c = {};
	try {
		require('uci').cursor().foreach('wwand_ims', 'ims_modem', (x) => {
			c.iface ??= x.ims_iface; c.vrf ??= x.vrf; c.apn ??= x.ims_apn;
			c.mnc_len ??= x.mnc_len; c.modem ??= x.modem;
		});
	} catch (e) {}
	return c;
}

// the P-CSCF from wwand's QMI (status contexts.<iface>.ipv6/ipv4.pcscf: QMI WDS
// Get Current Settings, the IPv6 0x2E and IPv4 0x23 lists), IPv6 first. No AT:
// wwand reads it over QMI already (needs a core with the 0x2E decode).
function discover_pcscf(st, iface)
{
	let c = st?.contexts?.[iface];
	for (let l in [ c?.ipv6?.pcscf, c?.ipv4?.pcscf ])
		for (let a in (type(l) == 'array') ? l : [])
			if (type(a) == 'string')
				return v6_short(a);
	return null;
}

function cmd_call(ctx, modem, m, st, args)
{
	let o = { number: null, talk: 12, ring: 30, hold: null, echo: 1, pcscf: null,
	          iface: null, vrf: null, mnc_len: null };
	for (let i = 0; i < length(args); i++) {
		switch (args[i]) {
		case '--talk':    o.talk = +args[++i]; break;
		case '--ring':    o.ring = +args[++i]; break;
		case '--hold':    o.hold = +args[++i]; break;
		case '--no-echo': o.echo = 0; break;
		case '--pcscf':   o.pcscf = args[++i]; break;
		case '--iface':   o.iface = args[++i]; break;
		case '--vrf':     o.vrf = args[++i]; break;
		case '--mnc-len': o.mnc_len = +args[++i]; break;
		default:
			if (substr(args[i], 0, 2) == '--')
				die(sprintf('unknown option %s', args[i]));
			o.number ??= args[i];
		}
	}
	if (!o.number)
		die('usage: wwandctl ims [modem] call <number> [--talk S] [--ring S] [--hold S] [--no-echo] [--pcscf ADDR] [--iface N] [--vrf N]');
	if (!fs.stat(UE_DRIVER))
		die(sprintf('%s not installed (it ships with wwand-ims)', UE_DRIVER));

	let cfg = ims_modem_cfg();
	let iface = o.iface ?? cfg.iface ?? 'wwims';
	let vrf   = o.vrf ?? cfg.vrf;
	let pcscf = o.pcscf ?? discover_pcscf(st, iface);
	if (!pcscf)
		die(sprintf('no P-CSCF over QMI for %s (is it up? `ifup %s`; needs a wwand with the WDS 0x2E decode); or pass --pcscf ADDR', iface, iface));
	let mnc = o.mnc_len ?? (cfg.mnc_len ? +cfg.mnc_len : null);

	let argv = [ 'ucode', '-L', UE_LIB, '-L', '/usr/lib/ucode/*.so', UE_DRIVER,
	             '--modem', modem, '--iface', iface, '--call', o.number, '--pcscf', pcscf,
	             '--echo', sprintf('%d', o.echo), '--ring', sprintf('%d', o.ring),
	             '--talk', sprintf('%d', o.talk) ];
	if (vrf)          push(argv, '--vrf', vrf);
	if (mnc)          push(argv, '--mnc-len', sprintf('%d', mnc));
	if (o.hold != null) push(argv, '--hold', sprintf('%d', o.hold));

	printf('calling %s through %s (iface %s, P-CSCF %s%s)\n', o.number, modem, iface, pcscf,
	       o.echo ? ', echo on' : '');
	// array form: no shell, so ucode's -L glob is expanded by ucode, not sh
	return system(argv);
}

function cmd_ims(ctx, args)
{
	let st = ctx.status();
	let r = null;
	if (args[0] != null && st.modems?.[args[0]])
		r = { modem: args[0], consumed: true };
	else {
		// default: the modem sipd's line is configured on (wwand_ims ims_modem),
		// so a box with a second modem need not name it
		let cfg = null;
		try {
			require('uci').cursor().foreach('wwand_ims', 'ims_modem', (x) => { cfg ??= x.modem; });
		} catch (e) { cfg = null; }
		r = (cfg && st.modems?.[cfg]) ? { modem: cfg, consumed: false }
		                              : ctx.resolve_modem(st, match(args[0] ?? '', /^(check|fix|setup|mbn|call)$/) ? null : args[0]);
	}
	let rest = r.consumed ? slice(args, 1) : args;
	let op = rest[0] ?? 'check';
	let m = st.modems[r.modem];
	let opts = { iface: null, table: null };

	if (op == 'mbn')
		return cmd_mbn(ctx, r.modem, m, slice(rest, 1));
	if (op == 'call')
		return cmd_call(ctx, r.modem, m, st, slice(rest, 1));

	for (let i = 1; i < length(rest); i++) {
		switch (rest[i]) {
		case '--apply': opts.apply = true; break;
		case '--force': opts.force = true; break;
		case '--no-reset': opts.no_reset = true; break;
		case '--keep-modem-ims': opts.keep_modem_ims = true; break;
		case '--iface': opts.iface = rest[++i]; break;
		case '--table': opts.table = +rest[++i]; break;
		case '--confdir': opts.confdir = rest[++i]; break;
		default: die(sprintf('unknown option %s', rest[i]));
		}
	}

	switch (op) {
	case 'check': return cmd_check(ctx, r.modem, st, m);
	case 'fix':   return cmd_fix(ctx, r.modem, m, opts);
	case 'setup': return cmd_setup(ctx, r.modem, m, opts);
	default:
		die('usage: wwandctl ims [modem] check | fix [--no-reset] [--keep-modem-ims] | setup [--apply] [--force] [--iface N] [--table N] | mbn [list|patch|upload]');
	}
}

return {
	help: [
		'ims [modem] check                      what the router\'s own IMS UE needs (modem + router)',
		'ims [modem] fix [--no-reset]           VoLTE FGIs on, the modem\'s own IMS off (Quectel)',
		'ims [modem] setup [--apply] [--force]  IMS PDN + VRF + firewall + sipd line from the MBN',
		'ims [modem] mbn [list|patch|upload]    the VoLTE FGIs into the carrier MBN, load it (new or --replace)',
		'ims [modem] call <number> [--no-echo]  one test VoLTE call from the router UE (--talk/--ring/--hold S)',
	],

	run: (ctx, args) => cmd_ims(ctx, args),

	// for the host tests
	_t: {
		fgi_parse: fgi_parse, fgi_plan: fgi_plan, qcfg_ims: qcfg_ims, cgdcont_parse: cgdcont_parse,
		ims_profile: ims_profile, pdp_option: pdp_option, setup_sections: setup_sections,
		section_plan: section_plan, num_list: num_list, fgi_merge: fgi_merge,
	},
};
