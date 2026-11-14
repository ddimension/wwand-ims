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
			s.fgi != null && !length(p.missing), sprintf('wwandctl ims %s fix', modem));
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
	if (!is_quectel(m))
		die(sprintf('%s is not a Quectel module: the FGI and IMS switches here are Quectel AT commands', modem));

	let s = state(ctx, modem, m);
	let reset = false;

	if (s.fgi == null)
		die('the modem does not answer AT+QNWCFG="lte_fgi_fdd" (firmware without it?)');
	let p = fgi_plan(s.fgi);
	if (length(p.missing)) {
		printf('LTE FGI: enabling %s\n', join(', ', p.missing));
		printf('  before: %s\n', join(':', s.fgi));
		let r = at(ctx, modem, sprintf('AT+QNWCFG="lte_fgi_fdd",%s', p.arg));
		if (r == null)
			die('AT+QNWCFG="lte_fgi_fdd" refused');
		let now = fgi_parse(at(ctx, modem, 'AT+QNWCFG="lte_fgi_fdd"'));
		if (length(fgi_plan(now).missing))
			die(sprintf('the FGI list did not take: %s', join(':', now ?? [])));
		printf('  after:  %s\n', join(':', now));
		printf('  undo:   AT+QNWCFG="lte_fgi_fdd",%s and a modem reset\n', join(':', s.fgi));
		reset = true;
	}
	else
		printf('LTE FGI 3 and 7: already on\n');

	if (!opts.keep_modem_ims && s.modem_ims != 2) {
		printf('modem\'s own IMS: %d -> 2 (off; our UE registers instead)\n', s.modem_ims ?? -1);
		if (at(ctx, modem, 'AT+QCFG="ims",2') == null)
			die('AT+QCFG="ims",2 refused');
		reset = true;
	}
	else if (s.modem_ims == 2)
		printf('modem\'s own IMS: already off\n');

	if (!reset)
		return printf('nothing to change\n');
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
		                              : ctx.resolve_modem(st, match(args[0] ?? '', /^(check|fix|setup)$/) ? null : args[0]);
	}
	let rest = r.consumed ? slice(args, 1) : args;
	let op = rest[0] ?? 'check';
	let m = st.modems[r.modem];
	let opts = { iface: null, table: null };

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
		die('usage: wwandctl ims [modem] check | fix [--no-reset] [--keep-modem-ims] | setup [--apply] [--force] [--iface N] [--table N]');
	}
}

return {
	help: [
		'ims [modem] check                      what the router\'s own IMS UE needs (modem + router)',
		'ims [modem] fix [--no-reset]           VoLTE FGIs on, the modem\'s own IMS off (Quectel)',
		'ims [modem] setup [--apply] [--force]  IMS PDN + VRF + firewall + sipd line from the MBN',
	],

	run: (ctx, args) => cmd_ims(ctx, args),

	// for the host tests
	_t: {
		fgi_parse: fgi_parse, fgi_plan: fgi_plan, qcfg_ims: qcfg_ims, cgdcont_parse: cgdcont_parse,
		ims_profile: ims_profile, pdp_option: pdp_option, setup_sections: setup_sections,
		section_plan: section_plan,
	},
};
