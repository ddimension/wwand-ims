'use strict';
'require baseclass';

/* Pure helpers for the VoLTE status page (view/wwand/ims-status.js), kept
   apart from the view so tools/test-imsfmt.js can check them without a DOM.
   Every timestamp comes from sipd (`ubus call wwand-ims status|calls`) and is
   on the ROUTER's clock; `now` is that clock too, so durations and "ago"
   never mix it with the browser's. Dates are shown in the browser's zone. */

/* seconds as 45s, 12m 0s, 3h 5m — the shape luci-app-wwand's fmtDur uses */
function dur(s) {
	s = Math.max(0, Math.floor(+s || 0));
	var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
	if (h) return '%dh %dm'.format(h, m);
	if (m) return '%dm %ds'.format(m, sec);
	return '%ds'.format(sec);
}

function pad(n) { return (n < 10 ? '0' : '') + n; }

/* a router timestamp as YYYY-MM-DD HH:MM:SS; today's as HH:MM:SS only */
function when(t, now) {
	if (t == null)
		return '-';
	var d = new Date(t * 1000), n = new Date((now != null ? now : t) * 1000);
	var hms = '%s:%s:%s'.format(pad(d.getHours()), pad(d.getMinutes()), pad(d.getSeconds()));
	if (d.getFullYear() == n.getFullYear() && d.getMonth() == n.getMonth() && d.getDate() == n.getDate())
		return hms;
	return '%d-%s-%s %s'.format(d.getFullYear(), pad(d.getMonth() + 1), pad(d.getDate()), hms);
}

var RESULTS = {
	answered: _('answered'),
	missed: _('missed'),
	declined: _('declined'),
	cancelled: _('cancelled'),
	failed: _('failed'),
};

var STATES = {
	registered: _('registered'),
	registering: _('registering'),
	refreshing: _('registered, refreshing'),
	down: _('not registered'),
	stopped: _('stopped'),
};

var REG_EVENT = {
	active: _('subscribed'),
	subscribing: _('subscribing'),
	idle: _('not subscribed'),
	failed: _('subscription failed'),
};

var TUNNEL = {
	up: _('up'),
	connecting: _('connecting'),
	down: _('down'),
};

var CALL_STATES = {
	trying: _('dialling'),
	calling: _('ringing the phone'),
	ringing: _('ringing'),
	early: _('early media'),
	up: _('connected'),
};

return baseclass.extend({
	dur: dur,
	when: when,

	/* in / out as the arrow a phone's call list shows */
	dir: function(d) {
		return d == 'in' ? '↙ ' + _('incoming') : (d == 'out' ? '↗ ' + _('outgoing') : '?');
	},

	result: function(r) { return RESULTS[r] || r || '?'; },

	/* a CSS class for the result badge: answered green, missed red */
	result_class: function(r) {
		return r == 'answered' ? 'success' : (r == 'missed' || r == 'failed' ? 'danger' : 'notice');
	},

	reg_state: function(s) { return STATES[s] || s || '?'; },

	call_state: function(s) { return CALL_STATES[s] || s || '?'; },

	/* how long a call talked (answered -> end), or rang when not answered */
	talk: function(r) {
		if (!r || r.end == null)
			return '-';
		return r.answered != null ? dur(r.end - r.answered) : '-';
	},

	number: function(n) { return (n == null || n === '') ? _('withheld') : String(n); },

	/* the relay's packet counters: "123 / 456" (to the network / from it) */
	packets: function(p) {
		if (!p)
			return '-';
		return '%d ↑ / %d ↓'.format(+(p.up || 0), +(p.down || 0));
	},

	/* the UE registration as [ label, text ] rows (backend 'ue') */
	ue_rows: function(st) {
		var ue = st && st.ue;
		if (!ue)
			return [];
		var rows = [ [ _('Registration'), this.reg_state(ue.state) ] ];
		if (ue.impu)
			rows.push([ _('Public identity'), ue.impu ]);
		if (ue.ue_addr)
			rows.push([ _('UE address'), ue.ue_addr ]);
		if (ue.pcscf)
			rows.push([ _('P-CSCF'), ue.pcscf ]);
		if (ue.expires != null)
			rows.push([ _('Registration expiry'), dur(ue.expires) ]);
		rows.push([ _('Operator profile'), ue.profile || _('built-in defaults') ]);
		rows.push([ _('SMS over IMS'), ue.smsip ? _('on') : _('off') ]);
		if (ue.reg_event)
			rows.push([ _('Registration events'), REG_EVENT[ue.reg_event] || ue.reg_event ]);
		return rows;
	},

	/* the VoWiFi tunnel (st.vowifi) as rows, [] without it */
	vowifi_rows: function(st) {
		var v = st && st.vowifi;
		if (!v)
			return [];
		var rows = [
			[ _('Tunnel'), TUNNEL[v.state] || v.state || '?' ],
			[ _('ePDG'), v.epdg || '-' ],
		];
		if (v.v6 || v.v4)
			rows.push([ _('Inner address'), [ v.v6, v.v4 ].filter(function(x) { return x; }).join(', ') ]);
		if (v.pcscf && v.pcscf.length)
			rows.push([ _('P-CSCF'), v.pcscf.join(', ') ]);
		rows.push([ _('Interface'), v.vrf ? '%s (VRF %s)'.format(v.dev || '?', v.vrf) : (v.dev || '?') ]);
		if (v.state != 'up' && v.error)
			rows.push([ _('Last error'), String(v.error) ]);
		return rows;
	},

	/* sipd itself as rows */
	gw_rows: function(st) {
		if (!st)
			return [];
		var rows = [
			[ _('Backend'), st.backend == 'ue' ? _('router IMS UE') : _('modem IMS (QMI)') ],
			[ _('Modem'), st.modem || '-' ],
			[ _('SIP listener'), '%s:%d'.format(st.listen || '?', +(st.port || 0)) ],
		];
		if (st.started != null && st.now != null)
			rows.push([ _('Running for'), dur(st.now - st.started) ]);
		return rows;
	},

	/* the extensions as [ user, state, where, expires ] */
	ext_rows: function(st) {
		var ex = (st && st.extensions) || {};
		return Object.keys(ex).sort().map(function(u) {
			var e = ex[u] || {};
			if (!e.registered)
				return [ u, _('not registered'), '-', '-' ];
			return [ u, _('registered'), '%s:%d (%s)'.format(e.address || '?', +(e.port || 0), e.transport || 'UDP'),
			         dur(e.expires) ];
		});
	},

	/* the running call as rows, [] without one */
	call_rows: function(st) {
		var c = st && st.call;
		if (!c)
			return [];
		var rows = [
			[ _('Direction'), this.dir(c.dir) ],
			[ _('Number'), this.number(c.number) ],
			[ _('Extension'), c.extension || '-' ],
			[ _('State'), this.call_state(c.state) ],
			[ _('Started'), when(c.start, st.now) ],
		];
		if (c.answered != null)
			rows.push([ _('Talking for'), dur(st.now - c.answered) ]);
		else if (c.start != null)
			rows.push([ _('Ringing for'), dur(st.now - c.start) ]);
		if (c.codec)
			rows.push([ _('Codec'), String(c.codec) ]);
		if (c.packets)
			rows.push([ _('RTP packets'), this.packets(c.packets) ]);
		return rows;
	},

	/* the call list as rows: [ time, direction, number, extension, result,
	   duration, codec, reason, result ] (the last for the badge class) */
	history_rows: function(h, now) {
		var self = this;
		return (h || []).map(function(r) {
			return [ when(r.start, now), self.dir(r.dir), self.number(r.number), r.extension || '-',
			         self.result(r.result), self.talk(r), r.codec ? String(r.codec) : '-', r.reason || '', r.result ];
		});
	},
});
