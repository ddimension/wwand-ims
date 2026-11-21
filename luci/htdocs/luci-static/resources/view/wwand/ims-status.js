'use strict';
'require view';
'require rpc';
'require poll';
'require dom';
'require uci';
'require wwand.imsfmt as fmt';

/* VoLTE status (wwand-ims): sipd's own view, per IMS line (one sipd per
   ims_modem section) — the IMS registration of the router's UE, the phones
   registered at that line, the running call and the last calls. Everything
   comes from `ubus call wwand-ims.<modem> status|calls` (read acl; an
   older sipd has `wwand-ims` only); when a line's sipd does not run there
   is nothing to show for it but that. Refreshed every 5 s. */

var rpcs = {};
function lineCall(obj, method) {
	var k = obj + '/' + method;
	if (!rpcs[k])
		rpcs[k] = rpc.declare({ object: obj, method: method, expect: { '': {} } });
	return L.resolveDefault(rpcs[k](), null);
}

/* the lines: the ims_modem sections, each with its modem's object */
function lines() {
	var out = uci.sections('wwand_ims', 'ims_modem').map(function(s, i) {
		return { name: s['.name'], modem: s.modem, index: i,
		         obj: (s.modem || s.card) ? 'wwand-ims.' + (s.modem || s['.name']) : 'wwand-ims' };
	});
	return out.length ? out : [ { name: null, modem: null, index: 0, obj: 'wwand-ims' } ];
}

/* [ label, text ] rows as a two-column table. Values as arrays: they come
   from the network (identities, addresses) and must not go through
   innerHTML (luci.js dom.append on a bare string) */
function kv(rows) {
	return E('table', { 'class': 'table' }, rows.map(function(r) {
		return E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td left', 'width': '33%' }, [ r[0] ]),
			E('td', { 'class': 'td left' }, [ r[1] ]),
		]);
	}));
}

function grid(head, rows, cell) {
	return E('table', { 'class': 'table' }, [
		E('tr', { 'class': 'tr table-titles' }, head.map(function(h) {
			return E('th', { 'class': 'th' }, [ h ]);
		})),
	].concat(rows.map(function(r) {
		/* only as many cells as there are titles: a row may carry more
		   (history_rows: the raw result, for the badge) */
		return E('tr', { 'class': 'tr' }, r.slice(0, head.length).map(function(v, i) {
			return E('td', { 'class': 'td' }, cell ? cell(v, i, r) : [ v ]);
		}));
	})));
}

function section(title, body) {
	return E('div', { 'class': 'cbi-section' }, [ E('h3', {}, [ title ]) ].concat(body));
}

function empty(text) {
	return E('p', {}, E('em', {}, [ text ]));
}

return view.extend({
	load: function() {
		return uci.load('wwand_ims').then(function() {
			return Promise.all(lines().map(function(l) {
				return Promise.all([ lineCall(l.obj, 'status'), lineCall(l.obj, 'calls') ]).then(function(r) {
					/* the first line answers on wwand-ims as well (older sipd) */
					if (!r[0] && l.index == 0 && l.obj != 'wwand-ims')
						return Promise.all([ lineCall('wwand-ims', 'status'), lineCall('wwand-ims', 'calls') ])
							.then(function(r2) { return { line: l, st: r2[0], calls: r2[1] }; });
					return { line: l, st: r[0], calls: r[1] };
				});
			}));
		});
	},

	renderAll: function(data) {
		var many = data.length > 1;

		return E('div', {}, data.map(L.bind(function(d) {
			var title = many ? _('Line %s (%s)').format(d.line.name, d.line.modem || '?') : null;
			var body = this.renderLine(d.st, d.calls);
			return title ? E('div', { 'class': 'cbi-section' }, [ E('h2', {}, [ title ]), body ]) : body;
		}, this)));
	},

	renderLine: function(st, calls) {
		if (!st || st.backend == null)
			return E('div', {}, [
				section(_('IMS'), [ empty(_('sipd is not running for this line (service wwand-ims-sipd). Set it up under Network → VoLTE, then start it.')) ]),
			]);

		var parts = [];

		parts.push(section(_('IMS registration'),
			st.ue ? [ kv(fmt.ue_rows(st)) ]
			      : [ empty(_('Backend qmi: the modem registers to IMS itself; its state is on the Modem status page.')) ]));

		var vw = fmt.vowifi_rows(st);
		if (vw.length)
			parts.push(section(_('VoWiFi'), [ kv(vw) ]));

		parts.push(section(_('Gateway'), [ kv(fmt.gw_rows(st)) ]));

		var ex = fmt.ext_rows(st);
		parts.push(section(_('Phones'), ex.length
			? [ grid([ _('Extension'), _('State'), _('Contact'), _('Expires in') ], ex) ]
			: [ empty(_('No extension configured.')) ]));

		var cr = fmt.call_rows(st);
		parts.push(section(_('Current call'), cr.length ? [ kv(cr) ] : [ empty(_('No call.')) ]));

		var hr = fmt.history_rows(calls && calls.calls, calls && calls.now);
		parts.push(section(_('Last calls'), hr.length
			? [ grid([ _('Time'), _('Direction'), _('Number'), _('Extension'), _('Result'), _('Duration'), _('Codec'), _('Reason') ],
				hr,
				function(v, i, r) {
					if (i == 4)
						return E('span', { 'class': 'label ' + fmt.result_class(r[8]) }, [ v ]);
					if (i == 7)
						return E('small', {}, [ v ]);
					return [ v ];
				}) ]
			: [ empty(_('No calls yet.')) ]));

		return E('div', {}, parts);
	},

	render: function(data) {
		var self = this;
		var body = E('div', { 'id': 'wwand-ims-status' }, [ this.renderAll(data) ]);

		poll.add(function() {
			return self.load().then(function(d) {
				dom.content(body, self.renderAll(d));
			});
		}, 5);

		return E([], [
			E('h2', {}, _('VoLTE')),
			E('div', { 'class': 'cbi-map-descr' }, _('Voice over LTE for the phones on the LAN: the IMS registration, the phones registered at the router, the running call and the last ten calls.')),
			body,
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null,
});
