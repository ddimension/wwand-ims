'use strict';
'require view';
'require rpc';
'require poll';
'require dom';
'require wwand.imsfmt as fmt';

/* VoLTE status (wwand-ims): sipd's own view — the IMS registration of the
   router's UE, the phones registered at sipd, the running call and the last
   calls. Everything comes from `ubus call wwand-ims status|calls` (read
   acl); sipd publishes that object, so when sipd does not run there is
   nothing to show but that. Refreshed every 5 s. */

var callStatus = rpc.declare({ object: 'wwand-ims', method: 'status', expect: { '': {} } });
var callCalls = rpc.declare({ object: 'wwand-ims', method: 'calls', expect: { '': {} } });

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
		return Promise.all([
			L.resolveDefault(callStatus(), null),
			L.resolveDefault(callCalls(), null),
		]);
	},

	renderAll: function(data) {
		var st = data[0], calls = data[1];

		if (!st || st.backend == null)
			return E('div', {}, [
				section(_('IMS'), [ empty(_('sipd is not running (service wwand-ims-sipd). Set it up under Network → VoLTE, then start it.')) ]),
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
