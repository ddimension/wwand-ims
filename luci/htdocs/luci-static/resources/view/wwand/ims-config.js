'use strict';
'require view';
'require form';
'require rpc';
'require uci';
'require ui';
'require tools.widgets as widgets';

/* VoLTE settings (wwand-ims): /etc/config/wwand_ims — the SIP side
   (sip_gateway), the phones or PBX trunks (extension), the modem carrying
   IMS (ims_modem) and the operator profiles (ims_profile). Saving reloads
   sipd (its init script has a reload trigger on wwand_ims). Only the
   options sipd and the router's UE act on are here; the [modem]/[mbn]
   values of a profile are `wwandctl ims` matters and stay as they are. */

var callStatus = rpc.declare({ object: 'wwand', method: 'status', expect: { modems: {} } });
var callSnapshot = rpc.declare({ object: 'wwand-ims', method: 'profile_snapshot', expect: { '': {} } });

/* "Clone current settings": sipd builds a profile from the modem's carrier
   configuration and what the network gave the router's UE (sipd/profile.uc
   snapshot); asked for a name, it goes into the staged uci changes like a
   section added by hand, and is saved with Save & Apply */
function clone_current(map) {
	return callSnapshot().then(function(res) {
		if (!res || res.ok === false || !res.options) {
			ui.addNotification(null, E('p', {}, [ _('No profile from the current settings: %s').format(
				(res && res.error) || _('sipd does not answer (is it running?)')) ]), 'warning');
			return;
		}

		var input = E('input', { 'class': 'cbi-input-text', 'value': res.name || 'operator' });
		var note = [];
		if (res.sources && !res.sources.registered)
			note.push(_('The UE is not registered: the network\'s values are missing.'));
		if (res.sources && !res.sources.mbn)
			note.push(_('The modem names no carrier configuration (MBN).'));

		ui.showModal(_('New operator profile from the current settings'), [
			E('p', {}, _('From the modem\'s carrier configuration (MBN, IMS APN, voice domain) and what the network gave the router\'s UE (registration expiry, IPsec algorithms, domain, SMS centre).')),
			E('p', {}, [ E('em', {}, note.join(' ')) ]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Profile name')),
				E('div', { 'class': 'cbi-value-field' }, input),
			]),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Cancel')), ' ',
				E('button', { 'class': 'btn cbi-button-positive', 'click': ui.createHandlerFn(this, function() {
					var name = input.value.trim();
					if (!/^[a-z0-9_]{1,40}$/.test(name)) {
						ui.addNotification(null, E('p', {}, _('A profile name has lower-case letters, digits and _ only.')), 'warning');
						return;
					}
					if (uci.get('wwand_ims', name)) {
						ui.addNotification(null, E('p', {}, [ _('There is a section named %s already.').format(name) ]), 'warning');
						return;
					}
					uci.add('wwand_ims', 'ims_profile', name);
					for (var k in res.options)
						uci.set('wwand_ims', name, k, res.options[k]);
					ui.hideModal();
					return map.save(null, true).then(function() {
						ui.addNotification(null, E('p', {}, [ _('Profile %s added from the current settings; Save & Apply keeps it.').format(name) ]), 'info');
					});
				}) }, _('Create')),
			]),
		]);
	});
}

/* ms / s / count: an empty field means "the default" */
function numeric(o, min) {
	o.datatype = min != null ? 'min(%d)'.format(min) : 'uinteger';
	o.rmempty = true;
	return o;
}

return view.extend({
	load: function() {
		return Promise.all([
			L.resolveDefault(callStatus(), {}),
			uci.load('wwand_ims'),
			uci.load('network'),
		]);
	},

	render: function(data) {
		/* the modems wwand knows, and the ones the config names (wwand may not
		   run): suggestions only, a Value keeps whatever is set */
		var seen = {};
		Object.keys(data[0] || {}).forEach(function(n) { seen[n] = true; });
		uci.sections('network', 'wwand_modem').forEach(function(s) { seen[s['.name']] = true; });
		uci.sections('wwand_ims').forEach(function(s) { if (s.modem) seen[s.modem] = true; });
		var modems = Object.keys(seen).sort();
		var ifaces = uci.sections('network', 'interface').map(function(s) { return s['.name']; })
			.filter(function(n) { return n != 'loopback'; });
		var m, s, o;

		m = new form.Map('wwand_ims', _('VoLTE'),
			_('Voice over LTE for phones on the LAN: the router registers to the operator\'s IMS and bridges the calls to the SIP phones or PBX trunks registered here. Saving restarts the SIP daemon; a call running then is dropped.'));

		/* ---- the SIP side -------------------------------------------------- */
		s = m.section(form.NamedSection, 'main', 'sip_gateway', _('SIP gateway'),
			_('Where the LAN phones register.'));
		s.addremove = false;

		/* a Value, not a NetworkSelect: sipd also takes an address here */
		o = s.option(form.Value, 'listen', _('Listen on'),
			_('An interface, whose IPv4 address the phones register to, or an address.'));
		ifaces.forEach(function(n) { o.value(n); });
		o.placeholder = 'lan';
		o.rmempty = true;

		o = s.option(form.Value, 'port', _('Port'));
		o.datatype = 'port';
		o.placeholder = '5060';
		o.rmempty = true;

		o = s.option(form.Value, 'realm', _('Realm'), _('The digest realm the phones authenticate in.'));
		o.placeholder = 'wwand-ims';
		o.rmempty = true;

		o = s.option(form.MultiValue, 'codec', _('Codecs (backend qmi)'),
			_('What sipd answers the phone with when the modem carries the call. With the router\'s own UE the phone must offer AMR-WB or AMR, which are relayed as they are.'));
		o.value('g722', 'G.722');
		o.value('pcma', 'G.711 A-law');
		o.value('pcmu', 'G.711 µ-law');
		o.rmempty = true;

		o = s.option(form.Value, 'call_history', _('Call list file'),
			_('Where the last ten calls are kept. The default is in RAM and gone after a reboot; a file on flash costs one write per call.'));
		o.placeholder = '/var/run/wwand-ims-sipd.calls';
		o.rmempty = true;

		o = s.option(form.Flag, 'redirect_info', _('Forwarding information'),
			_('A forwarded call (e.g. a landline diverted to this number): the network\'s History-Info is passed on, with Diversion headers made from it (who forwarded, why). The network itself leaves out what may not be shown.'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.Value, 'sip_trace', _('SIP trace file'),
			_('For debugging only: every SIP message of both sides is written there in full, identities and keys included. Leave empty in normal operation.'));
		o.placeholder = '/tmp/wwand-ims-sip.trace';
		o.rmempty = true;

		/* ---- phones / trunks ------------------------------------------------ */
		s = m.section(form.TypedSection, 'extension', _('Phones'),
			_('A SIP phone or a PBX trunk that registers here with this user name and password. Incoming calls ring the first one registered.'));
		s.anonymous = true;
		s.addremove = true;

		o = s.option(form.Value, 'username', _('User name'));
		o.rmempty = false;
		o.datatype = 'and(minlength(1),maxlength(64))';

		o = s.option(form.Value, 'password', _('Password'));
		o.password = true;
		o.rmempty = false;

		o = s.option(form.ListValue, 'line', _('IMS line'),
			_('The line (IMS modem) this phone or trunk uses: it registers at that line\'s SIP port. Default: the first line.'));
		o.value('', _('first line'));
		uci.sections('wwand_ims', 'ims_modem').forEach(function(l, i) {
			o.value(l['.name'], '%s (%s)'.format(l['.name'], l.modem || '?'));
		});
		o.rmempty = true;

		/* ---- the IMS lines: one per modem ----------------------------------- */
		s = m.section(form.TypedSection, 'ims_modem', _('IMS lines'),
			_('One IMS line per modem: its SIM and IMS connection carry the calls of the phones assigned to it. Each line runs its own instance of sipd with its own SIP port for the phones (the first one the gateway\'s port, then one more per line), VRF, tunnel and RTP ports. Run `wwandctl ims <modem> setup` for each.'));
		s.anonymous = false;
		s.addremove = true;

		o = s.option(form.Value, 'modem', _('Modem'), _('The wwand_modem section in /etc/config/network. Empty for a SIM card in a reader (below).'));
		modems.forEach(function(n) { o.value(n); });

		o = s.option(form.Value, 'card', _('SIM card without a modem'),
			_('VoWiFi only, with the SIM in a card reader instead of a modem: a reader of wwand-rsim\'s rsim-card, for example pcsc:0, or ssh:root@host:wwand:wwmodem0 for the card of a modem on another router. Needs backend Router IMS UE; no IMS PDN, no SMS.'));
		o.placeholder = 'pcsc:0';

		o = s.option(form.ListValue, 'backend', _('Backend'),
			_('Router IMS UE: the router registers itself, with the modem\'s SIM; it needs the IMS PDN as its own interface in a VRF. Modem IMS: the modem\'s own VoLTE, driven over QMI.'));
		o.value('ue', _('Router IMS UE'));
		o.value('qmi', _('Modem IMS (QMI)'));
		o.default = 'qmi';

		o = s.option(form.ListValue, 'access', _('IMS access'),
			_('IMS PDN: over the modem\'s IMS connection. VoWiFi: through an IKEv2 tunnel to the operator\'s ePDG over the router\'s internet connection (package wwand-ims-vowifi). Both: the first one, the other while it does not work (back after a minute of working again); a running call ends at the switch.'));
		o.value('pdn', _('IMS PDN'));
		o.value('vowifi', _('VoWiFi (ePDG)'));
		o.value('vowifi pdn', _('VoWiFi, IMS PDN as fallback'));
		o.value('pdn vowifi', _('IMS PDN, VoWiFi as fallback'));
		o.default = 'pdn';
		o.depends('backend', 'ue');

		o = s.option(form.Value, 'epdg', _('ePDG'),
			_('Default: epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org from the SIM.'));
		o.datatype = 'host';
		o.rmempty = true;
		o.depends({ access: /vowifi/ });

		o = s.option(form.ListValue, 'vowifi_loglevel', _('Tunnel log detail'),
			_('How much of the tunnel setup (IKEv2, EAP-AKA) strongSwan reports to the system log. 2 shows every IKE step; for debugging.'));
		o.value('', _('Normal (1)'));
		o.value('0', _('Quiet (0)'));
		o.value('2', _('Every IKE step (2)'));
		o.value('3', _('Raw (3)'));
		o.value('4', _('With keys (4) — never in normal operation'));
		o.rmempty = true;
		o.depends({ access: /vowifi/ });

		o = s.option(widgets.NetworkSelect, 'ims_iface', _('IMS interface'),
			_('The interface (proto wwand) of the IMS PDN.'));
		o.nocreate = true;
		o.placeholder = 'wwims';
		o.depends({ backend: 'ue', access: 'pdn' });

		o = s.option(form.Value, 'vrf', _('VRF'), _('The VRF device the IMS interface is in.'));
		o.placeholder = 'ims';
		o.depends('backend', 'ue');

		o = s.option(form.ListValue, 'profile', _('Operator profile'),
			_('Automatic: the profile whose IMSI or ICCID prefix matches the SIM.'));
		o.value('', _('automatic'));
		uci.sections('wwand_ims', 'ims_profile').forEach(function(p) {
			o.value(p['.name'], p.label ? '%s (%s)'.format(p.label, p['.name']) : p['.name']);
		});
		o.cfgvalue = function(sid) {
			var v = uci.get('wwand_ims', sid, 'profile');
			return (v == 'auto') ? '' : v;
		};
		o.rmempty = true;

		o = s.option(form.Flag, 'smsip', _('SMS over IMS'),
			_('The router registers for SMS too. What arrives is stored in the modem like an SMS it received itself (Modem Tools → SMS), and SMS sent through wwand go over IMS. With one number on several SIMs the network may then deliver SMS to the router instead of the phone.'));
		o.depends('backend', 'ue');
		o.rmempty = true;

		o = s.option(form.ListValue, 'sms_storage', _('SMS storage'),
			_('Where an SMS received over IMS is stored.'));
		o.value('ME', _('Modem memory'));
		o.value('SM', _('SIM card'));
		o.default = 'ME';
		o.depends('smsip', '1');

		o = s.option(form.DynamicList, 'pcscf', _('P-CSCF'),
			_('Fixed P-CSCF addresses instead of the ones the IMS PDN names.'));
		o.datatype = 'ipaddr';
		o.depends('backend', 'ue');

		o = s.option(form.Value, 'ims_apn', _('IMS APN'),
			_('Only to find the IMS PDN among the modem\'s contexts; default: the interface\'s APN.'));
		o.depends('backend', 'ue');
		o.rmempty = true;

		o = numeric(s.option(form.Value, 'sip_port', _('SIP port for the phones'),
			_('Default: the gateway\'s port for the first line, one more for each further line.')), 1);
		o = numeric(s.option(form.Value, 'rtp_base', _('RTP port base')), 1024);
		o.placeholder = _('40000 + 200 per line');
		o.depends('backend', 'ue');
		o = numeric(s.option(form.Value, 'rtp_span', _('RTP ports')), 2);
		o.placeholder = '200';
		o.depends('backend', 'ue');

		/* ---- per SIM: overrides by ICCID -------------------------------- */
		s = m.section(form.TypedSection, 'ims_sim', _('SIM cards'),
			_('Settings of one SIM card, matched by its ICCID (or a prefix), over those of the line it is in: a card may use VoWiFi where another one in the same modem uses the IMS PDN. A line starts again by itself when its modem gets another card.'));
		s.anonymous = false;
		s.addremove = true;

		o = s.option(form.Value, 'label', _('Label'));
		o.rmempty = true;
		o = s.option(form.DynamicList, 'iccid', _('ICCID'), _('The card\'s ICCID, or a prefix of it; the longest match wins.'));
		o.datatype = 'and(minlength(4),maxlength(22))';
		o.rmempty = false;
		o = s.option(form.ListValue, 'access', _('IMS access'));
		o.value('', _('as the line'));
		o.value('pdn', _('IMS PDN'));
		o.value('vowifi', _('VoWiFi (ePDG)'));
		o.value('vowifi pdn', _('VoWiFi, IMS PDN as fallback'));
		o.value('pdn vowifi', _('IMS PDN, VoWiFi as fallback'));
		o.rmempty = true;
		o = s.option(form.ListValue, 'profile', _('Operator profile'));
		o.value('', _('as the line'));
		uci.sections('wwand_ims', 'ims_profile').forEach(function(p) {
			o.value(p['.name'], p.label ? '%s (%s)'.format(p.label, p['.name']) : p['.name']);
		});
		o.rmempty = true;
		o = s.option(form.ListValue, 'smsip', _('SMS over IMS'));
		o.value('', _('as the line'));
		o.value('1', _('on'));
		o.value('0', _('off'));
		o.rmempty = true;
		o = s.option(form.Value, 'epdg', _('ePDG'));
		o.datatype = 'host';
		o.rmempty = true;
		o.depends({ access: /vowifi/ });

		/* ---- operator profiles --------------------------------------------- */
		s = m.section(form.TypedSection, 'ims_profile', _('Operator profiles'),
			_('Values of the router\'s IMS UE per operator. An empty field keeps the built-in default.'));
		s.addremove = true;
		s.anonymous = false;
		s.nodescriptions = true;
		/* next to "Add": a new profile cloned from what is in use now */
		s.renderSectionAdd = function(extra_class) {
			var el = form.TypedSection.prototype.renderSectionAdd.apply(this, [ extra_class ]);
			el.appendChild(E('button', {
				'class': 'cbi-button cbi-button-add',
				'title': _('A new profile from the modem\'s carrier configuration and the network\'s values'),
				'click': ui.createHandlerFn(this, function(ev) {
					ev.preventDefault();
					return clone_current(m);
				}),
			}, [ _('Clone current settings') ]));
			return el;
		};

		s.tab('match', _('Match'));
		s.tab('carrier', _('Carrier'));
		s.tab('sip', _('SIP'));
		s.tab('security', _('Security'));
		s.tab('media', _('Calls'));
		s.tab('sms', _('SMS'));
		s.tab('vowifi', _('VoWiFi'));

		o = s.taboption('match', form.Value, 'label', _('Label'));
		o.rmempty = true;
		o = s.taboption('match', form.DynamicList, 'match_imsi', _('IMSI prefixes'));
		o.datatype = 'and(uinteger,maxlength(15))';
		o = s.taboption('match', form.DynamicList, 'match_iccid', _('ICCID prefixes'));
		o.datatype = 'and(uinteger,maxlength(20))';

		/* the modem's side of a profile (wwandctl ims check/fix/mbn act on it) */
		o = s.taboption('carrier', form.Value, 'mbn', _('Carrier configuration (MBN)'),
			_('auto: the modem chooses; a name: that one is selected.'));
		o.rmempty = true;
		o = s.taboption('carrier', form.Value, 'ims_apn', _('IMS APN'));
		o.rmempty = true;
		o = s.taboption('carrier', form.ListValue, 'ims_pdp_type', _('IMS PDP type'));
		o.value('', _('default'));
		o.value('ipv4', 'IPv4');
		o.value('ipv6', 'IPv6');
		o.value('ipv4v6', 'IPv4v6');
		o.rmempty = true;
		o = s.taboption('carrier', form.ListValue, 'voice_domain', _('Voice domain'));
		o.value('', _('default'));
		o.value('cs_only', _('CS only'));
		o.value('ps_only', _('PS only'));
		o.value('cs_preferred', _('CS preferred'));
		o.value('ps_preferred', _('PS preferred'));
		o.rmempty = true;
		o = s.taboption('carrier', form.ListValue, 'usage', _('UE usage'));
		o.value('', _('default'));
		o.value('voice_centric', _('voice centric'));
		o.value('data_centric', _('data centric'));
		o.rmempty = true;
		o = s.taboption('carrier', form.Value, 'domain', _('Home domain'),
			_('Default: ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org from the IMSI.'));
		o.datatype = 'hostname';
		o.rmempty = true;

		o = numeric(s.taboption('sip', form.Value, 'sip_t1_ms', _('SIP T1 (ms)')), 100);
		o.placeholder = '500';
		o = numeric(s.taboption('sip', form.Value, 'sip_t2_s', _('SIP T2 (s)')), 1);
		o.placeholder = '4';
		o = numeric(s.taboption('sip', form.Value, 'reg_expires', _('Registration expiry (s)'),
			_('Asked for; the network decides.')), 60);
		o = s.taboption('sip', form.Value, 'sip_transport', _('Transports'),
			_('udp,tcp; without tcp the UE does not listen on TCP.'));
		o.placeholder = 'udp,tcp';
		o.rmempty = true;
		o = s.taboption('sip', form.Flag, 'reg_event', _('Registration events'),
			_('Subscribe to the registration state (RFC 3680).'));
		o.default = '1';
		/* kept as 0 when off: an absent option means on */
		o.rmempty = false;
		o = s.taboption('sip', form.Value, 'user_agent', _('User-Agent'));
		o.rmempty = true;
		o = s.taboption('sip', form.Value, 'pcscf_port', _('P-CSCF port'));
		o.datatype = 'port';
		o.placeholder = '5060';
		o.rmempty = true;

		o = s.taboption('security', form.ListValue, 'ipsec_integrity', _('IPsec integrity'));
		o.value('', _('default (all)'));
		o.value('hmac-sha-1-96', 'HMAC-SHA-1-96');
		o.value('hmac-md5-96', 'HMAC-MD5-96');
		o.rmempty = true;
		o = s.taboption('security', form.MultiValue, 'ipsec_encryption', _('IPsec encryption'));
		o.value('null', _('none (null)'));
		o.value('aes', 'AES-CBC');
		o.value('3des', '3DES');
		o.rmempty = true;

		o = numeric(s.taboption('media', form.Value, 'alert_delay_ms', _('Ringing delay (ms)'),
			_('An incoming call: the router reports "ringing" to the network this late, while the LAN phone rings at once. When the number has further SIMs (MultiSIM), a phone in idle is otherwise not alerted. 0 = at once. Keep it below 5000: Telekom gives up on the router after 5.9 s without it.')));
		o.placeholder = '4500';
		o = s.taboption('sms', form.Value, 'sms_smsc', _('SMS centre'),
			_('Default: the one an SMS came from, else the SIM\'s.'));
		o.datatype = 'and(minlength(3),maxlength(21))';
		o.placeholder = '+491234567890';
		o.rmempty = true;
		o = s.taboption('sms', form.Value, 'sms_psi', _('SMS centre URI'),
			_('Where outgoing SMS are sent, %s for the centre\'s number. Default: tel:<number>.'));
		o.placeholder = 'sip:%s@ims.example.net;user=phone';
		o.rmempty = true;

		/* what the operator's ePDG wants (ims_modem option access 'vowifi');
		   an empty field keeps what Telekom DE's took */
		o = s.taboption('vowifi', form.Value, 'vowifi_epdg', _('ePDG'),
			_('Default: epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org from the SIM.'));
		o.datatype = 'host';
		o.rmempty = true;
		o = s.taboption('vowifi', form.Value, 'vowifi_apn', _('APN (IDr)'),
			_('Sent as the IKE responder identity (TS 24.302). Default: ims; %any sends none. The identity the ePDG answers with is accepted (strongSwan plugin epdg-idr).'));
		o.rmempty = true;
		o = s.taboption('vowifi', form.DynamicList, 'vowifi_proposals', _('IKE proposals'),
			_('strongSwan notation. Default: aes256-sha512-modp4096, then charon\'s defaults.'));
		o = s.taboption('vowifi', form.DynamicList, 'vowifi_esp_proposals', _('ESP proposals'),
			_('Default: charon\'s.'));
		o = s.taboption('vowifi', form.ListValue, 'vowifi_remote_auth', _('ePDG authentication'));
		o.value('', _('EAP-AKA only (default)'));
		o.value('eap-aka', _('EAP-AKA only'));
		o.value('pubkey', _('certificate'));
		o.rmempty = true;
		o = s.taboption('vowifi', form.Value, 'vowifi_pani', _('P-Access-Network-Info'));
		o.placeholder = 'IEEE-802.11';
		o.rmempty = true;
		o = numeric(s.taboption('vowifi', form.Value, 'vowifi_rekey_s', _('IKE rekeying (s)'),
			_('0 or empty: no rekeying. wwandctl ims setup takes it from the carrier config.')));
		o.placeholder = '0';
		o = numeric(s.taboption('vowifi', form.Value, 'vowifi_esp_rekey_s', _('ESP rekeying (s)'),
			_('0 or empty: no rekeying.')));
		o.placeholder = '0';
		o = numeric(s.taboption('vowifi', form.Value, 'vowifi_dpd_s', _('Dead peer detection (s)'),
			_('0: off.')));
		o.placeholder = '60';

		o = numeric(s.taboption('media', form.Value, 'rtp_timeout_s', _('RTP timeout (s)'),
			_('End a call when a side sends no RTP for that long; 0 = never.')));
		o.placeholder = '30';
		o = numeric(s.taboption('media', form.Value, 'rtcp_timeout_s', _('RTCP timeout (s)'),
			_('The same for RTCP; 0 = off.')));
		o.placeholder = '0';

		return m.render();
	},
});
