'use strict';
'require view';
'require form';
'require rpc';
'require uci';
'require tools.widgets as widgets';

/* VoLTE settings (wwand-ims): /etc/config/wwand_ims — the SIP side
   (sip_gateway), the phones or PBX trunks (extension), the modem carrying
   IMS (ims_modem) and the operator profiles (ims_profile). Saving reloads
   sipd (its init script has a reload trigger on wwand_ims). Only the
   options sipd and the router's UE act on are here; the [modem]/[mbn]
   values of a profile are `wwandctl ims` matters and stay as they are. */

var callStatus = rpc.declare({ object: 'wwand', method: 'status', expect: { modems: {} } });

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

		o = s.option(form.Value, 'modem', _('Modem'));
		modems.forEach(function(n) { o.value(n); });
		o.rmempty = true;

		/* ---- the modem ------------------------------------------------------ */
		s = m.section(form.TypedSection, 'ims_modem', _('IMS modem'),
			_('The modem whose SIM and IMS connection carry the calls.'));
		s.anonymous = true;
		s.addremove = true;

		o = s.option(form.Value, 'modem', _('Modem'), _('The wwand_modem section in /etc/config/network.'));
		modems.forEach(function(n) { o.value(n); });
		o.rmempty = false;

		o = s.option(form.ListValue, 'backend', _('Backend'),
			_('Router IMS UE: the router registers itself, with the modem\'s SIM; it needs the IMS PDN as its own interface in a VRF. Modem IMS: the modem\'s own VoLTE, driven over QMI.'));
		o.value('ue', _('Router IMS UE'));
		o.value('qmi', _('Modem IMS (QMI)'));
		o.default = 'qmi';

		o = s.option(form.ListValue, 'access', _('IMS access'),
			_('IMS PDN: over the modem\'s IMS connection. VoWiFi: through an IKEv2 tunnel to the operator\'s ePDG over the router\'s internet connection (package wwand-ims-vowifi).'));
		o.value('pdn', _('IMS PDN'));
		o.value('vowifi', _('VoWiFi (ePDG)'));
		o.default = 'pdn';
		o.depends('backend', 'ue');

		o = s.option(form.Value, 'epdg', _('ePDG'),
			_('Default: epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org from the SIM.'));
		o.datatype = 'host';
		o.rmempty = true;
		o.depends('access', 'vowifi');

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

		o = numeric(s.option(form.Value, 'rtp_base', _('RTP port base')), 1024);
		o.placeholder = '40000';
		o.depends('backend', 'ue');
		o = numeric(s.option(form.Value, 'rtp_span', _('RTP ports')), 2);
		o.placeholder = '200';
		o.depends('backend', 'ue');

		/* ---- operator profiles --------------------------------------------- */
		s = m.section(form.TypedSection, 'ims_profile', _('Operator profiles'),
			_('Values of the router\'s IMS UE per operator. An empty field keeps the built-in default.'));
		s.addremove = true;
		s.anonymous = false;
		s.nodescriptions = true;

		s.tab('match', _('Match'));
		s.tab('sip', _('SIP'));
		s.tab('security', _('Security'));
		s.tab('media', _('Calls'));
		s.tab('sms', _('SMS'));

		o = s.taboption('match', form.Value, 'label', _('Label'));
		o.rmempty = true;
		o = s.taboption('match', form.DynamicList, 'match_imsi', _('IMSI prefixes'));
		o.datatype = 'and(uinteger,maxlength(15))';
		o = s.taboption('match', form.DynamicList, 'match_iccid', _('ICCID prefixes'));
		o.datatype = 'and(uinteger,maxlength(20))';

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

		o = numeric(s.taboption('media', form.Value, 'rtp_timeout_s', _('RTP timeout (s)'),
			_('End a call when a side sends no RTP for that long; 0 = never.')));
		o.placeholder = '30';
		o = numeric(s.taboption('media', form.Value, 'rtcp_timeout_s', _('RTCP timeout (s)'),
			_('The same for RTCP; 0 = off.')));
		o.placeholder = '0';

		return m.render();
	},
});
