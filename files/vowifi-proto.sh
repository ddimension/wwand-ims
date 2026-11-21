#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 André Valentin <avalentin@marcant.net>
# wwand-ims-vowifi — netifd proto handler of the VoWiFi tunnel (proto
# wwandvowifi), wwand's model: sipd keeps the IKEv2 tunnel to the ePDG,
# netifd does the router side — the XFRM interface (OpenWrt's proto xfrm)
# and, through this handler on its alias, the IP configuration. On setup
# and on every renew (sipd calls `network.interface.<name> renew` when the
# tunnel comes up or changes) this asks sipd for the inner addresses and
# hands them to netifd with a default route; ip4table/ip6table of the
# interface put them into the tunnel's VRF table, with netifd's `from`
# rules. While the tunnel is down the link is reported down.
#
#   config interface 'wwvowifi'
#   	option proto 'wwandvowifi'
#   	option device '@imswifi0'	# config interface 'imswifi0', proto xfrm
#   	option ip4table '31'
#   	option ip6table '31'

[ -n "$INCLUDE_ONLY" ] || {
	. /lib/functions.sh
	. ../netifd-proto.sh
	init_proto "$@"
}

proto_wwandvowifi_init_config() {
	available=1
	renew_handler=1
	# sipd owns the tunnel and drives netifd (renew) over ubus: no task here
	no_proto_task=1
}

_wwandvowifi_update() {
	local interface="$1" device="$2"
	local resp up v4 v6

	# everything out of sipd's answer FIRST: proto_init_update starts a new
	# JSON document and the reply's would be gone
	resp="$(ubus -t 5 call wwand-ims vowifi_addr 2>/dev/null)"
	if [ -n "$resp" ]; then
		json_load "$resp"
		json_get_vars up v4 v6
	fi

	if [ "$up" != "1" ]; then
		proto_init_update "$device" 0
		proto_send_update "$interface"
		return 0
	fi

	proto_init_update "$device" 1
	[ -n "$v4" ] && {
		proto_add_ipv4_address "$v4" 32
		proto_add_ipv4_route "0.0.0.0" 0
	}
	[ -n "$v6" ] && {
		proto_add_ipv6_address "$v6" 128
		proto_add_ipv6_route "::" 0
	}
	proto_send_update "$interface"
}

proto_wwandvowifi_setup() {
	_wwandvowifi_update "$1" "$2"
}

proto_wwandvowifi_renew() {
	_wwandvowifi_update "$1" "$2"
}

proto_wwandvowifi_teardown() {
	return 0
}

[ -n "$INCLUDE_ONLY" ] || {
	add_protocol wwandvowifi
}
