#!/bin/sh
# calltest.sh HOST NUMBER [MODEM]
#
# Hardware test of the ims plugin, run from a workstation: reset the modem
# (so nothing the plugin set earlier survives in it), wait until IMS is
# registered with voice available, dial NUMBER through the plugin, and pass
# once the call reaches the network's ringing state over LTE (the plugin's
# wwand.ims.call events; the network may still end it right after). Hangs up
# after a few seconds either way. The callee's phone rings briefly.
#
# Prints one line per step and ends with PASS or FAIL (exit 0 / 1).

host=$1
num=$2
modem=${3:-wwmodem0}

[ -n "$host" ] && [ -n "$num" ] || { echo "usage: $0 HOST NUMBER [MODEM]" >&2; exit 2; }

S="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o LogLevel=ERROR root@$host"

$S "modem=$modem num='$num'" 'sh -s' <<'EOF'
p() { ubus -t 30 call wwand modem_plugin "{\"modem\":\"$modem\",\"plugin\":\"ims\",\"op\":\"$1\",\"args\":$2}"; }
say() { echo "$(date +%T) $*"; }

say "modem reset"
ubus -t 30 call wwand modem_reset "{\"modem\":\"$modem\"}" >/dev/null || { say FAIL reset; exit 1; }
sleep 20

reg=
for i in $(seq 1 40); do
	r=$(p status '{}' 2>/dev/null)
	reg=$(echo "$r" | jsonfilter -e '@.registration.status' 2>/dev/null)
	voice=$(echo "$r" | jsonfilter -e '@.services.voice' 2>/dev/null)
	[ "$reg" = registered ] && [ "$voice" = available ] && break
	sleep 5
done
say "ims $reg, voice $voice"
[ "$reg" = registered ] && [ "$voice" = available ] || { say FAIL no ims; exit 1; }

# the VoLTE enable takes effect at the next registration; give the plugin's
# open (triggered by the status call above) a re-registration to land in
sleep 15

# the plugin's wwand.ims.call events show every state, even one that lasts
# less than a poll interval (a call the network ends right after 180 Ringing)
ev=/tmp/calltest.$$
timeout 30 ubus listen wwand.ims.call > $ev 2>/dev/null &
lp=$!
sleep 1

say "dial $num"
d=$(p dial "{\"number\":\"$num\"}")
id=$(echo "$d" | jsonfilter -e '@.id' 2>/dev/null)
say "dial -> $(echo "$d" | tr -d '\n\t')"

res=FAIL
if [ -n "$id" ]; then
	for i in $(seq 1 10); do
		sleep 2
		grep -q '"state":"alerting","direction":"mo","mode":"lte"' $ev && res=PASS
		grep -q '"state":"conversation"' $ev && res=PASS
		grep -q '"state":"end"' $ev && break
		[ $res = PASS ] && break
	done
	sed -n 's/.*"state":"\([a-z_]*\)".*"mode":"\([a-z0-9]*\)".*"end_reason":\([0-9a-z]*\).*/\1 over \2 (end reason \3)/p' $ev |
		uniq | while read -r l; do say "call $id $l"; done
	sleep 3
	p hangup "{\"id\":$id}" >/dev/null 2>&1
	say "hangup"
fi
kill $lp 2>/dev/null
rm -f $ev

say "$res"
[ "$res" = PASS ]
EOF
