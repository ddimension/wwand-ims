#!/bin/sh
# efs-dump.sh MODEM OUTDIR [PATHLIST]
#
# Read-only snapshot of the modem EFS items a carrier MBN writes (IMS, voice
# domain, SMS domain, ...), taken through wwand's `modem_at` so the daemon
# keeps its AT port. One <path>.hex per item, plus MANIFEST with the modem,
# firmware and MBN selection the snapshot belongs to.
#
# Why a snapshot before anything else: an MBN activation or an EFS write
# replaces these items wholesale, and the modem offers no "previous value".
# This file is the only way back. It is also the measurement basis for the
# item layouts: two snapshots under two known MBNs differ exactly where the
# carrier settings live.
#
# Quectel only (AT+QNVFR). An item that does not exist answers ERROR and is
# listed as such in MANIFEST, which is itself a result: it says this firmware
# does not carry the item.

modem=$1
out=$2
list=${3:-$(dirname "$0")/efs-paths.txt}

[ -n "$modem" ] && [ -n "$out" ] && [ -r "$list" ] || {
	echo "usage: $0 MODEM OUTDIR [PATHLIST]" >&2
	exit 1
}

mkdir -p "$out" || exit 1

# at CMD -> the response lines, one per line; exit 1 on an AT error
at() {
	local cmd json
	cmd=$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')
	json=$(ubus -t 20 call wwand modem_at \
		"{\"modem\":\"$modem\",\"command\":\"$cmd\",\"timeout\":10000}") || return 1
	[ "$(echo "$json" | jsonfilter -e '@.ok')" = "true" ] || return 1
	echo "$json" | jsonfilter -e '@.response[*]'
}

{
	echo "modem: $modem"
	echo "taken: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	at 'ATI' | sed 's/^/ati: /'
	at 'AT+QMBNCFG="Select"' | sed 's/^/mbn: /'
	at 'AT+QMBNCFG="AutoSel"' | sed 's/^/mbn: /'
	at 'AT+QCFG="ims"' | sed 's/^/ims: /'
} > "$out/MANIFEST"

n=0 miss=0
grep -v '^#' "$list" | grep . | while read -r path; do
	file="$out$path.hex"
	mkdir -p "$(dirname "$file")"
	if hex=$(at "AT+QNVFR=\"$path\"" | sed -n 's/^+QNVFR: *//p') && [ -n "$hex" ]; then
		echo "$hex" > "$file"
		echo "item: $path $(( ${#hex} / 2 )) bytes" >> "$out/MANIFEST"
	else
		echo "item: $path ERROR" >> "$out/MANIFEST"
	fi
done

grep -c ' bytes$' "$out/MANIFEST" | sed 's/$/ items read/'
grep -c ' ERROR$' "$out/MANIFEST" | sed 's/$/ items absent/'
