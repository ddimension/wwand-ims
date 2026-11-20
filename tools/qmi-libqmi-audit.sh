#!/bin/sh
# qmi-libqmi-audit.sh [CORE_SRC] [LIBQMI_DATA] [IDL_JSON]
#
# Dumps the QMI schemas of the wwand core (CORE_SRC = its src-ucode, default
# ../wwand/src-ucode) and of plugins/ims.uc, then runs
# qmi-libqmi-audit.py against libqmi's data/ directory and, if given, a vendor
# IDL dump. Needs the host ucode (~/.local/bin/ucode).
set -e
top=$(cd "$(dirname "$0")/.." && pwd)
core=${1:-$top/../wwand/src-ucode}
libqmi=${2:-$(ls -d /vol/release/chateau/openwrt/build_dir/target-*/libqmi-1.38.0/data | head -1)}
idl=${3:-$top/research/op8t-20261113/idl-libqmiservices.json}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
ln -s "$(cd "$core" && pwd)" "$tmp/wwand"
export LD_LIBRARY_PATH="$HOME/.local/lib"
uc() { "$HOME/.local/bin/ucode" -L "$HOME/.local/lib/ucode/*.so" -L "$tmp" "$@"; }
mods=""
for f in "$core"/codec/schema/*.uc; do
	n=$(basename "$f" .uc)
	grep -q '^export default' "$f" && grep -q 'messages' "$f" || continue
	echo "import ${n}_s from 'wwand.codec.schema.$n';" >> "$tmp/dump.uc"
	mods="$mods $n: ${n}_s,"
done
dumper='let out = {};
for (let n, S in all) {
	let o = { service: S.service, messages: {} };
	for (let k, m in S.messages) {
		let e = { id: m.id };
		for (let part in [ "req", "resp", "ind" ])
			if (m[part]) { e[part] = {}; for (let f, d in m[part]) e[part][f] = d?.t; }
		o.messages[k] = e;
	}
	out[n] = o;
}
print(out, "\n");'
{ echo "let all = {$mods };"; echo "$dumper"; } >> "$tmp/dump.uc"
uc "$tmp/dump.uc" > "$tmp/core.json"
# the plugin keeps its schemas as plain consts from IMSA to the end of PDC
p="$top/plugins/ims.uc"
a=$(grep -n '^const IMSA = {' "$p" | cut -d: -f1)
b=$(awk -v a="$a" 'NR > a && /^const PDC = \{/ { f = 1 } f && /^};/ { print NR; exit }' "$p")
{ sed -n "${a},${b}p" "$p"
  echo 'let all = { "plugin.imsa": IMSA, "plugin.ims": IMS, "plugin.nas": NAS, "plugin.voice": VOICE, "plugin.pdc": PDC };'
  echo "$dumper"; } > "$tmp/plugin.uc"
uc "$tmp/plugin.uc" > "$tmp/plugin.json"
if [ -f "$idl" ]; then
	python3 "$top/tools/qmi-libqmi-audit.py" "$libqmi" "$tmp/core.json" "$tmp/plugin.json" --idl "$idl"
else
	python3 "$top/tools/qmi-libqmi-audit.py" "$libqmi" "$tmp/core.json" "$tmp/plugin.json"
fi
