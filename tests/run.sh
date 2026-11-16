#!/bin/sh
# Host tests. They import the wwand codec through tests/wwand, a symlink to
# the wwand source tree next to this repo (the workspace layout); point
# WWAND_SRC elsewhere if it is not there.
TESTDIR=$(cd "$(dirname "$0")" && pwd)
WWAND_SRC=${WWAND_SRC:-$TESTDIR/../../wwand/src-ucode}

[ -d "$WWAND_SRC" ] || { echo "wwand source tree not found: $WWAND_SRC" >&2; exit 1; }
ln -sfn "$WWAND_SRC" "$TESTDIR/wwand"
ln -sfn ../plugins/ims.uc "$TESTDIR/ims_plugin.uc"
ln -sfn ../sipd/sip.uc "$TESTDIR/sipd_sip.uc"
ln -sfn ../sipd/core.uc "$TESTDIR/sipd_core.uc"
ln -sfn ../ue/aka.uc "$TESTDIR/ue_aka.uc"
ln -sfn ../ue/secagree.uc "$TESTDIR/ue_secagree.uc"
ln -sfn ../ue/reg.uc "$TESTDIR/ue_reg.uc"
ln -sfn ../ue/call.uc "$TESTDIR/ue_call.uc"
ln -sfn ../sipd/line_ue.uc "$TESTDIR/sipd_line_ue.uc"
ln -sfn ../sipd/relay.uc "$TESTDIR/sipd_relay.uc"
ln -sfn ../sipd/profile.uc "$TESTDIR/sipd_profile.uc"
ln -sfn ../ue/regevent.uc "$TESTDIR/ue_regevent.uc"
ln -sfn ../ctl/ims.uc "$TESTDIR/ctl_ims.uc"
ln -sfn ../ctl/mcfg.uc "$TESTDIR/ims_mcfg.uc"

# wwand's native module wwand_io.so now carries the NETLINK_XFRM binding
# (sub-namespace xfrm, merged from the old src/xfrm). Built out of tree from
# $WWAND_SRC/../io. The nstests load it; the unit tests pass a fake xfrm.
IO_SRC="$WWAND_SRC/../io"
IO_BUILD=${IO_BUILD:-$TESTDIR/.build/io}

if [ -x "$HOME/.local/bin/ucode" ]; then
	UCODE="$HOME/.local/bin/ucode"
	export LD_LIBRARY_PATH="$HOME/.local/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
	MODPATH="$HOME/.local/lib/ucode/*.so"
else
	UCODE=ucode
	MODPATH="/usr/lib/ucode/*.so"
fi

if command -v cmake >/dev/null 2>&1 && [ -d "$IO_SRC" ]; then
	mkdir -p "$IO_BUILD"
	( cd "$IO_BUILD" && cmake -DCMAKE_PREFIX_PATH="$HOME/.local" "$IO_SRC" >/dev/null &&
	  make >/dev/null ) || { echo "wwand_io module build failed" >&2; exit 1; }
fi

# BYTECODE=1: run the suite against what the package ships, the UE and sipd
# modules compiled by CMakeLists.txt with this same ucode (bytecode is
# VM-locked), instead of the sources. The require()d scripts are source in the
# package too. The links above point back at the sources on the next plain run.
if [ "${BYTECODE:-0}" = 1 ]; then
	UC_BUILD="$TESTDIR/.build/ucode"
	mkdir -p "$UC_BUILD"
	( cd "$UC_BUILD" && cmake -DUCODE_COMPILER="$UCODE" "$TESTDIR/.." >/dev/null &&
	  make >/dev/null ) || { echo "bytecode build failed" >&2; exit 1; }
	grep -qx bytecode "$UC_BUILD/ucode-mode" ||
		{ echo "$UCODE cannot emit bytecode" >&2; exit 1; }
	n=0
	for f in "$UC_BUILD"/ucode/wwand-ims/*.uc; do
		# only the names the suite loads (linked above); the programs are not
		[ -L "$TESTDIR/$(basename "$f")" ] || continue
		ln -sfn "$f" "$TESTDIR/$(basename "$f")"
		n=$((n + 1))
	done
	echo "bytecode: $n modules from $UC_BUILD/ucode/wwand-ims"
fi

rc=0
for t in "$TESTDIR"/test_*.uc; do
	out=$(cd "$TESTDIR" && "$UCODE" -L "$MODPATH" -L "$TESTDIR/*.uc" -L "$TESTDIR/wwand/*.uc" -L "$TESTDIR/*" "$t" 2>&1)
	echo "$(basename "$t" .uc): $(echo "$out" | tail -1 | sed 's/^(null): //')"
	echo "$out" | grep -q ' 0 failures$' || { echo "$out"; rc=1; }
done
# kernel tests: a user + network namespace of their own, so they need neither
# root nor touch the host's SAs. Skipped (and said so) where that is not
# possible: no module built, no unprivileged user namespaces, no xfrm_user.
for t in "$TESTDIR"/nstest_*.uc; do
	name=$(basename "$t" .uc)
	if [ ! -f "$IO_BUILD/wwand_io.so" ]; then
		echo "$name: SKIPPED (no wwand_io.so in $IO_BUILD)"
		continue
	fi
	if ! unshare -rn sh -c 'ip xfrm state >/dev/null 2>&1'; then
		echo "$name: SKIPPED (no user+net namespace with xfrm here)"
		continue
	fi
	out=$(cd "$TESTDIR" && unshare -rn sh -c 'ip link set lo up; ip addr add 192.0.2.1/32 dev lo; ip addr add 192.0.2.2/32 dev lo; ip addr add 2001:db8::1/128 dev lo nodad; ip addr add 2001:db8::2/128 dev lo nodad; exec "$@"' sh \
		"$UCODE" -L "$IO_BUILD/*.so" -L "$MODPATH" -L "$TESTDIR/*.uc" -L "$TESTDIR/wwand/*.uc" -L "$TESTDIR/*" "$t" 2>&1)
	echo "$name: $(echo "$out" | tail -1 | sed 's/^(null): //')"
	echo "$out" | grep -q ' 0 failures$' || { echo "$out"; rc=1; }
done
exit $rc
