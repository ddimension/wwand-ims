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
ln -sfn ../ctl/ims.uc "$TESTDIR/ctl_ims.uc"
ln -sfn ../ctl/mcfg.uc "$TESTDIR/ims_mcfg.uc"

# the native xfrm module (src/xfrm), built out of tree: under the build
# project /vol/release/wwand-ims when it exists, else in tests/.build
if [ -z "$XFRM_BUILD" ]; then
	if [ -d /vol/release/wwand-ims ]; then
		XFRM_BUILD=/vol/release/wwand-ims/build-host/xfrm
	else
		XFRM_BUILD=$TESTDIR/.build/xfrm
	fi
fi

if [ -x "$HOME/.local/bin/ucode" ]; then
	UCODE="$HOME/.local/bin/ucode"
	export LD_LIBRARY_PATH="$HOME/.local/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
	MODPATH="$HOME/.local/lib/ucode/*.so"
else
	UCODE=ucode
	MODPATH="/usr/lib/ucode/*.so"
fi

if command -v cmake >/dev/null 2>&1; then
	mkdir -p "$XFRM_BUILD"
	( cd "$XFRM_BUILD" && { [ -f Makefile ] || cmake -DCMAKE_PREFIX_PATH="$HOME/.local" "$TESTDIR/../src/xfrm" >/dev/null; } &&
	  make >/dev/null ) || { echo "xfrm module build failed" >&2; exit 1; }
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
	if [ ! -f "$XFRM_BUILD/wwand_ims_xfrm.so" ]; then
		echo "$name: SKIPPED (no wwand_ims_xfrm.so in $XFRM_BUILD)"
		continue
	fi
	if ! unshare -rn sh -c 'ip xfrm state >/dev/null 2>&1'; then
		echo "$name: SKIPPED (no user+net namespace with xfrm here)"
		continue
	fi
	out=$(cd "$TESTDIR" && unshare -rn sh -c 'ip link set lo up; ip addr add 192.0.2.1/32 dev lo; ip addr add 192.0.2.2/32 dev lo; ip addr add 2001:db8::1/128 dev lo nodad; ip addr add 2001:db8::2/128 dev lo nodad; exec "$@"' sh \
		"$UCODE" -L "$XFRM_BUILD/*.so" -L "$MODPATH" -L "$TESTDIR/*.uc" -L "$TESTDIR/wwand/*.uc" -L "$TESTDIR/*" "$t" 2>&1)
	echo "$name: $(echo "$out" | tail -1 | sed 's/^(null): //')"
	echo "$out" | grep -q ' 0 failures$' || { echo "$out"; rc=1; }
done
exit $rc
