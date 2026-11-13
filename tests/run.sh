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

if [ -x "$HOME/.local/bin/ucode" ]; then
	UCODE="$HOME/.local/bin/ucode"
	export LD_LIBRARY_PATH="$HOME/.local/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
	MODPATH="$HOME/.local/lib/ucode/*.so"
else
	UCODE=ucode
	MODPATH="/usr/lib/ucode/*.so"
fi

rc=0
for t in "$TESTDIR"/test_*.uc; do
	out=$(cd "$TESTDIR" && "$UCODE" -L "$MODPATH" -L "$TESTDIR/*.uc" -L "$TESTDIR/wwand/*.uc" -L "$TESTDIR/*" "$t" 2>&1)
	echo "$(basename "$t" .uc): $(echo "$out" | tail -1 | sed 's/^(null): //')"
	echo "$out" | grep -q ' 0 failures$' || { echo "$out"; rc=1; }
done
exit $rc
