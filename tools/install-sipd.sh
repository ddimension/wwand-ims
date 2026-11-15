#!/bin/sh
# install-sipd.sh DESTDIR [XFRM_SO]
#
# Lay out sipd and the IMS UE the way the init script loads them, until there
# is a package: the ucode files under their module names in
# DESTDIR/usr/share/wwand-ims, the xfrm module next to them, the init script,
# `wwandctl ims` and wwand-ims-setup.
# A dev deploy to a router:
#
#   sh tools/install-sipd.sh /tmp/stage /vol/release/wwand-ims/build-target/xfrm/wwand_ims_xfrm.so
#   tar -C /tmp/stage -c . | ssh root@ROUTER 'tar -C / -x && chmod +x /etc/init.d/wwand-ims-sipd'
#
# /etc/config/wwand_ims is not touched (files/wwand_ims.config is the example).

set -e
dest=$1
so=$2
[ -n "$dest" ] || { echo "usage: $0 DESTDIR [XFRM_SO]" >&2; exit 1; }
top=$(cd "$(dirname "$0")/.." && pwd)
lib="$dest/usr/share/wwand-ims"

mkdir -p "$lib" "$dest/etc/init.d"
cp "$top/sipd/sipd.uc"     "$lib/sipd.uc"
cp "$top/sipd/core.uc"     "$lib/sipd_core.uc"
cp "$top/sipd/sip.uc"      "$lib/sipd_sip.uc"
cp "$top/sipd/line_ue.uc"  "$lib/sipd_line_ue.uc"
cp "$top/sipd/relay.uc"    "$lib/sipd_relay.uc"
cp "$top/ue/aka.uc"        "$lib/ue_aka.uc"
cp "$top/ue/secagree.uc"   "$lib/ue_secagree.uc"
cp "$top/ue/reg.uc"        "$lib/ue_reg.uc"
cp "$top/ue/call.uc"       "$lib/ue_call.uc"
[ -n "$so" ] && cp "$so" "$lib/wwand_ims_xfrm.so"
cp "$top/files/wwand-ims-sipd.init" "$dest/etc/init.d/wwand-ims-sipd"
chmod +x "$dest/etc/init.d/wwand-ims-sipd"
# `wwandctl ims` (a wwandctl command of this package) and its setup entry
mkdir -p "$dest/usr/share/ucode/wwand/ctl" "$dest/usr/sbin"
cp "$top/ctl/ims.uc" "$dest/usr/share/ucode/wwand/ctl/ims.uc"
cp "$top/ctl/mcfg.uc" "$dest/usr/share/ucode/wwand/ims_mcfg.uc"
cp "$top/files/wwand-ims-setup" "$dest/usr/sbin/wwand-ims-setup"
chmod +x "$dest/usr/sbin/wwand-ims-setup"
echo "installed into $dest"
