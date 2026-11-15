# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 André Valentin <avalentin@marcant.net>
#
# wwand-ims builds one native ucode module, the xfrm NETLINK_XFRM binding
# (src/xfrm -> wwand_ims_xfrm.so). The ucode tree (plugins/, ue/, sipd/,
# ctl/) ships as source: the wwand daemon loads the plugin and the sipd init
# loads the UE modules with `ucode -L`, so there is no bytecode step here.
#
# A future mcfg C tool (src/mcfg, mcfg_tools) is GPL-3.0 and ships as a
# SEPARATE package; it is deliberately NOT added here (see docs/design.md §7).
cmake_minimum_required(VERSION 3.13)
project(wwand-ims C)
add_subdirectory(src/xfrm)
