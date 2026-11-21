# SPDX-License-Identifier: GPL-2.0-only
#
# wwand-ims build: the shipped ucode files, precompiled to bytecode by default
# and laid out under the names they are installed and loaded by. The output
# tree ${CMAKE_BINARY_DIR}/ucode mirrors the target:
#   ucode/wwand/      -> /usr/share/ucode/wwand   (plugin, wwandctl command)
#   ucode/wwand-ims/  -> /usr/share/wwand-ims     (sipd and the UE, loaded with
#                                                  `ucode -L /usr/share/wwand-ims`)
# The feed Makefile copies these two trees and nothing else, so this file is
# the one place that says what ships and under which name.
#
# The approach is wwand's (its repo-root CMakeLists.txt): one compiler call per
# file; every module name of this tree, the stock extensions and the one wwand
# core module sipd imports are passed as `dynlink=`, so a file compiles on its
# own and its imports resolve at runtime through the search path. An import of
# any other name is still a compile error. `-s` strips the debug info, without
# which the bytecode embeds the absolute build path.
#
# Only ES modules (top-level `export`) and programs can be bytecode. The
# require()d scripts (top-level `return`: the wwand plugin, the wwandctl
# command, sipd_core, sipd_sip, ims_mcfg) ship as source in either mode,
# because require() reads source at runtime.
#
# The compiling ucode must be the revision of the target's runtime: bytecode is
# VM-locked (UCODE_BYTECODE_VERSION, ucode's include/ucode/vm.h). The feed
# build passes the SDK host ucode as UCODE_COMPILER.

cmake_minimum_required(VERSION 3.13)

project(wwand-ims NONE)

option(UCODE_PRECOMPILE "Precompile the ucode modules and programs to bytecode" ON)
find_program(UCODE_COMPILER ucode DOC "ucode interpreter used as bytecode compiler")

set(SRC ${CMAKE_CURRENT_SOURCE_DIR})
set(OUT ${CMAKE_BINARY_DIR}/ucode)

# --- what ships, as <source>=<installed path under ucode/> --------------------
# Deliberately explicit: the check below fails the configure when a .uc file in
# a shipped directory is in none of these lists (nor in IMS_UCODE_UNSHIPPED).

# ES modules -> -cmodule. Their installed basename is their module name.
set(IMS_UCODE_MODULES
  ue/aka.uc=wwand-ims/ue_aka.uc
  ue/call.uc=wwand-ims/ue_call.uc
  ue/reg.uc=wwand-ims/ue_reg.uc
  ue/regevent.uc=wwand-ims/ue_regevent.uc
  ue/smsip.uc=wwand-ims/ue_smsip.uc
  ue/secagree.uc=wwand-ims/ue_secagree.uc
  sipd/line_ue.uc=wwand-ims/sipd_line_ue.uc
  sipd/profile.uc=wwand-ims/sipd_profile.uc
  sipd/relay.uc=wwand-ims/sipd_relay.uc
)

# programs (shebang) -> -c, the interpreter line is kept
set(IMS_UCODE_PROGRAMS
  sipd/sipd.uc=wwand-ims/sipd.uc
  tools/ims-register.uc=wwand-ims/ims-register.uc
)

# require()d scripts -> copied as source
set(IMS_UCODE_PLAIN
  plugins/ims.uc=wwand/plugins/ims.uc
  ctl/ims.uc=wwand/ctl/ims.uc
  ctl/mcfg.uc=wwand/ims_mcfg.uc
  sipd/core.uc=wwand-ims/sipd_core.uc
  sipd/sip.uc=wwand-ims/sipd_sip.uc
)

# in a shipped directory but not installed: development tools
set(IMS_UCODE_UNSHIPPED
  tools/eg25-voice.uc
  tools/sipcall.uc
)

# imported names outside this tree, resolved on the device
set(IMS_UCODE_EXTERN digest fs socket struct ubus uci uloop wwand_io wwand.log wwand.sms_pdu)

# --- capability probe ---------------------------------------------------------
# An older ucode (2026.01.16, the openwrt-25.12 images up to 25.12.6, has no
# `-cmodule` and cannot load a bytecode module either; the 25.12 branch has
# 2026.07.09 since 2026-11-11) or a missing host ucode does not fail the
# build: everything
# then ships as source, which runs the same, only without the start-up win.
set(IMS_BYTECODE OFF)
if(UCODE_PRECOMPILE AND UCODE_COMPILER)
  set(_probe_src ${CMAKE_BINARY_DIR}/uc_probe.uc)
  set(_probe_out ${CMAKE_BINARY_DIR}/uc_probe.out)
  file(WRITE ${_probe_src}
    "'use strict';\n"
    "import * as fs from 'fs';\n"
    "export function p(x) { let a = x?.b ?? 0; a ??= 1; return a + length(fs); };\n")
  execute_process(
    COMMAND ${UCODE_COMPILER} -s -cmodule,dynlink=fs -o ${_probe_out} ${_probe_src}
    RESULT_VARIABLE _probe_rc OUTPUT_QUIET ERROR_VARIABLE _probe_err)
  if(_probe_rc EQUAL 0 AND EXISTS ${_probe_out})
    set(IMS_BYTECODE ON)
    message(STATUS "wwand-ims: ucode bytecode precompile enabled (${UCODE_COMPILER})")
  else()
    message(WARNING "wwand-ims: '${UCODE_COMPILER}' cannot precompile ucode bytecode "
      "(rc=${_probe_rc}: ${_probe_err}) — shipping ucode SOURCE instead")
  endif()
elseif(UCODE_PRECOMPILE)
  message(WARNING "wwand-ims: no ucode compiler found — shipping ucode SOURCE instead")
endif()
# which mode this build took, for tests/run.sh BYTECODE=1 and for a reader
if(IMS_BYTECODE)
  file(WRITE ${CMAKE_BINARY_DIR}/ucode-mode "bytecode\n")
else()
  file(WRITE ${CMAKE_BINARY_DIR}/ucode-mode "source\n")
endif()

# --- list checks (configure time) ---------------------------------------------

set(_listed ${IMS_UCODE_UNSHIPPED})
foreach(e IN LISTS IMS_UCODE_MODULES IMS_UCODE_PROGRAMS IMS_UCODE_PLAIN)
  string(REGEX REPLACE "=.*$" "" _f ${e})
  list(APPEND _listed ${_f})
endforeach()

# the only glob here, and only to check the lists against the tree
file(GLOB _on_disk RELATIVE ${SRC}
  ${SRC}/plugins/*.uc ${SRC}/ctl/*.uc ${SRC}/sipd/*.uc ${SRC}/ue/*.uc ${SRC}/tools/*.uc)
foreach(f IN LISTS _on_disk)
  if(NOT f IN_LIST _listed)
    message(FATAL_ERROR "${f} is not listed in CMakeLists.txt (add it to "
      "IMS_UCODE_MODULES/_PROGRAMS/_PLAIN, or _UNSHIPPED)")
  endif()
endforeach()
foreach(f IN LISTS _listed)
  if(NOT f IN_LIST _on_disk)
    message(FATAL_ERROR "CMakeLists.txt lists ${f}, which does not exist")
  endif()
  file(READ ${SRC}/${f} _body)
  if(_body MATCHES "from[ \t]+'[.][.]?/")
    message(FATAL_ERROR "${f} uses a relative import — bytecode modules "
      "resolve only through the search path")
  endif()
endforeach()
unset(_body)

# --- compile flags ------------------------------------------------------------

set(_dyn "")
foreach(e IN LISTS IMS_UCODE_EXTERN)
  list(APPEND _dyn "dynlink=${e}")
endforeach()
foreach(e IN LISTS IMS_UCODE_MODULES)
  string(REGEX REPLACE "^.*=" "" _dst ${e})
  get_filename_component(_name ${_dst} NAME_WE)
  if(_name MATCHES "-")
    message(FATAL_ERROR "${_dst}: '-' in a module name cannot be resolved by the "
      "dotted module loader — use '_'")
  endif()
  list(APPEND _dyn "dynlink=${_name}")
endforeach()
list(JOIN _dyn "," _dynflags)

# --- per-file rules -----------------------------------------------------------

set(_outputs "")
foreach(kind MODULES PROGRAMS PLAIN)
  foreach(e IN LISTS IMS_UCODE_${kind})
    string(REGEX REPLACE "=.*$" "" _src ${e})
    string(REGEX REPLACE "^.*=" "" _dst ${e})
    get_filename_component(_dir ${OUT}/${_dst} DIRECTORY)
    if(IMS_BYTECODE AND kind STREQUAL "MODULES")
      set(_cmd ${UCODE_COMPILER} -s -cmodule,${_dynflags} -o ${OUT}/${_dst} ${SRC}/${_src})
      set(_what "UC")
    elseif(IMS_BYTECODE AND kind STREQUAL "PROGRAMS")
      set(_cmd ${UCODE_COMPILER} -s -c${_dynflags} -o ${OUT}/${_dst} ${SRC}/${_src})
      set(_what "UC")
    else()
      set(_cmd ${CMAKE_COMMAND} -E copy ${SRC}/${_src} ${OUT}/${_dst})
      set(_what "CP")
    endif()
    add_custom_command(OUTPUT ${OUT}/${_dst}
      COMMAND ${CMAKE_COMMAND} -E make_directory ${_dir}
      COMMAND ${_cmd}
      DEPENDS ${SRC}/${_src}
      COMMENT "${_what} ${_src} -> ${_dst}"
      VERBATIM)
    list(APPEND _outputs ${OUT}/${_dst})
  endforeach()
endforeach()

add_custom_target(ims_ucode ALL DEPENDS ${_outputs})
