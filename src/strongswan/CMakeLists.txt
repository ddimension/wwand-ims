# SPDX-License-Identifier: GPL-2.0-or-later
# The strongSwan (charon) plugins wwand-ims-vowifi needs, built out of
# strongSwan's tree as loadable modules (load_modular):
#
#   libstrongswan-ext-aka.so   EAP-AKA card backed by an external program
#                              (the USIM in the modem, vowifi/ext_aka.uc)
#   libstrongswan-epdg-idr.so  accepts the IKEv2 responder identity an ePDG
#                              answers with, for listed EAP-only connections
#
# They are built against the headers and config.h of the strongSwan they
# run in — the feed's strongswan installs them (Build/InstallDev) under
# STRONGSWAN_INCLUDE_DIR, with libsimaka under STRONGSWAN_LIB_DIR. A plugin
# is tied to that strongSwan's ABI: the package pins its version.
#
#   cmake -DSTRONGSWAN_INCLUDE_DIR=<staging>/usr/include/strongswan \
#         -DSTRONGSWAN_LIB_DIR=<staging>/usr/lib/ipsec src/strongswan
#
# STRONGSWAN_INCLUDE_DIR is either an installed tree (config.h at its top,
# libstrongswan/ libcharon/ libsimaka/ below) or a configured strongSwan
# source tree (config.h at its top, the libraries under src/).

cmake_minimum_required(VERSION 3.13)
project(wwand-ims-strongswan C)

set(STRONGSWAN_INCLUDE_DIR "" CACHE PATH "strongSwan headers: config.h with libstrongswan/ libcharon/ libsimaka/")
set(STRONGSWAN_LIB_DIR "" CACHE PATH "where libsimaka.so is (link time)")
set(STRONGSWAN_PLUGIN_DIR "/usr/lib/ipsec/plugins" CACHE PATH "install directory of the plugins")
set(STRONGSWAN_RPATH "/usr/lib/ipsec" CACHE STRING "run-time path of libsimaka")

if(NOT EXISTS "${STRONGSWAN_INCLUDE_DIR}/config.h")
	message(FATAL_ERROR "STRONGSWAN_INCLUDE_DIR (${STRONGSWAN_INCLUDE_DIR}) has no config.h")
endif()

# an installed header tree, or a configured source tree
if(EXISTS "${STRONGSWAN_INCLUDE_DIR}/libcharon/daemon.h")
	set(SW_LIBS "${STRONGSWAN_INCLUDE_DIR}")
elseif(EXISTS "${STRONGSWAN_INCLUDE_DIR}/src/libcharon/daemon.h")
	set(SW_LIBS "${STRONGSWAN_INCLUDE_DIR}/src")
else()
	message(FATAL_ERROR "no libcharon headers under ${STRONGSWAN_INCLUDE_DIR}")
endif()

set(SW_INCLUDES "${SW_LIBS}/libstrongswan" "${SW_LIBS}/libcharon" "${SW_LIBS}/libsimaka")
# -Wno-format: strongSwan's own printf hooks (%Y, %B, ...)
set(SW_FLAGS -include "${STRONGSWAN_INCLUDE_DIR}/config.h" -Wall -Wno-pointer-sign -Wno-format)

# NO_CMAKE_FIND_ROOT_PATH: exactly where told — OpenWrt's cmake.mk confines
# library lookups to its find root, which would re-root a path given here
find_library(SIMAKA_LIB NAMES simaka PATHS "${STRONGSWAN_LIB_DIR}" "${STRONGSWAN_INCLUDE_DIR}/src/libsimaka/.libs"
	NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH)
if(NOT SIMAKA_LIB)
	message(FATAL_ERROR "libsimaka not found (STRONGSWAN_LIB_DIR=${STRONGSWAN_LIB_DIR})")
endif()

function(sw_plugin name dir)
	string(REPLACE "_" "-" dash "${name}")
	add_library(${name} MODULE ${ARGN})
	set_target_properties(${name} PROPERTIES
		PREFIX "libstrongswan-" OUTPUT_NAME "${dash}"
		C_VISIBILITY_PRESET default
		INSTALL_RPATH "${STRONGSWAN_RPATH}" BUILD_WITH_INSTALL_RPATH ON)
	target_include_directories(${name} PRIVATE ${SW_INCLUDES} "${CMAKE_CURRENT_SOURCE_DIR}/${dir}")
	target_compile_options(${name} PRIVATE ${SW_FLAGS})
	install(TARGETS ${name} LIBRARY DESTINATION "${STRONGSWAN_PLUGIN_DIR}")
endfunction()

sw_plugin(ext_aka ext_aka ext_aka/ext_aka_plugin.c ext_aka/ext_aka_card.c)
target_link_libraries(ext_aka PRIVATE "${SIMAKA_LIB}")

sw_plugin(epdg_idr epdg_idr epdg_idr/epdg_idr_plugin.c)
