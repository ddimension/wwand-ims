# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 André Valentin <avalentin@marcant.net>
cmake_minimum_required(VERSION 3.13)

project(ucode-mod-wwand-ims-xfrm C)

set(CMAKE_C_STANDARD 11)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wno-unused-parameter)

find_path(UCODE_INCLUDE_DIR ucode/module.h)
find_library(UCODE_LIBRARY NAMES ucode)

if(NOT UCODE_INCLUDE_DIR OR NOT UCODE_LIBRARY)
  message(FATAL_ERROR "libucode headers/library not found (install ucode dev files)")
endif()

add_library(wwand_ims_xfrm MODULE wwand-ims-xfrm.c)

set_target_properties(wwand_ims_xfrm PROPERTIES OUTPUT_NAME wwand_ims_xfrm PREFIX "")
target_include_directories(wwand_ims_xfrm PRIVATE ${UCODE_INCLUDE_DIR})
target_link_options(wwand_ims_xfrm PRIVATE -Wl,--no-undefined)
target_link_libraries(wwand_ims_xfrm ${UCODE_LIBRARY})

install(TARGETS wwand_ims_xfrm LIBRARY DESTINATION lib/ucode)
