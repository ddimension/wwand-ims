/*
 * Copyright (C) 2026 André Valentin
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup ext_aka ext_aka
 * @ingroup cplugins
 *
 * @defgroup ext_aka_plugin ext_aka_plugin
 * @{ @ingroup ext_aka
 */

#ifndef EXT_AKA_PLUGIN_H_
#define EXT_AKA_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct ext_aka_plugin_t ext_aka_plugin_t;

/**
 * Plugin providing an EAP-AKA card backed by an external program
 * (charon.plugins.ext-aka.program, default /usr/libexec/strongswan/ext-aka).
 */
struct ext_aka_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** EXT_AKA_PLUGIN_H_ @}*/
