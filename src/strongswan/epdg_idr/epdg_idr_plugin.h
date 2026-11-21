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
 * @defgroup epdg_idr epdg_idr
 * @ingroup cplugins
 *
 * @defgroup epdg_idr_plugin epdg_idr_plugin
 * @{ @ingroup epdg_idr
 */

#ifndef EPDG_IDR_PLUGIN_H_
#define EPDG_IDR_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct epdg_idr_plugin_t epdg_idr_plugin_t;

/**
 * Accept an ePDG's own IKEv2 responder identity (TS 24.302 7.2.2).
 *
 * A UE sends the APN as IDr in its first IKE_AUTH request, and an ePDG
 * answers with an identity of its own (its FQDN). charon requires the IDr it
 * sent, so for the connections listed in charon.plugins.epdg-idr.connections
 * whose remote side authenticates by EAP only (RFC 5998, the ePDG proven by
 * the mutual EAP method), the plugin relaxes the remote identity of the peer
 * config to %any when the ePDG's answer carries another IDr — for the
 * lifetime of that peer config: load the connection again (vici load-conn)
 * before a new attempt so the configured IDr is sent again.
 */
struct epdg_idr_plugin_t {

	/**
	 * Implements plugin interface.
	 */
	plugin_t plugin;
};

#endif /** EPDG_IDR_PLUGIN_H_ @}*/
