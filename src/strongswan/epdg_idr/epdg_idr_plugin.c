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

#include "epdg_idr_plugin.h"

#include <daemon.h>
#include <bus/listeners/listener.h>
#include <encoding/payloads/id_payload.h>
#include <collections/linked_list.h>

typedef struct private_epdg_idr_plugin_t private_epdg_idr_plugin_t;
typedef struct epdg_idr_listener_t epdg_idr_listener_t;

/**
 * The listener and its state. listener_t first: METHOD(listener_t, ...)
 * casts the listener pointer to this type.
 */
struct epdg_idr_listener_t {

	/**
	 * Listener on the bus
	 */
	listener_t listener;

	/**
	 * Connection names (charon.plugins.epdg-idr.connections)
	 */
	linked_list_t *names;
};

/**
 * Private data
 */
struct private_epdg_idr_plugin_t {

	/**
	 * Public interface
	 */
	epdg_idr_plugin_t public;

	/**
	 * The listener on the bus
	 */
	epdg_idr_listener_t *listener;
};

/**
 * Is this connection one of ours?
 */
static bool listed(epdg_idr_listener_t *this, peer_cfg_t *peer_cfg)
{
	enumerator_t *enumerator;
	char *name;
	bool found = FALSE;

	enumerator = this->names->create_enumerator(this->names);
	while (enumerator->enumerate(enumerator, &name))
	{
		if (streq(name, peer_cfg->get_name(peer_cfg)))
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

/**
 * The first remote auth round of a peer config, or NULL
 */
static auth_cfg_t *remote_round(peer_cfg_t *peer_cfg)
{
	enumerator_t *enumerator;
	auth_cfg_t *auth = NULL;

	enumerator = peer_cfg->create_auth_cfg_enumerator(peer_cfg, FALSE);
	if (!enumerator->enumerate(enumerator, &auth))
	{
		auth = NULL;
	}
	enumerator->destroy(enumerator);
	return auth;
}

/**
 * Replace the AUTH_RULE_IDENTITY of an auth config by id (owned by it then),
 * returning a clone of the one there before (or NULL)
 */
static identification_t *swap_identity(auth_cfg_t *auth, identification_t *id)
{
	enumerator_t *enumerator;
	identification_t *old = NULL, *value;
	auth_rule_t rule;

	enumerator = auth->create_enumerator(auth);
	while (enumerator->enumerate(enumerator, &rule, &value))
	{
		if (rule == AUTH_RULE_IDENTITY)
		{
			old = value->clone(value);
			auth->replace(auth, enumerator, AUTH_RULE_IDENTITY, id);
			id = NULL;
			break;
		}
	}
	enumerator->destroy(enumerator);
	DESTROY_IF(id);
	return old;
}

METHOD(listener_t, message, bool,
	epdg_idr_listener_t *this, ike_sa_t *ike_sa, message_t *message,
	bool incoming, bool plain)
{
	peer_cfg_t *peer_cfg;
	auth_cfg_t *auth;
	id_payload_t *payload;
	identification_t *idr, *configured, *old;

	/* the decrypted IKE_AUTH response to our own request */
	if (!incoming || !plain || message->get_request(message) ||
		message->get_exchange_type(message) != IKE_AUTH ||
		!ike_sa->has_condition(ike_sa, COND_ORIGINAL_INITIATOR))
	{
		return TRUE;
	}
	peer_cfg = ike_sa->get_peer_cfg(ike_sa);
	if (!peer_cfg || !listed(this, peer_cfg))
	{
		return TRUE;
	}
	payload = (id_payload_t*)message->get_payload(message, PLV2_ID_RESPONDER);
	auth = remote_round(peer_cfg);
	if (!payload || !auth)
	{
		return TRUE;
	}
	/* the ePDG proves itself by the mutual EAP method alone: with a
	 * certificate its identity is what the certificate confirms */
	if ((uintptr_t)auth->get(auth, AUTH_RULE_AUTH_CLASS) != AUTH_CLASS_EAP)
	{
		return TRUE;
	}
	configured = auth->get(auth, AUTH_RULE_IDENTITY);
	if (!configured || configured->contains_wildcards(configured))
	{
		return TRUE;
	}
	idr = payload->get_identification(payload);
	if (configured->matches(configured, idr) != ID_MATCH_NONE)
	{
		idr->destroy(idr);
		return TRUE;
	}

	/* for the lifetime of this peer config: putting the configured identity
	 * back once the IKE_SA is up crashed charon (6.0.7, mipsel, 2026-11-21:
	 * the auth config entry is not ours to swap again then); a peer config
	 * loaded anew (vici load-conn before each attempt, as wwand-ims does)
	 * sends the configured IDr again */
	old = swap_identity(auth, identification_create_from_string("%any"));
	if (old)
	{
		DBG1(DBG_CFG, "epdg-idr: accepting responder identity '%Y' instead "
			 "of '%Y' (EAP-only)", idr, old);
		old->destroy(old);
	}
	idr->destroy(idr);
	return TRUE;
}

METHOD(plugin_t, get_name, char*,
	private_epdg_idr_plugin_t *this)
{
	return "epdg-idr";
}

/**
 * The connection names from the settings: a list separated by commas or
 * spaces
 */
static void load_names(epdg_idr_listener_t *this)
{
	enumerator_t *enumerator;
	char *list, *name;

	list = lib->settings->get_str(lib->settings,
								  "%s.plugins.epdg-idr.connections", NULL, lib->ns);
	if (!list)
	{
		return;
	}
	enumerator = enumerator_create_token(list, ", ", " ");
	while (enumerator->enumerate(enumerator, &name))
	{
		this->names->insert_last(this->names, strdup(name));
	}
	enumerator->destroy(enumerator);
}

static bool plugin_cb(private_epdg_idr_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
		load_names(this->listener);
		charon->bus->add_listener(charon->bus, &this->listener->listener);
	}
	else
	{
		charon->bus->remove_listener(charon->bus, &this->listener->listener);
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_epdg_idr_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "epdg-idr"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_epdg_idr_plugin_t *this)
{
	epdg_idr_listener_t *l = this->listener;

	l->names->destroy_function(l->names, free);
	free(l);
	free(this);
}

/**
 * See header
 */
PLUGIN_DEFINE(epdg_idr)
{
	private_epdg_idr_plugin_t *this;
	epdg_idr_listener_t *l;

	INIT(l,
		.listener = {
			.message = _message,
		},
		.names = linked_list_create(),
	);
	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
		.listener = l,
	);

	return &this->public.plugin;
}
