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
 * @defgroup ext_aka_card ext_aka_card
 * @{ @ingroup ext_aka
 */

#ifndef EXT_AKA_CARD_H_
#define EXT_AKA_CARD_H_

#include <simaka_card.h>

typedef struct ext_aka_card_t ext_aka_card_t;

/**
 * SIM card implementation that runs the AKA algorithm in an external
 * program: a USIM in a modem, reached however the program reaches it.
 */
struct ext_aka_card_t {

	/**
	 * Implements simaka_card_t interface
	 */
	simaka_card_t card;

	/**
	 * Destroy an ext_aka_card_t.
	 */
	void (*destroy)(ext_aka_card_t *this);
};

/**
 * Create an ext_aka_card instance.
 */
ext_aka_card_t *ext_aka_card_create();

#endif /** EXT_AKA_CARD_H_ @}*/
