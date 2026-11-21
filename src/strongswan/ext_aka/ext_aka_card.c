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

#include "ext_aka_card.h"

#include <daemon.h>
#include <utils/process.h>
#include <threading/mutex.h>

#include <errno.h>
#include <unistd.h>

#define EXT_AKA_DEFAULT_PROGRAM "/usr/libexec/strongswan/ext-aka"

typedef struct private_ext_aka_card_t private_ext_aka_card_t;

/**
 * Private data of an ext_aka_card_t object.
 */
struct private_ext_aka_card_t {

	/**
	 * Public interface.
	 */
	ext_aka_card_t public;

	/**
	 * The program that runs the AKA algorithm on the card
	 */
	char *program;

	/**
	 * RAND of the last synchronisation failure, and the AUTS the card gave
	 */
	char sync_rand[AKA_RAND_LEN];
	char sync_auts[AKA_AUTS_LEN];
	bool have_auts;

	/**
	 * Protects the AUTS cache
	 */
	mutex_t *mutex;
};

/**
 * Read up to len-1 bytes of the child's stdout into buf (NUL terminated)
 */
static void read_all(int fd, char *buf, size_t len)
{
	size_t got = 0;
	ssize_t n;

	while (got + 1 < len)
	{
		n = read(fd, buf + got, len - 1 - got);
		if (n < 0 && errno == EINTR)
		{
			continue;
		}
		if (n <= 0)
		{
			break;
		}
		got += n;
	}
	buf[got] = '\0';
}

/**
 * The hex value after "<key> " on a line of out, into dst of exactly len bytes
 * (or up to len bytes when var_len is given). TRUE if found and well formed.
 */
static bool get_hex(char *out, char *key, char *dst, size_t len, int *var_len)
{
	char *line = out, *end, *p;
	size_t klen = strlen(key);
	chunk_t bin;

	while (line && *line)
	{
		end = strchr(line, '\n');
		if (strncmp(line, key, klen) == 0 && line[klen] == ' ')
		{
			p = line + klen + 1;
			bin = chunk_from_hex(chunk_create(p, end ? end - p : strlen(p)), NULL);
			if ((var_len && bin.len >= 4 && bin.len <= len) ||
				(!var_len && bin.len == len))
			{
				memcpy(dst, bin.ptr, bin.len);
				if (var_len)
				{
					*var_len = bin.len;
				}
				chunk_clear(&bin);
				return TRUE;
			}
			chunk_clear(&bin);
			return FALSE;
		}
		line = end ? end + 1 : NULL;
	}
	return FALSE;
}

/**
 * Run the program: `<program> aka <identity> <RAND hex> <AUTN hex>`. It
 * prints "RES <hex>", "CK <hex>", "IK <hex>" (each on a line), or "AUTS
 * <hex>" when the card reports a synchronisation failure, and exits 0; any
 * other exit is a failure.
 */
static bool run(private_ext_aka_card_t *this, identification_t *id,
				char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN],
				char *out, size_t outlen)
{
	char idbuf[256], randhex[2 * AKA_RAND_LEN + 1], autnhex[2 * AKA_AUTN_LEN + 1];
	char *argv[] = { this->program, "aka", idbuf, randhex, autnhex, NULL };
	char *envp[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
	process_t *process;
	int fd = -1, code;

	snprintf(idbuf, sizeof(idbuf), "%Y", id);
	chunk_to_hex(chunk_create(rand, AKA_RAND_LEN), randhex, FALSE);
	chunk_to_hex(chunk_create(autn, AKA_AUTN_LEN), autnhex, FALSE);

	process = process_start(argv, envp, NULL, &fd, NULL, TRUE);
	if (!process)
	{
		DBG1(DBG_IKE, "ext-aka: starting %s failed", this->program);
		return FALSE;
	}
	read_all(fd, out, outlen);
	close(fd);
	if (!process->wait(process, &code) || code != 0)
	{
		DBG1(DBG_IKE, "ext-aka: %s did not succeed", this->program);
		return FALSE;
	}
	return TRUE;
}

METHOD(simaka_card_t, get_quintuplet, status_t,
	private_ext_aka_card_t *this, identification_t *id,
	char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN], char ck[AKA_CK_LEN],
	char ik[AKA_IK_LEN], char res[AKA_RES_MAX], int *res_len)
{
	char out[512], auts[AKA_AUTS_LEN];

	if (!run(this, id, rand, autn, out, sizeof(out)))
	{
		return FAILED;
	}
	if (get_hex(out, "AUTS", auts, AKA_AUTS_LEN, NULL))
	{
		DBG1(DBG_IKE, "ext-aka: the card reports a sequence number out of sync");
		this->mutex->lock(this->mutex);
		memcpy(this->sync_rand, rand, AKA_RAND_LEN);
		memcpy(this->sync_auts, auts, AKA_AUTS_LEN);
		this->have_auts = TRUE;
		this->mutex->unlock(this->mutex);
		return INVALID_STATE;
	}
	if (!get_hex(out, "RES", res, AKA_RES_MAX, res_len) ||
		!get_hex(out, "CK", ck, AKA_CK_LEN, NULL) ||
		!get_hex(out, "IK", ik, AKA_IK_LEN, NULL))
	{
		DBG1(DBG_IKE, "ext-aka: %s gave no RES/CK/IK", this->program);
		return FAILED;
	}
	return SUCCESS;
}

/**
 * The AUTS the card gave for this RAND in get_quintuplet()
 */
METHOD(simaka_card_t, resync, bool,
	private_ext_aka_card_t *this, identification_t *id,
	char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN])
{
	bool found = FALSE;

	this->mutex->lock(this->mutex);
	if (this->have_auts && memeq(this->sync_rand, rand, AKA_RAND_LEN))
	{
		memcpy(auts, this->sync_auts, AKA_AUTS_LEN);
		this->have_auts = FALSE;
		found = TRUE;
	}
	this->mutex->unlock(this->mutex);
	if (!found)
	{
		DBG1(DBG_IKE, "ext-aka: no AUTS for this RAND");
	}
	return found;
}

METHOD(ext_aka_card_t, destroy, void,
	private_ext_aka_card_t *this)
{
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * See header
 */
ext_aka_card_t *ext_aka_card_create()
{
	private_ext_aka_card_t *this;

	INIT(this,
		.public = {
			.card = {
				.get_triplet = (void*)return_false,
				.get_quintuplet = _get_quintuplet,
				.resync = _resync,
				.get_pseudonym = (void*)return_null,
				.set_pseudonym = (void*)nop,
				.get_reauth = (void*)return_null,
				.set_reauth = (void*)nop,
			},
			.destroy = _destroy,
		},
		.program = lib->settings->get_str(lib->settings,
								"%s.plugins.ext-aka.program",
								EXT_AKA_DEFAULT_PROGRAM, lib->ns),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	return &this->public;
}
