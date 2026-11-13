/* SPDX-License-Identifier: GPL-2.0-only */
/* SHA-256 and SHA-384, after FIPS 180-4. Only what the MBN hash table needs:
 * one-shot digests over a buffer. */
#ifndef MCFG_SHA2_H
#define MCFG_SHA2_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_LEN 32
#define SHA384_LEN 48

void sha256(const uint8_t *data, size_t len, uint8_t out[SHA256_LEN]);
void sha384(const uint8_t *data, size_t len, uint8_t out[SHA384_LEN]);

#endif
