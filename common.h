/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 */

#ifndef _COMMON_H
#define _COMMON_H

#define SERV_PORT 1225

#define SMAGIC 0x05110106

#define SVERSION (1)

#define CRYPTO_MBEDTEE_TA "mbedtee-ta"

/*common header for dispatcher -- 256 bytes*/
struct cheader {
	unsigned int magic;
	char operation_type[32];
	unsigned int version;
	char reserved[216];
};

struct ack {
	int ret;
	char msg[252];
};

#define min(a, b) ((a) < (b) ? (a) : (b))

static inline size_t crypto_strlcpy(char *dst,
	const char *src, size_t n)
{
	char *d = dst;
	const char *s = src;

	if (n) {
		while (--n && (*d++ = *s++))
			;
		if (n == 0)
			*d = 0;
	}

	if (n == 0) {
		while (*s++)
			;
	}

	return s - src - 1;
}

#endif
