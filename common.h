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

#endif
