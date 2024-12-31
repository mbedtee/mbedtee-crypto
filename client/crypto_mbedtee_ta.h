/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 */

#ifndef _CRYPTO_MBEDTEE_TA_H
#define _CRYPTO_MBEDTEE_TA_H

#include "../common.h"

int crypto_mbedtee_ta(int sockfd, char *platform_name, char *object_in, char *object_out,
	char *config_in, char *certificate_out);

#endif
