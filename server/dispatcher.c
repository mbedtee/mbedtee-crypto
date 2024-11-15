/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "log.h"
#include "dispatcher.h"

#include "crypto_mbedtee_ta.h"

static void __dispatch(int connfd, struct cheader *h)
{
	if (!strcmp(h->operation_type, CRYPTO_MBEDTEE_TA))
		crypto_mbedtee_ta(connfd);
}

void dispatch(int connfd)
{
	struct cheader h = {0};
	char cbuf[512] = {0};
	struct sockaddr_in peer;
	socklen_t addr_len = sizeof(peer);

	getpeername(connfd, (struct sockaddr *)&peer, &addr_len);

	slog("Client Connected %s:%d\n", inet_ntop(AF_INET,
		&peer.sin_addr, cbuf, sizeof(cbuf)), ntohs(peer.sin_port));

	memset(cbuf, 0, sizeof(cbuf));
	memset((char *)&h, 0, sizeof(h));

	if (recv(connfd, cbuf, sizeof(cbuf), 0) == sizeof(h)) {
		memcpy((char *)&h, cbuf, sizeof(h));
		if (SMAGIC == h.magic) {
			if (h.version < SVERSION) {
				slog("error cryptoclient version %d\n", h.version);
				memset((char *)&h, 0, sizeof(h));
				strncpy((char *)&h, "cryptoclient version too low, pls pull the "
							"latest cryptoclient\n", sizeof(h) - 1);
			}
			slog("cryptoclient version: %d\n", h.version);
			if (send(connfd, (char *)&h, sizeof(h), 0) != sizeof(h)) {
				slog("error send ack cheader\n");
				return;
			}

			__dispatch(connfd, &h);
		} else slog("h.magic %x error\n", h.magic);
	}

	slog("Client Disconnected\n\n");
}
