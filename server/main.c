/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include "log.h"
#include "dispatcher.h"

#include "../common.h"

char cwd[256] = {0};

int main(int argc, char *argv[])
{
	int sockfd, connfd;
	struct sockaddr_in servaddr;
	struct timeval timeout = {3, 0};

	if (getcwd(cwd, sizeof(cwd)) == NULL)
		return -1;

	if (daemon(true, false) == -1)
		exit(-1);

	slog("Starting CryptoServer\n");

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		slog("create socket error: %s(errno: %d)\n", strerror(errno),errno);
		return -1;
	}

	setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(SERV_PORT);

	if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
		slog("bind socket error: %s(errno: %d)\n", strerror(errno),errno);
		return -1;
	}

	if (listen(sockfd, 10) < 0) {
		slog("listen socket error: %s(errno: %d)\n", strerror(errno),errno);
		return -1;
	}

	while (1) {
		if ((connfd = accept(sockfd, NULL, NULL)) < 0) {
			slog("accept socket error: %s(errno: %d)\n", strerror(errno),errno);
			continue;
		}

		dispatch(connfd);
	}
}
