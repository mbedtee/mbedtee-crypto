// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <getopt.h>
#include <errno.h>
#include <pwd.h>
#include <netdb.h>
#include <sys/socket.h>

#include "crypto_mbedtee_ta.h"

struct sheader {
	unsigned int magic;
	unsigned int config_size;
	unsigned int object_size;
	char platform_name[32];
	char user_name[36];
	char host_name[32];
	char config_file_name[228];
	char certi_file_name[228];
	char object_in_file_name[228];
	char object_out_file_name[228];
};

#define SPACKET_SIZE (1024*256)

int crypto_mbedtee_ta(int sockfd, char *platform_name, char *object_in,
	char *object_out, char *config_in, char *certificate_out)
{
	int config_in_fd = -1, object_in_fd = -1, object_out_fd = -1,
	certificate_out_fd = -1, ret = -1;

	int config_size = 0, object_size = 0, certi_out_size = 0,
		object_out_size = 0;

	struct sheader h, hrecv;
	struct ack a;

	unsigned char *sockbuf = NULL;

	struct passwd *user = NULL;

	struct stat filestat;

	int rd_bytes = 0;
	int send_bytes = 0;

	int wr_bytes = 0;
	int recv_bytes = 0;

	int pos = 0;

	memset(&h, 0, sizeof(h));
	memset(&hrecv, 0, sizeof(hrecv));

	config_in_fd = open(config_in, O_RDONLY);
	if (config_in_fd < 0) {
		fprintf(stderr, "Error while trying to open %s\n", config_in);
		return ret;
	}

	if (fstat(config_in_fd, &filestat) < 0) {
		fprintf(stderr, "While trying to get the file status of %s\n", config_in);
		goto out;
	}

	config_size = filestat.st_size;

	object_in_fd = open(object_in, O_RDONLY);
	if (object_in_fd < 0) {
		fprintf(stderr, "Error while trying to open %s\n", object_in);
		goto out;
	}

	if (fstat(object_in_fd, &filestat) < 0) {
		fprintf(stderr, "While trying to get the file status of %s\n", object_in);
		goto out;
	}

	object_size = filestat.st_size;

	certificate_out_fd = open(certificate_out, O_RDWR | O_TRUNC | O_CREAT, 0755);
	if (certificate_out_fd < 0) {
		fprintf(stderr, "Error while trying to open %s\n", certificate_out);
		goto out;
	}
	object_out_fd = open(object_out, O_RDWR | O_TRUNC | O_CREAT, 0755);
	if (object_out_fd < 0) {
		fprintf(stderr, "Error while trying to open %s\n", object_out);
		goto out;
	}

	h.magic = SMAGIC;
	h.config_size = config_size;
	h.object_size = object_size;

	user = getpwuid(geteuid());

	strlcpy(h.user_name, user ? user->pw_name : "UnknownUser",
			sizeof(h.user_name));

	strlcpy(h.config_file_name, config_in +
		((strlen(config_in) > (sizeof(h.config_file_name) - 1)) ?
		(strlen(config_in) + 1 - sizeof(h.config_file_name)) : 0),
			sizeof(h.config_file_name));

	strlcpy(h.certi_file_name, certificate_out +
		((strlen(certificate_out) > (sizeof(h.certi_file_name) - 1)) ?
		(strlen(certificate_out) + 1 - sizeof(h.certi_file_name)) : 0),
			sizeof(h.certi_file_name));

	strlcpy(h.object_in_file_name, object_in +
		((strlen(object_in) > (sizeof(h.object_in_file_name) - 1)) ?
		(strlen(object_in) + 1 - sizeof(h.object_in_file_name)) : 0),
			sizeof(h.object_in_file_name));

	strlcpy(h.object_out_file_name, object_out +
		((strlen(object_out) > (sizeof(h.object_out_file_name) - 1)) ?
		(strlen(object_out) + 1 - sizeof(h.object_out_file_name)) : 0),
			sizeof(h.object_out_file_name));

	gethostname((h.host_name), sizeof(h.host_name) - 1);
	strlcpy(h.platform_name, platform_name, sizeof(h.platform_name));

	fprintf(stdout, "current user: %s\n", h.user_name);

	sockbuf = calloc(1, SPACKET_SIZE);
	if (!sockbuf) {
		fprintf(stderr, "Error: no memory??\n");
		goto out;
	}

	if (send(sockfd, &h, sizeof(h), 0) < 0) {
		fprintf(stderr, "send header error: %s(errno: %d)\n", strerror(errno), errno);
		fprintf(stderr, "maybe server was down??\n");
		goto out;
	}

	/*recv ack for header*/
	pos = 0;
	while (pos < sizeof(hrecv)) {
		recv_bytes = recv(sockfd, (char *)&hrecv + pos, sizeof(hrecv) - pos, 0);
		if (recv_bytes < 0) {
			fprintf(stderr, "recv header error: %s(errno: %d)\n", strerror(errno), errno);
			goto out;
		}
		pos += recv_bytes;
	}

	if (memcmp(&h, &hrecv, sizeof(h))) {
		fprintf(stderr, "%s header data error\n", __func__);
		goto out;
	}

	/*send config file*/
	while (config_size) {
		rd_bytes = read(config_in_fd, sockbuf, SPACKET_SIZE);
		config_size -= rd_bytes;
		pos = 0;
		while (rd_bytes > 0) {
			send_bytes = send(sockfd, sockbuf + pos, rd_bytes, 0);
			if (send_bytes < 0) {
				fprintf(stderr, "send config error: %s(errno: %d)\n", strerror(errno), errno);
				goto out;
			}
			rd_bytes -= send_bytes;
			pos += send_bytes;
		}
	}
	fprintf(stdout, "%s config file send done\n", __func__);

	/*recv ack for certificate*/
	memset(&a, 0, sizeof(a));
	if (recv(sockfd, &a, sizeof(a), 0) < 0) {
		fprintf(stderr, "recv certificate ack error: %s(errno: %d)\n", strerror(errno), errno);
		goto out;
	}
	fprintf(stdout, "SERVER INFO: %s", a.msg);
	if (a.ret <= 0)
		goto out;

	/*recv & save certificate*/
	certi_out_size = a.ret;
	while (certi_out_size) {
		recv_bytes = recv(sockfd, sockbuf, min(certi_out_size, SPACKET_SIZE), 0);
		if (recv_bytes < 0) {
			fprintf(stderr, "recv certificate error: %s(errno: %d)\n", strerror(errno), errno);
			goto out;
		}

		certi_out_size -= recv_bytes;
		pos = 0;
		while (recv_bytes > 0) {
			wr_bytes = write(certificate_out_fd, sockbuf + pos, recv_bytes);
			if (wr_bytes < 0) {
				fprintf(stderr, "write certificate error: %s(errno: %d)\n", strerror(errno), errno);
				goto out;
			}
			recv_bytes -= wr_bytes;
			pos += wr_bytes;
		}
	}
	fprintf(stdout, "%s certificate recv & saved\n", __func__);

	/*send object file*/
	while (object_size) {
		rd_bytes = read(object_in_fd, sockbuf, SPACKET_SIZE);
		object_size -= rd_bytes;
		pos = 0;
		while (rd_bytes > 0) {
			send_bytes = send(sockfd, sockbuf + pos, rd_bytes, 0);
			if (send_bytes < 0) {
				fprintf(stderr, "send object error: %s(errno: %d)\n", strerror(errno), errno);
				goto out;
			}
			rd_bytes -= send_bytes;
			pos += send_bytes;
		}
	}
	fprintf(stdout, "%s object file send done\n", __func__);

	/*recv ack for object*/
	memset(&a, 0, sizeof(a));
	if (recv(sockfd, &a, sizeof(a), 0) < 0) {
		fprintf(stderr, "recv certificate ack error: %s(errno: %d)\n", strerror(errno), errno);
		goto out;
	}
	fprintf(stdout, "SERVER INFO: %s", a.msg);
	if (a.ret <= 0)
		goto out;

	/*recv & save certificate*/
	object_out_size = a.ret;
	while (object_out_size) {
		recv_bytes = recv(sockfd, sockbuf, min(object_out_size, SPACKET_SIZE), 0);
		if (recv_bytes < 0) {
			fprintf(stderr, "recv object error: %s(errno: %d)\n", strerror(errno), errno);
			goto out;
		}

		object_out_size -= recv_bytes;
		pos = 0;
		while (recv_bytes > 0) {
			wr_bytes = write(object_out_fd, sockbuf + pos, recv_bytes);
			if (wr_bytes < 0) {
				fprintf(stderr, "write object error: %s(errno: %d)\n", strerror(errno), errno);
				goto out;
			}
			recv_bytes -= wr_bytes;
			pos += wr_bytes;
		}
	}
	fprintf(stdout, "%s object recv & saved\n", __func__);

	ret = 0;

out:
	if (config_in_fd > 0)
		close(config_in_fd);
	if (object_in_fd > 0)
		close(object_in_fd);
	if (certificate_out_fd > 0)
		close(certificate_out_fd);
	if (object_out_fd > 0)
		close(object_out_fd);
	if (sockbuf)
		free(sockbuf);
	return ret;
}
