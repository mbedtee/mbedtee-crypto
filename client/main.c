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
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <errno.h>
#include <pwd.h>

#include "crypto_mbedtee_ta.h"

#define APP_NAME	"cryptoclient"
#define VERSION		"1.0"

static const char *serv_ip = "127.0.0.1";

static struct option long_options[] = {
	{"type",			required_argument,	NULL, 't'},
	{"config-in",		required_argument,	NULL, 'x'},
	{"object-in",		required_argument,	NULL, 'i'},
	{"object-out",		required_argument,	NULL, 'o'},
	{"certificate-out",	required_argument,	NULL, 'c'},
	{"platform",		required_argument,	NULL, 'p'},
	{"help",			no_argument,		NULL, 'h'},
	{0, 0, NULL, 0}
};

static void print_usage(void)
{
	fprintf(stdout, "\tVersion: %s\n", VERSION);
	fprintf(stdout, "\t--type : operation type, mbedtee-ta or others. (INPUT)\n");
	fprintf(stdout, "\t--platform-name : specify the platform name, generic or others. (INPUT)\n");
	fprintf(stdout, "\t--config-in : specify the TA config file path. (INPUT)\n");
	fprintf(stdout, "\t--object-in : specify the TA object file path. (INPUT)\n");
	fprintf(stdout, "\t--object-out : specify the signed TA object file path. (OUTPUT)\n");
	fprintf(stdout, "\t--certificate-out : specify the TA certificate file path. (OUTPUT)\n");
	fprintf(stdout, "\t--help : this help information.\n");
	fprintf(stdout, "Ex:\t ==> (./%s --type %s --platform generic --config-in ta.config --object-in ta_raw.o --object-out ta_signed.o --certificate-out ta.certi).\n",
		 APP_NAME, CRYPTO_MBEDTEE_TA);
}

/*
 * Connect to serv_ip@serv_port, return socket_fd.
 */
static int connect_server(const char *serv_ip, int serv_port)
{
	int sockfd;
	struct sockaddr_in servaddr;
	struct timeval timeout = {3, 0};

	printf("trying connect to %s@%d\n", serv_ip, serv_port);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		printf("create socket error: %s(errno: %d)\n", strerror(errno), errno);
		return -1;
	}

	setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(serv_port);
	if (inet_pton(AF_INET, serv_ip, &servaddr.sin_addr) <= 0) {
		printf("inet_pton error for %s\n", serv_ip);
		close(sockfd);
		return -1;
	}

	if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
		printf("connect error: %s(errno: %d)\n", strerror(errno), errno);
		printf("maybe server was down??\n");
		close(sockfd);
		return -1;
	}
	printf("success connected to %s@%d\n", serv_ip, serv_port);
	return sockfd;
}

int main(int argc, char *argv[])
{
	int ret = -1, opt = -1;
	char *operation_type = NULL;
	char *config_in = NULL;
	char *object_in = NULL;
	char *object_out = NULL;
	char *certificate_out = NULL;
	char *platform = NULL;

	int option_index = 0;

	struct timeval ts, te;
	int sockfd = -1, pos = 0, recv_bytes = 0;
	struct cheader h, hrecv;

	if ((argc == 2) && (!strcmp(argv[1], "-h") ||
		!strcmp(argv[1], "--help") || !strcmp(argv[1], "-help"))) {
		print_usage();
		exit(0);
	} else if (argc >= 9) {
		while ((opt = getopt_long_only(argc, argv, "t:x:i:o:c:p:h",
			long_options, &option_index)) != -1) {
			switch (opt) {
			case 't':
				operation_type = optarg;
				fprintf(stdout, "operation type: %s\n", operation_type);
				break;

			case 'x':
				config_in = optarg;
				fprintf(stdout, "config_in: %s\n", config_in);
				break;

			case 'i':
				object_in = optarg;
				fprintf(stdout, "object_in: %s\n", object_in);
				break;

			case 'o':
				object_out = optarg;
				fprintf(stdout, "object_out: %s\n", object_out);
				break;

			case 'c':
				certificate_out = optarg;
				fprintf(stdout, "certificate_out: %s\n", certificate_out);
				break;

			case 'p':
				platform = optarg;
				fprintf(stdout, "platform: %s\n", platform);
				break;

			case 'h': /* help information */
				print_usage();
				exit(0);

			default:
				print_usage();
				exit(ret);
			}
		}
	} else {
		print_usage();
		exit(ret);
	}

	if (!operation_type)
		exit(ret);

	gettimeofday(&ts, NULL);

	sockfd = connect_server(serv_ip, SERV_PORT);
	if (sockfd < 0)
		goto out;

	memset(&h, 0, sizeof(h));
	memset(&hrecv, 0, sizeof(hrecv));
	h.magic = SMAGIC;
	h.version = SVERSION;
	crypto_strlcpy(h.operation_type, operation_type, sizeof(h.operation_type));

	if (send(sockfd, &h, sizeof(h), 0) < 0) {
		fprintf(stderr, "send cheader error: %s(errno: %d)\n", strerror(errno), errno);
		fprintf(stderr, "maybe server was down??\n");
		goto out;
	}

	/* recv ack for header */
	pos = 0;
	while (pos < sizeof(hrecv)) {
		recv_bytes = recv(sockfd, (char *)&hrecv + pos, sizeof(hrecv) - pos, 0);
		if (recv_bytes < 0) {
			fprintf(stderr, "recv cheader error: %s(errno: %d)\n", strerror(errno), errno);
			goto out;
		}
		pos += recv_bytes;
	}
	if (memcmp(&h, &hrecv, sizeof(h))) {
		fprintf(stderr, "handshake error\n");
		fprintf(stderr, "SERVER INFO: %s\n", (char *)&hrecv);
		goto out;
	}

	fprintf(stdout, "SERVER handshake PASS\n");

	if (!strcmp(operation_type, CRYPTO_MBEDTEE_TA))
		ret = crypto_mbedtee_ta(sockfd, platform, object_in, object_out, config_in, certificate_out);

out:
	gettimeofday(&te, NULL);
	if (sockfd > 0)
		close(sockfd);
	fprintf(stdout, "Elapsed time: %ld us\n", (1000000*(te.tv_sec - ts.tv_sec) +
				te.tv_usec - ts.tv_usec));
	exit(ret);
}
