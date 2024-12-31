// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <mbedtls.h>

#include "log.h"
#include "common.h"
#include "crypto_mbedtee_ta.h"

extern char cwd[256];

/* 1024 bytes */
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

#define CERTI_MAGIC (0x54524543) /* CERT */

struct certi_header {
	unsigned int magic;
	unsigned int total_len;
	char certi_type[40];
	unsigned int rsa_key_offset;
	unsigned int rsa_key_size;
	unsigned int crypto_key_offset;
	unsigned int crypto_key_size;
	unsigned int config_offset;
	unsigned int config_size;
	unsigned int segment_offset;
	unsigned int segment_size;
	unsigned int version_offset;
	unsigned int version_size;
};

static char *strstr_of_config(char *buf, char *e)
{
	char *pos = NULL;

	pos = strstr(buf, e);
	if (!pos)
		return NULL;

	pos = strchr(pos, '=');
	if (!pos)
		return NULL;

	pos++;
	while ((*pos != '\"')) {
		if (*pos == '=')
			return NULL;
		pos++;
	}

	pos++;
	return pos;
}

static int strlen_of_config(char *buf, char *e)
{
	char *pos = NULL;
	int len = 0;

	pos = strstr(buf, e);
	if (!pos)
		return 0;

	pos = strchr(pos, '=');
	if (!pos)
		return 0;

	pos++;
	while ((*pos != '\"')) {
		if (*pos == '=')
			return 0;
		pos++;
	}

	pos++;
	while (*(pos + len) != '\"') {
		if (*(pos + len) == '=')
			return 0;
		len++;
	}

	return len;
}

static int rand_func(void *rng_state, unsigned char *output, size_t len)
{
	unsigned int i;

	srand((int)time(NULL)+(int)rand());

	if (rng_state != NULL)
		rng_state = NULL;

	for (i = 0; i < len; ++i)
		output[i] = rand();

	return 0;
}

static int check_config(char *c)
{
	int ret = false, len = 0;
	char *temptr_strtok;
	char *c_bak;
	char *split_c = "-";
	char tmp[256];

	len = strlen_of_config(c, "uuid");
	if (!len) {
		slog("invalid UUID info\n");
		goto out;
	}

	memset(tmp, 0, sizeof(tmp));
	memcpy(tmp, strstr_of_config(c, "uuid"), len);
	temptr_strtok = strtok_r(tmp, split_c, &c_bak);
	temptr_strtok = strtok_r(NULL, split_c, &c_bak);
	temptr_strtok = strtok_r(NULL, split_c, &c_bak);
	temptr_strtok = strtok_r(NULL, split_c, &c_bak);
	temptr_strtok = strtok_r(NULL, split_c, &c_bak);
	if (!temptr_strtok || strlen(temptr_strtok) != 12) {
		slog("invalid uuid info %s\n", c);
		goto out;
	}

	if (!strlen_of_config(c, "name")) {
		slog("invalid name info\n");
		goto out;
	}

	if (!strlen_of_config(c, "path")) {
		slog("invalid path info\n");
		goto out;
	}

	if (!strlen_of_config(c, "stack_size")) {
		slog("invalid stack_size info\n");
		goto out;
	}

	if (!strlen_of_config(c, "heap_size")) {
		slog("invalid heap_size info\n");
		goto out;
	}

	if (strlen_of_config(c, "single_instance") != 1) {
		slog("invalid single_instance info\n");
		goto out;
	}

	if (strlen_of_config(c, "dev_access") < 6) {
		slog("invalid dev_access info\n");
		goto out;
	}

	ret = true;
out:
	return ret;
}

static int prepare_certificate(struct sheader *h,
		char *config, unsigned char *certi, unsigned char ta_crypto_key[16])
{
	int ret = -1, KeyLen = 0, i = 0;
	char pubKeyPath[512] = {0};
	char parentKeyPairPath[512] = {0};
	char parentCryptoKeyPath[512] = {0};
	struct certi_header c = {0};
	int pos = 0, rd_bytes = 0;
	unsigned char parentCryptoKey[16];
	struct stat file_st;
	FILE *pubKeyHdl = NULL, *cryptoKeyHdl = NULL;

	mbedtls_rsa_context *rsa;
	mbedtls_pk_context pk;
	const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	unsigned char shasum[64];
	size_t olen;
	mbedtls_cipher_context_t cipher;

	mbedtls_pk_init(&pk);
	mbedtls_cipher_init(&cipher);

	sprintf(pubKeyPath, "%s/%s/%s.pub.der", cwd, h->platform_name, CRYPTO_MBEDTEE_TA);
	sprintf(parentKeyPairPath, "%s/%s/mbedtee-root.der", cwd, h->platform_name);
	sprintf(parentCryptoKeyPath, "%s/%s/mbedtee-root.cryptokey", cwd, h->platform_name);

	if (check_config(config) != true)
		return -1;

	memset(&c, 0, sizeof(c));
	c.magic = CERTI_MAGIC;
	strlcpy(c.certi_type, CRYPTO_MBEDTEE_TA, sizeof(c.certi_type));

	stat(pubKeyPath, &file_st);

	pubKeyHdl = fopen(pubKeyPath, "r");
	if (pubKeyHdl == NULL) {
		slog("Open ta pub key file error @ %s\n", pubKeyPath);
		goto out;
	}

	cryptoKeyHdl = fopen(parentCryptoKeyPath, "r");
	if (cryptoKeyHdl == NULL) {
		slog("Open ta crypto key file error\n");
		goto out;
	}

	c.rsa_key_size = file_st.st_size;
	c.rsa_key_offset = sizeof(c);
	c.crypto_key_offset = c.rsa_key_offset + c.rsa_key_size;
	c.crypto_key_size = 16;
	c.config_offset = c.crypto_key_offset + c.crypto_key_size;
	c.config_size = h->config_size;
	c.segment_offset = c.config_offset + c.config_size;
	c.segment_size = 8;
	c.version_offset = c.segment_offset + c.segment_size;
	c.version_size = 8;
	c.total_len = sizeof(c) + c.rsa_key_size + c.crypto_key_size +
			c.config_size + c.segment_size + c.version_size;

	for (i = 0; i < (int)h->config_size; i++)
		certi[c.config_offset + i] = config[i];

	KeyLen = c.rsa_key_size;
	while (KeyLen) {
		rd_bytes = fread(certi + c.rsa_key_offset + pos, 1, KeyLen, pubKeyHdl);
		if (rd_bytes > 0) {
			pos += rd_bytes;
			KeyLen -= rd_bytes;
		}
	}

	pos = 0;
	KeyLen = sizeof(parentCryptoKey);
	while (KeyLen) {
		rd_bytes = fread(parentCryptoKey + pos, 1, KeyLen, cryptoKeyHdl);
		if (rd_bytes > 0) {
			pos += rd_bytes;
			KeyLen -= rd_bytes;
		}
	}

	rand_func(NULL, certi + c.crypto_key_offset, c.crypto_key_size);
	memcpy(ta_crypto_key, certi + c.crypto_key_offset, c.crypto_key_size);
	memset(certi + c.segment_offset, 0, c.segment_size);
	memset(certi + c.version_offset, 0, c.version_size);
	memcpy(certi, &c, sizeof(c));


	mbedtls_md(md_info, certi, c.total_len, shasum);

	ret = mbedtls_pk_parse_keyfile(&pk, parentKeyPairPath, NULL, rand_func, NULL);
	if (ret != 0) {
		slog("error paring %s\n", parentKeyPairPath);
		goto out;
	}

	rsa = mbedtls_pk_rsa(pk);
	mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);

	ret = mbedtls_rsa_pkcs1_sign(rsa, rand_func, NULL, MBEDTLS_MD_SHA256,
			mbedtls_md_get_size(md_info), shasum, certi + c.total_len);
	if (ret != 0) {
		slog("rsa_sign failed\n");
		goto out;
	}

	slog("certificate signed\n");

	mbedtls_cipher_setup(&cipher, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC));
	mbedtls_cipher_set_padding_mode(&cipher, MBEDTLS_PADDING_NONE);
	mbedtls_cipher_setkey(&cipher, parentCryptoKey, 128, MBEDTLS_ENCRYPT);
	/* mbedtls_cipher_set_iv(&cipher, IV, IVLen); IV is zero */
	mbedtls_aes_cts(&cipher, certi, c.total_len, certi, &olen, 1);

	slog("certificate encrypted\n");

	ret = c.total_len + mbedtls_rsa_get_len(rsa);

out:
	mbedtls_pk_free(&pk);
	mbedtls_cipher_free(&cipher);

	if (pubKeyHdl)
		fclose(pubKeyHdl);

	if (cryptoKeyHdl)
		fclose(cryptoKeyHdl);
	return ret;
}

static int prepare_ta_object(struct sheader *h,
	unsigned char *buf, unsigned char ta_crypto_key[16])
{
	int ret = -1;
	char privKeyPath[512] = {0};

	mbedtls_rsa_context *rsa;
	mbedtls_pk_context pk;
	const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	unsigned char shasum[64];
	size_t olen;
	mbedtls_cipher_context_t cipher;

	mbedtls_pk_init(&pk);
	mbedtls_cipher_init(&cipher);

	sprintf(privKeyPath, "%s/%s/%s.der", cwd, h->platform_name, CRYPTO_MBEDTEE_TA);

	mbedtls_md(md_info, buf, h->object_size, shasum);

	ret = mbedtls_pk_parse_keyfile(&pk, privKeyPath, NULL, rand_func, NULL);
	if (ret != 0) {
		slog("error paring %s\n", privKeyPath);
		goto out;
	}

	rsa = mbedtls_pk_rsa(pk);
	mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);

	ret = mbedtls_rsa_pkcs1_sign(rsa, rand_func, NULL, MBEDTLS_MD_SHA256,
			mbedtls_md_get_size(md_info), shasum, buf + h->object_size);
	if (ret != 0) {
		slog("rsa_sign failed\n");
		goto out;
	}

	slog("object signed\n");

	mbedtls_cipher_setup(&cipher, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC));
	mbedtls_cipher_set_padding_mode(&cipher, MBEDTLS_PADDING_NONE);
	mbedtls_cipher_setkey(&cipher, ta_crypto_key, 128, MBEDTLS_ENCRYPT);
	/* mbedtls_cipher_set_iv(&cipher, IV, IVLen); IV is zero */
	mbedtls_aes_cts(&cipher, buf, h->object_size, buf, &olen, 1);

	slog("object encrypted\n");

	ret = h->object_size + mbedtls_rsa_get_len(rsa);

out:
	mbedtls_pk_free(&pk);
	mbedtls_cipher_free(&cipher);
	return ret;
}

void crypto_mbedtee_ta(int connfd)
{
	unsigned char ta_crypto_key[16];
	char buf[4096];
	int ret = -1, sret = -1;
	unsigned char *obj = NULL;
	unsigned char certi[4096];
	struct ack a;
	int sbytes = 0;
	int config_size = 0, object_size = 0;
	int pos = 0;

	struct sheader h = {0};

	memset(buf, 0, sizeof(buf));
	memset((char *)&h, 0, sizeof(h));

	if (recv(connfd, buf, sizeof(buf), 0) == sizeof(h)) {
		memcpy((char *)&h, buf, sizeof(h));
		if (h.magic != SMAGIC) {
			memset((char *)&h, 0, sizeof(h));
			slog("header magic error\n");
		}

		if (send(connfd, (char *)&h, sizeof(h), 0) != sizeof(h)) {
			slog("error send ack header\n");
			return;
		}
		if (h.magic != SMAGIC)
			return;
	} else {
		slog("client exception??\n");
		return;
	}

	slog("%s@%s signing %s for %s\n",
		h.user_name, h.host_name, CRYPTO_MBEDTEE_TA, h.platform_name);

	slog("Files: %s %s %s %s\n",
		h.config_file_name, h.certi_file_name,
		h.object_in_file_name, h.object_out_file_name);

	/* recv config file */
	memset(buf, 0, sizeof(buf));
	config_size = min(h.config_size, sizeof(buf) - 1024);/* reserved 1024 for signature */
	while (config_size) {
		sbytes = recv(connfd, buf + pos, config_size, 0);
		if (sbytes > 0)	{
			pos += sbytes;
			config_size -= sbytes;
		} else {
			slog("RECV CONFIG ERROR\n");
			return;
		}
	}

	/* prepare certificate file */
	memset(certi, 0, sizeof(certi));
	ret = prepare_certificate(&h, buf, certi, ta_crypto_key);
	memset(&a, 0, sizeof(a));
	a.ret = ret;
	if (ret <= 0)
		sprintf(a.msg, "prepare certificate failed\n");
	else
		sprintf(a.msg, "prepare certificate done\n");

	slog("%s", a.msg);
	sret = send(connfd, (char *)&a, sizeof(a), 0);
	if ((ret <= 0) || (sret <= 0))
		goto out;

	ret = send(connfd, (char *)certi, ret, 0);
	slog("sent certificate %d bytes\n", ret);
	if (ret <= 0)
		goto out;

	obj = (unsigned char *)malloc(h.object_size+1024);
	if (!obj) {
		slog("Memory not enough\n");
		goto out;
	}

	/* recv object file */
	pos = 0;
	object_size = h.object_size;
	if (obj) {
		while (object_size) {
			sbytes = recv(connfd, obj + pos, object_size, 0);
			if (sbytes > 0)	{
				pos += sbytes;
				object_size -= sbytes;
			} else {
				slog("RECV OBJECT ERROR\n");
				goto out;
			}
		}
	}

	ret = prepare_ta_object(&h, obj, ta_crypto_key);

	memset(&a, 0, sizeof(a));
	a.ret = ret;
	if (ret <= 0)
		sprintf(a.msg, "process ta object failed\n");
	else
		sprintf(a.msg, "process ta object done\n");

	slog("%s", a.msg);

	sret = send(connfd, (char *)&a, sizeof(a), 0);
	if ((ret <= 0) || (sret <= 0))
		goto out;

	pos = 0;
	object_size = ret;
	while (object_size) {
		sbytes = send(connfd, obj + pos, object_size, 0);
		if (sbytes > 0)	{
			pos += sbytes;
			object_size -= sbytes;
		} else {
			slog("SEND OBJECT ERROR\n");
			goto out;
		}
	}

	slog("sent object %d bytes\n", ret);

out:
	if (obj)
		free(obj);
}
