#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
#

APP = cryptoserver

CFLAGS = -O2 -Wall -Werror -Imbedtls -Imbedtls/include -Imbedtls/library

SRCS = main.c log.c crypto_mbedtee_ta.c dispatcher.c \
	mbedtls/mbedtls.c mbedtls/library/*.c

all : clean
	@gcc $(CFLAGS) -o $(APP) $(SRCS)
	@strip ${APP}

clean :
	@rm -f ${APP}
