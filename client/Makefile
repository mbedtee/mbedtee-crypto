#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
#

CFLAGS = -O2 -Wall -Werror
APP = cryptoclient

all : clean
	@gcc $(CFLAGS) -o ${APP} *.c
	@strip ${APP}

clean :
	@rm -f ${APP}
