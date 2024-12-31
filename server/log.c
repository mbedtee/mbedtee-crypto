// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "log.h"

void slog(const char *fmt, ...)
{
	static char __buf[8192] = {0};
	static char cwd[256] = {0};
	char logfile[512] = {0};
	char timestr[64] = {0};
	static FILE *logfp;
	time_t now = time(NULL);
	va_list args = {0};
	size_t l = 0;

	if (!fmt)
		return;

	strftime(timestr, sizeof(timestr),
		"%Y-%m-%d", localtime(&now));

	if (cwd[0] == 0 && getcwd(cwd, sizeof(cwd)) == NULL)
		return;

	sprintf(logfile, "%s/%s.log", cwd, timestr);

	if (logfp == NULL)
		logfp = fopen(logfile, "a+");
	else if (access(logfile, F_OK) < 0) {
		fclose(logfp);
		logfp = fopen(logfile, "a+");
	}

	struct timeval tv;
	struct tm *p = NULL;

	gettimeofday(&tv, NULL);
	p = localtime(&tv.tv_sec);

	snprintf(timestr, sizeof(timestr), "[%04d-%02d-%02d %02d:%02d:%02d.%03ld] ",
		1900 + p->tm_year, 1 + p->tm_mon, p->tm_mday,
		p->tm_hour, p->tm_min, p->tm_sec, tv.tv_usec/1000);

	fprintf(logfp, "%s", timestr);

	va_start(args, fmt);
	l = vsnprintf(__buf, sizeof(__buf), fmt, args);
	va_end(args);

	if (l <= sizeof(__buf))
		fprintf(logfp, "%s", __buf);

	fflush(logfp);
}
