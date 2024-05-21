// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 Taike Automation Ltd.
 * TMB Bus userspace tools.
 */

#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <poll.h>
#include <argp.h>

#include <linux/const.h>
#include <linux/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "tmb.h"

#ifndef AF_TMB
#define AF_TMB  46
#endif

struct app_context {
	char *iface;
	size_t size;
	uint8_t buf[TMB_MTU];
	uint8_t pattern;
	int period;
	int addr;
	int ap;
	bool dontwait;
	bool cyclic;
	bool quiet;
	bool send;
	bool recv;
	bool nop;
	bool bg;
};

static char doc[] = "A TMB bus test utility";
static char args_doc[] = "IFACE";

static struct argp_option options[] = {
	{"addr",	'a', "<hex addr>",	0,	"Bus addr"},
	{"ap",		'i', "<idx>",		0,	"AP index"},
	{"send",	's', 0,			0,	"Send data"},
	{"recv",	'r', 0,			0,	"Recv data"},
	{"dontwait",	'd', 0,			0,	"Immediate read local copy of an AP (Slave only)"},
	{"nop",		'n', 0,			0,	"Just keep open a AF_TMB socket"},
	{"cyclic",	'c', 0,			0,	"Cyclic receive mode"},
	{"bg",		'b', 0,			0,	"Background send mode"},
	{"pattern",	'p', "<hex byte>",	0,	"Pattern char"},
	{"size",	'l', "<bytes>",		0,	"Data size"},
	{"quiet",	'q', 0,			0,	"Supress data dumps"},
	{"period",	't', "<ms>",		0,	"Data update period for the background mode (default=1000)"},
	{0}
};

static void hex_dump(char *desc, void *addr, int len)
{
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char*)addr;

	if (desc != NULL)
		printf ("%s\n", desc);

	for (i = 0; i < len; i++) {
		if ((i % 16) == 0) {
			if (i != 0)
				printf("  %s\n", buff);

			printf("  %04x ", i);
		}

		printf(" %02x", pc[i]);

		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];

		buff[(i % 16) + 1] = '\0';
	}

	while ((i % 16) != 0) {
		printf("   ");
		i++;
    	}

	printf("  %s\n", buff);
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct app_context *ctx = state->input;

	switch(key) {
	case 'l':
		ctx->size = strtol(arg, NULL, 10);
		break;
	case 'a':
		ctx->addr = strtol(arg, NULL, 16);
		break;
	case 'i':
		ctx->ap = strtol(arg, NULL, 10);
		break;
	case 't':
		ctx->period = strtol(arg, NULL, 10);
		break;
	case 's':
		ctx->send = true;
		break;
	case 'r':
		ctx->recv = true;
		break;
	case 'n':
		ctx->nop = true;
		break;
	case 'c':
		ctx->cyclic = true;
		break;
	case 'b':
		ctx->bg = true;
		break;
	case 'p':
		ctx->pattern = strtoll(arg, NULL, 16);
		break;
	case 'q':
		ctx->quiet = true;
		break;
	case 'd':
		ctx->dontwait = true;
		break;
	case ARGP_KEY_ARG:
		ctx->iface = arg;
		break;
	case ARGP_KEY_END:
	    if(state->arg_num < 1)
		argp_usage(state);
	    break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc};

static int send_once(struct app_context *ctx, int sock)
{
	int size;

	if (ctx->pattern)
		for (size_t i = 0; i < ctx->size; i++)
			ctx->buf[i] = ctx->pattern;

	if (!ctx->quiet) {
		printf("SEND: addr 0x%02x:%03d; size %ld\n",
		       ctx->addr, ctx->ap, ctx->size);
		hex_dump(NULL, ctx->buf, ctx->size);
	}

	size = send(sock, ctx->buf, ctx->size, 0);
	if (size != ctx->size)
		return errno;

	return 0;
}

static int send_mmaped(struct app_context *ctx, int sock)
{
	int size = ctx->size;
	uint8_t *buf;
	int ret, idx = 0;

	buf = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, sock, 0);
	if (buf == MAP_FAILED)
		return errno;

	for (int i = 0; i < size; i++)
		buf[i] = 0;

	printf("Background SEND: addr 0x%02x:%03d; size %ld\n",
	       ctx->addr, ctx->ap, ctx->size);

	ret = ioctl(sock, TMB_IOCTL_MMAP, size);
	if (ret)
		return ret;

	while (true) {
		idx++;
		usleep(ctx->period * 1000);

		for (int i = 0; i < size; i++)
			buf[i] = idx;
	}
}

static int recv_cyclic(struct app_context *ctx, int sock)
{
	int size, ret;

	ret = ioctl(sock, TMB_IOCTL_CYCLE_RECV, ctx->size);
	if (ret) {
		printf("ioctl err: %s\n", strerror(errno));
		return ret;
	}

	while (true) {
		size = recv(sock, ctx->buf, ctx->size, 0);
		if (size < 0)
			return errno;

		if (!ctx->quiet) {
			printf("Cyclic RECV: addr 0x%02x:%03d; size %ld\n",
			       ctx->addr, ctx->ap, ctx->size);
			hex_dump(NULL, ctx->buf, size);
		}
	}

	return 0;
}

static int recv_once(struct app_context *ctx, int sock)
{
	int size, flags = 0;

	if (ctx->dontwait)
		flags |= MSG_DONTWAIT;

	size = recv(sock, ctx->buf, ctx->size, flags);
	if (size < 0)
		return errno;

	if (!ctx->quiet) {
		printf("RECV: addr 0x%02x:%03d; size %ld\n",
		       ctx->addr, ctx->ap, ctx->size);
		hex_dump(NULL, ctx->buf, size);
	}

	return 0;
}

static int open_socket(const char *iface_name, uint8_t addr, uint8_t ap)
{
	struct sockaddr_tmb sockaddr = {0};
	struct ifreq ifr;
	int sock, ret;

	sock = socket(AF_TMB, SOCK_RAW, TMB_RAW);
	if (sock < 0) {
		printf("socket creation err (%d)\n", sock);
		return 0;
	}

	strcpy(ifr.ifr_name, iface_name);
	ret = ioctl(sock, SIOCGIFINDEX, &ifr);
	if (ret) {
		printf("ioctl err: %s\n", strerror(errno));
		goto exit;
	}

	sockaddr.family = AF_TMB;
	sockaddr.ifindex = ifr.ifr_ifindex;

	ret = bind(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
	if (ret) {
		printf("bind err: %s\n", strerror(errno));
		goto exit;
	}

	sockaddr.addr = addr;
	sockaddr.ap = ap;

	ret = connect(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
	if (ret) {
		printf("connect err: %s\n", strerror(errno));
		goto exit;
	}

	return sock;
exit:
	close(sock);
	return ret;
}

static int app(struct app_context *ctx)
{
	int sock, ret;

	sock = open_socket(ctx->iface, ctx->addr, ctx->ap);
	if (sock < 0)
		return sock;

	if (ctx->send) {
		if (ctx->bg)
			ret = send_mmaped(ctx, sock);
		else
			ret = send_once(ctx, sock);
	}

	if (ctx->recv) {
		if (ctx->cyclic)
			ret = recv_cyclic(ctx, sock);
		else
			ret = recv_once(ctx, sock);
	}

	if (ctx->nop)
		while (true);

	if (ret)
		printf("Error (%d): %s\n", ret, strerror(ret));

	close(sock);

	return ret;
}

int main(int argc, char **argv)
{
	struct app_context ctx = {0};
	error_t err;

	/* Off buffered stdout */
	setvbuf(stdout, NULL, _IONBF, 0);

	/* Default values */
	ctx.period = 1000;

	err = argp_parse(&argp, argc, argv, 0, 0, &ctx);
	if (err)
		return err;

	return app(&ctx);
}
