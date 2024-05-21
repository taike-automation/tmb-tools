// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 Taike Automation Ltd.
 * TMB Bus userspace tools.
 */

#include <stdbool.h>
#include <pthread.h>
#include <signal.h>
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
#include <sys/time.h>

#include "tmb.h"

#ifndef AF_TMB
#define AF_TMB  46
#endif

#define POLL_TIMEOUT_MS		(5 * 1000) /* depend on BCR value */

#define MASTER_IFACE_DEFAULT	"tmb0"
#define SLAVE_IFACE_DEFAULT	"tmb1"
#define ADDR_DEFAULT		0x1b

#define screen_clear()		printf("\033[H\033[J")
#define screen_gotoxy(x, y)	printf("\033[%d;%dH", x, y)

struct payload {
	union {
		struct {
			uint8_t ap;
			int64_t time;
		};
		uint8_t raw[32];
	};
} __attribute__((packed));

struct client_data {
	struct app_context *app;
	char *iface;
	uint8_t addr;
	uint8_t idx;
};

struct client_context {
	pthread_t tid;
	pthread_attr_t attr;
	struct client_data arg;
};

struct server_context {
	int sock;
	struct payload payload;
	int32_t packets;
	uint64_t bytes;
};

struct app_context {
	struct client_context *client_ctx;
	struct server_context *server_ctx;
	char *args[2];
	char *master_iface;
	char *slave_iface;
	uint32_t packets;
	uint64_t bytes;
	uint8_t addr;
	bool reverse;
	int slave_threads;
	int master_threads;
};

static char doc[] = "A TMB bus test utility";
static char args_doc[] = "<slave threads num> <master threads num>";

static struct argp_option options[] = {
	{"master",	'm', "<name>",		0, "Master net iface"},
	{"slave",	's', "<name>",		0, "Slave net iface"},
	{"addr",	'a', "<hex value>",	0, "Slave device addr"},
	{0}
};

static struct app_context app = {0};

static uint64_t get_timestamp(void) {
	struct timeval time;
	gettimeofday(&time, NULL);
	return time.tv_sec * 1000 + time.tv_usec / 1000;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct app_context *ctx = state->input;

	switch(key) {
	case 'm':
		ctx->master_iface = arg;
		break;
	case 's':
		ctx->slave_iface = arg;
		break;
	case 'a':
		ctx->addr = strtol(arg, NULL, 16);
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num >= 2)
			argp_usage (state);
		ctx->args[state->arg_num] = arg;
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

static void update_screen(struct app_context *app)
{
	struct server_context *ctx;
	int idx = 0;

	screen_clear();
	screen_gotoxy(0, 0);

	if (app->slave_threads)
		printf("Slave send ---> Master recv\n");

	for (int i = 0; i < app->slave_threads; i++) {
		ctx = &app->server_ctx[idx];
		printf("AP [%02d]: packets %8d; bytes %16ld; timestamp %016ld; ap %d\n",
		       idx, ctx->packets, ctx->bytes,
		       ctx->payload.time, ctx->payload.ap);
		idx++;
	}

	if (app->master_threads)
		printf("Master send ---> Slave recv\n");

	for (int i = 0; i < app->master_threads; i++) {
		ctx = &app->server_ctx[idx];
		printf("AP [%02d]: packets %8d; bytes %16ld; timestamp %016ld; ap %d\n",
		       idx, ctx->packets, ctx->bytes,
		       ctx->payload.time, ctx->payload.ap);
		idx++;
	}

	printf("--------------------------------------------\n");
	printf("Overall packets %8d; bytes %16ld\n",
	       app->packets, app->bytes);

	ctx = &app->server_ctx[0];
	for (int i = app->slave_threads; i < app->master_threads; i++) {
		if (abs(ctx->packets - app->server_ctx[i].packets) > 2) {
			printf("WTF happens\n");
			exit(-EFAULT);
		}
	}
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

static void *client(void *param)
{
	struct client_data *client = param;
	struct app_context *app = client->app;
	int sock, ret = 0;
	uint32_t *cnt;
	struct payload *payload;

	sock = open_socket(client->iface, client->addr, client->idx);
	if (sock < 0) {
		ret = sock;
		goto out;
	}

	payload = mmap(0, sizeof(struct payload), PROT_READ | PROT_WRITE,
		   MAP_SHARED, sock, 0);
	if (payload == MAP_FAILED) {
		ret = errno;
		goto out;
	}

	memset(payload, 0, sizeof(struct payload));
	payload->ap = client->idx;

	ret = ioctl(sock, TMB_IOCTL_MMAP, sizeof(struct payload));
	if (ret)
		goto out;

	while (true) {
		usleep(100 * 1000);
		payload->time = get_timestamp();
	}

out:
	pthread_exit(NULL);
}

static int spawn_clients(struct app_context *app)
{
	struct client_context *ctx;
	int count = app->master_threads + app->slave_threads;
	int sock, idx = 0;

	app->client_ctx = malloc(sizeof(struct client_context) * count);
	if (app->client_ctx == NULL)
		return -ENOMEM;

	for (int i = 0; i < app->slave_threads; i++) {
		ctx = &app->client_ctx[idx];

		ctx->arg.iface = app->slave_iface;
		ctx->arg.addr = app->addr;
		ctx->arg.app = app;
		ctx->arg.idx = idx;
		idx++;

		pthread_attr_init(&ctx->attr);
		pthread_create(&ctx->tid, &ctx->attr, client, &ctx->arg);
	}

	for (int i = 0; i < app->master_threads; i++) {
		ctx = &app->client_ctx[idx];

		ctx->arg.iface = app->master_iface;
		ctx->arg.addr = app->addr;
		ctx->arg.app = app;
		ctx->arg.idx = idx;
		idx++;

		pthread_attr_init(&ctx->attr);
		pthread_create(&ctx->tid, &ctx->attr, client, &ctx->arg);
	}

	return 0;
}

static int server_recv(struct app_context *app, int sock, int idx)
{
	int size;
	struct server_context *ctx = &app->server_ctx[idx];

	return recv(sock, &ctx->payload, sizeof(struct payload), 0);
}

static int server_prepare(struct app_context *app)
{
	int count = app->master_threads + app->slave_threads;
	int sock, idx = 0;

	app->server_ctx = malloc(sizeof(struct server_context) * count);
	if (app->server_ctx == NULL)
		return -ENOMEM;

	for (int i = 0; i < app->slave_threads; i++) {
		sock = open_socket(app->master_iface, app->addr, idx);
		if (sock < 0)
			return sock;
		app->server_ctx[idx++].sock = sock;
	}

	for (int i = 0; i < app->master_threads; i++) {
		sock = open_socket(app->slave_iface, app->addr, idx);
		if (sock < 0)
			return sock;
		app->server_ctx[idx++].sock = sock;
	}

	return 0;
}

static int server(struct app_context *app)
{
	struct server_context *ctx;
	struct pollfd *fds;
	int count = app->master_threads + app->slave_threads;
	int ts = (int)time(NULL);
	int sock, size, ret, idx = 0;

	fds = malloc(sizeof(struct pollfd) * count);
	if (fds == NULL)
		return -ENOMEM;

	for (int i = 0; i < app->slave_threads; i++) {
		sock = app->server_ctx[idx].sock;

		ret = ioctl(sock, TMB_IOCTL_CYCLE_RECV, sizeof(struct payload));
		if (ret) {
			printf("ioctl err: %s\n", strerror(errno));
			return ret;
		}

		fds[idx].fd = sock;
		fds[idx].events = POLLIN;
		idx++;
	}

	for (int i = 0; i < app->master_threads; i++) {
		fds[idx].fd = app->server_ctx[idx].sock;
		fds[idx].events = POLLIN | POLLERR;
		idx++;
	}

	while (true) {
		ret = poll(fds, count, POLL_TIMEOUT_MS);
		if (ret < 0) {
			printf("Poll error (%d): %s\n", errno, strerror(errno));
			return errno;
		}
		if (ret == 0) {
			printf("Poll timeout!\n");
			return -ETIMEDOUT;
		}

		for (int i = 0; i < count; i++) {
			if (fds[i].revents & POLLERR) {
				printf("Recv err (%d): AP %d\n", i);
				return -EFAULT;
			}

			if (fds[i].revents & POLLIN) {
				fds[i].revents = 0;

				size = server_recv(app, fds[i].fd, i);
				if (size != sizeof(struct payload)) {
					printf("Size mismatch (%d): AP %d\n",
					       size, i);
					return -EFAULT;
				}

				ctx = &app->server_ctx[i];
				ctx->packets++;
				ctx->bytes += size;

				if (ctx->payload.ap != i) {
					update_screen(app);
					printf("AP missmatch: %d != %d\n",
						ctx->payload.ap, i);
					return -EFAULT;
				}

				app->packets++;
				app->bytes += size;
			}
		}

		/* Update screen every second */
		if ((int)time(NULL) > ts) {
			update_screen(app);
			ts = (int)time(NULL);
		}
	}
}

static void ctrl_c_hook(int signum)
{
	update_screen(&app);
}

int main(int argc, char **argv)
{
	struct sigaction action;
	int ret;

	app.master_iface = MASTER_IFACE_DEFAULT;
	app.slave_iface = SLAVE_IFACE_DEFAULT;
	app.addr = ADDR_DEFAULT;

	ret = argp_parse(&argp, argc, argv, 0, 0, &app);
	if (ret)
		return ret;

	app.slave_threads = strtol(app.args[0], NULL, 10);
	app.master_threads = strtol(app.args[1], NULL, 10);

	memset(&action, 0, sizeof(struct sigaction));
	action.sa_handler = ctrl_c_hook;
	sigaction(SIGINT, &action, NULL);

	ret = server_prepare(&app);
	if (ret)
		return ret;

	ret = spawn_clients(&app);
	if (ret)
		return ret;

	return server(&app);
}
