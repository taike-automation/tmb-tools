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
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "tmb.h"

#ifndef AF_TMB
#define AF_TMB  46
#endif

enum parser_state {
	STATE_INITIAL,
	STATE_CTRL0_M,
	STATE_CTRL1_M,
	STATE_CTRL2_M,
	STATE_CTRL0_S,
	STATE_CTRL1_S,
	STATE_CTRL2_S,
	STATE_DATA,
};

struct log_entry {
	unsigned short word;
	union {
		unsigned int info;
		struct {
			unsigned int par:1;
			unsigned int type:1;
			unsigned int decode:1;
			unsigned int lag:1;
			unsigned int ts:12;
			unsigned int cnt:12;
		};
	};
} __attribute__((packed));

struct frame {
	uint16_t buf[TMB_TRANSACTION_MAX_LEN];
	uint16_t req_size;
	uint16_t actual_size;
	uint16_t size;
	uint16_t ts;
	uint8_t dev;
	uint8_t page;
	uint8_t op;
	bool ack;
	bool broadcast;
	bool invalid;
	bool noresp;
};

struct parser {
	enum parser_state state;
	enum parser_state prev_state;
	struct log_entry sync_buf[2];
	struct frame frame;
	uint16_t cnt;
	int sync_slot;
	int idx;
};

struct app_context {
	struct parser p;
	char *iface;
	bool hex;
	bool raw;
	bool ascii;
};

static char doc[] = "A TMB bus logger";
static char args_doc[] = "IFACE";

static struct argp_option options[] = {
	{"hex",		'x', 0, 0, "Print a hex dump of frame"},
	{"raw",		'r', 0, 0, "Print a raw log entries"},
	{"ascii",	'a', 0, 0, "Print a ASCII dump of frame"},
	{0}
};

static int parser_step(struct parser *p, struct log_entry *e,
		       struct frame *frame);

static void hex_dump(void *addr, int size, bool ascii)
{
    unsigned char *byte = (unsigned char*)addr;
    unsigned char buff[17];
    int i;

    // Process every byte in the data.
    for (i = 0; i < size; i++) {
	// Multiple of 16 means new line (with line offset).

	if ((i % 16) == 0 && ascii) {
		// Just don't printf ASCII for the zeroth line.
		if (i != 0)
			printf("  %s\n", buff);

		// Output the offset.
		printf("  %04x ", i);
	}

	// Now the hex code for the specific character.
	if ((i % 2) == 0)
		printf(" %04x", *((uint16_t *)&byte[i]));

	// And store a printable ASCII character for later.
	if ((byte[i] < 0x20) || (byte[i] > 0x7e)) {
		buff[i % 16] = '.';
	} else {
		buff[i % 16] = byte[i];
	}

	buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
	printf("   ");
	i++;
    }

    // And printf the final ASCII bit.
    printf("  %s\n", buff);
}

static inline void parser_set_state(struct parser *p, enum parser_state state)
{
	p->prev_state = p->state;
	p->state = state;
}

static inline int parser_fault(struct parser *p)
{
	memset(p, 0, sizeof(struct parser));
	return -EFAULT;
}

static inline void parser_flush(struct parser *p)
{
	memset(&p->frame, 0, sizeof(struct frame));
	p->idx = 0;
	parser_set_state(p, STATE_INITIAL);
}

static int parser_noresp_frame(struct parser *p, struct frame *frame)
{
	struct tmb_ctrl_word0 *word0;
	struct tmb_ctrl_word1 *word1;
	struct frame *f = &p->frame;
	size_t size;

	word0 = (struct tmb_ctrl_word0 *)&f->buf[0];
	word1 = (struct tmb_ctrl_word1 *)&f->buf[1];
	size = (p->idx - 1) * sizeof(uint16_t);

	/* Reparse word0 and word1 because frame was changed */
	memset(frame, 0, sizeof(struct frame));
	memcpy(frame->buf, f->buf, size);
	frame->req_size = word0->size;
	frame->op = word0->op;
	frame->dev = word1->dev;
	frame->page = word1->page;
	frame->broadcast = (word1->dev == TMB_ADDR_BROADCAST) ? true : false;
	frame->size = size;
	frame->noresp = true;

	return size;
}

static int parser_dump_frame(struct parser *p, struct frame *frame)
{
	struct frame *f = &p->frame;
	size_t size = p->idx * sizeof(uint16_t);

	memcpy(frame, f, sizeof(struct frame));
	frame->size = size;

	parser_flush(p);

	return size;
}

static bool parser_sof(struct parser *p, struct log_entry *e,
		       struct frame *frame, int *size)
{
	struct tmb_ctrl_word1 *word1 = (struct tmb_ctrl_word1 *)e;
	struct frame dummy;
	bool sof = false;

	/* If two words in a row has type == CTRL, this is potentionaly SOF */
	if (e->type == TMB_WORD_TYPE_CTRL)
		memcpy(&p->sync_buf[p->sync_slot++], e,
		       sizeof(struct log_entry));
	else
		p->sync_slot = 0;

	if (p->sync_slot != 2)
		return false;

	/* If SOF found */
	if (word1->ms == TMB_MS_MASTER) {
		/* Read or Write with no responce, dump frame */
		if (p->prev_state == STATE_CTRL2_M ||
		    p->prev_state == STATE_CTRL0_S)
			*size = parser_noresp_frame(p, frame);

		parser_flush(p);
		parser_set_state(p, STATE_CTRL0_M);
		parser_step(p, &p->sync_buf[0], &dummy);
		parser_step(p, &p->sync_buf[1], &dummy);
		sof = true;
	}

	p->sync_slot = 0;

	return sof;
}

static int parser_process(struct parser *p, struct log_entry *e,
			  struct frame *frame)
{
	int size = 0;
	int ret;

	ret = parser_sof(p, e, frame, &size);
	if (ret)
		return size;
	else
		return parser_step(p, e, frame);
}

static int parser_step(struct parser *p, struct log_entry *e,
		       struct frame *frame)
{
	struct tmb_ctrl_word0 *word0;
	struct tmb_ctrl_word1 *word1;
	struct frame *f = &p->frame;
	struct frame dummy;
	int ret;

	if (p->idx == sizeof(f->buf))
		parser_flush(p);

	f->buf[p->idx++] = e->word;

	switch (p->state) {
	case STATE_INITIAL:
		break;

	case STATE_CTRL0_M:
		word0 = (struct tmb_ctrl_word0 *)&e->word;

		if (e->type != TMB_WORD_TYPE_CTRL)
			return parser_fault(p);

		f->req_size = word0->size;
		f->op = word0->op;
		parser_set_state(p, STATE_CTRL1_M);

		break;

	case STATE_CTRL1_M:
		word1 = (struct tmb_ctrl_word1 *)&e->word;

		if ((e->type != TMB_WORD_TYPE_CTRL) ||
		    (word1->ms != TMB_MS_MASTER))
			return parser_fault(p);

		f->dev = word1->dev;
		f->page = word1->page;
		f->broadcast = (word1->dev == TMB_ADDR_BROADCAST) ?
			true : false;
		parser_set_state(p, STATE_CTRL2_M);

		break;

	case STATE_CTRL2_M:
		if (e->type != TMB_WORD_TYPE_DATA)
			return parser_fault(p);

		p->cnt = f->req_size;

		if (f->op == TMB_OP_READ)
			parser_set_state(p, STATE_CTRL0_S);
		else
			parser_set_state(p, STATE_DATA);
		break;

	case STATE_CTRL0_S:
		word0 = (struct tmb_ctrl_word0 *)&e->word;

		if (e->type != TMB_WORD_TYPE_CTRL)
			return parser_fault(p);

		parser_set_state(p, STATE_CTRL1_S);
		f->actual_size = word0->size;
		f->ack = word0->ack;

		break;

	case STATE_CTRL1_S:
		if (e->type != TMB_WORD_TYPE_CTRL)
			return parser_fault(p);

		parser_set_state(p, STATE_CTRL2_S);
		break;

	case STATE_CTRL2_S:
		if (e->type != TMB_WORD_TYPE_DATA)
			return parser_fault(p);

		if ((f->op == TMB_OP_WRITE) ||
		    ((f->op == TMB_OP_READ) && !f->ack))
			return parser_dump_frame(p, frame);

		p->cnt = f->actual_size;
		parser_set_state(p, STATE_DATA);

		break;

	case STATE_DATA:
		if (e->type != TMB_WORD_TYPE_DATA)
			return parser_fault(p);

		if (--p->cnt == 0) {
			if ((f->op == TMB_OP_READ) || f->broadcast)
				return parser_dump_frame(p, frame);
			else
				parser_set_state(p, STATE_CTRL0_S);
		}
		break;
	}

	return 0;
}

static void print_raw(struct tmb_log_entry *entry)
{
	printf("[%04u:%04u] word %04x/%04x; type %01u/%01u; par %01u/%01u; dec %01u/%01u; lag %01u/%01u\n",
	       entry->cnt, entry->ts, entry->word1, entry->word2,
	       entry->type1, entry->type2, entry->par1, entry->par2,
	       entry->decode1, entry->decode2, entry->lag1, entry->lag2);
}

static int print_frame(struct app_context *ctx, struct frame *frame)
{
	if (frame->op == TMB_OP_READ)
		printf("%s", "READ ");
	else
		printf("%s", "WRITE ");

	if (frame->broadcast)
		printf("%s", "(BROADCAST) ");
	else if (frame->noresp)
		printf("%s", "(NORESPONCE) ");
	else
		printf("\t");

	if (frame->noresp || frame->broadcast)
		printf("len %d dev 0x%02x:%02d\n",
		       frame->size / 2, frame->dev, frame->page);
	else
		printf("len %d dev 0x%02x:%02d status %s\n",
		       frame->size / 2, frame->dev, frame->page,
		       frame->ack ? "ACKed" : "NACKed");

	if (ctx->hex)
		hex_dump(frame, frame->size, ctx->ascii);

	return 0;
}

static int log_entry_strip(struct tmb_log_entry *tmb_entry,
			   struct log_entry *entry)
{
	entry->word = tmb_entry->word1;
	entry->type = tmb_entry->type1;
	entry->cnt = tmb_entry->cnt;
	entry->ts = tmb_entry->ts;

	return 0;
}

static int process_raw_data(struct app_context *ctx, void *buf, size_t size)
{
	struct tmb_log_entry *entries;
	struct tmb_log_entry *entry;
	struct log_entry entry_stripped;
	struct frame frame;
	int cnt, ret;

	cnt = size / sizeof(struct tmb_log_entry);
	entries = (struct tmb_log_entry *)buf;

	for (int i = 0; i < cnt; i++) {
		entry = &entries[i];

		if (ctx->raw) {
			print_raw(entry);
			continue;
		}

		log_entry_strip(entry, &entry_stripped);

		size = parser_process(&ctx->p, &entry_stripped, &frame);
		if (size < 0) {
			fprintf(stderr, "parse err: %s\n", strerror(size));
			return size;
		}
		if (size > 0) {
			ret = print_frame(ctx, &frame);
			if (ret) {
				fprintf(stderr, "Logger: invalid frame!\n");
				return ret;
			}
		}
	}

	return 0;
}

static int logger(struct app_context *ctx)
{
	struct sockaddr_tmb addr = {0};
	struct parser parser = {0};
	struct tmb_log_entry *entries;
	uint8_t buf[TMB_MTU];
	struct ifreq ifr;
	int sock, ret, size, cnt = 0;

	sock = socket(AF_TMB, SOCK_RAW, TMB_RAW);
	if (sock < 0) {
		fprintf(stderr, "socket creation err (%d)\n", sock);
		return 0;
	}

	strcpy(ifr.ifr_name, ctx->iface);
	ret = ioctl(sock, SIOCGIFINDEX, &ifr);
	if (ret) {
		fprintf(stderr, "ioctl err: %s\n", strerror(errno));
		goto exit;
	}

	addr.family = AF_TMB;
	addr.ifindex = ifr.ifr_ifindex;

	ret = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret) {
		fprintf(stderr, "bind err: %s\n", strerror(errno));
		goto exit;
	}

	ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret) {
		printf("connect err: %s\n", strerror(errno));
		goto exit;
	}

	while(true) {
		size = recv(sock, buf, sizeof(buf), 0);
		if (size < 0) {
			fprintf(stderr, "recv err: %s\n", strerror(errno));
			ret = errno;
			goto exit;
		}
		if (size % sizeof(struct tmb_log_entry)) {
			fprintf(stderr, "recv err: invalid size (%d)\n", size);
			ret = -EMSGSIZE;
			goto exit;
		}

		ret = process_raw_data(ctx, buf, size);
		if (ret)
			goto exit;
	}

exit:
	close(sock);
	return ret;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct app_context *ctx = state->input;

	switch(key) {
	case 'x':
		ctx->hex = true;
		break;
	case 'a':
		ctx->ascii = true;
		break;
	case 'r':
		ctx->raw = true;
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

int main(int argc, char **argv)
{
	struct app_context ctx = {0};
	error_t err;

	/* Off buffered stdout */
	setvbuf(stdout, NULL, _IONBF, 0);

	err = argp_parse(&argp, argc, argv, 0, 0, &ctx);
	if (err)
		return err;

	return logger(&ctx);
}
