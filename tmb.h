// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 Taike Automation Ltd.
 * Definitions for the TMB buf network interface
 */

#ifndef _UAPI_TMB_H
#define _UAPI_TMB_H

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/stddef.h>

/* Definitions of the protocol argument in a socket(AF_TMB, ...) syscall */
#define TMB_RAW			0 /* RAW socket */
#define TMB_PROTO_NUM		1

/* TMB socket options */
#define SOL_TMB_BASE	100
#define SOL_TMB_RAW	(SOL_TMB_BASE + TMB_RAW)

/* Maximum size of payload in transaction (exclude checksum) */
#define TMB_MTU				508

/* Definitions of a socket ioctl cmd's */
#define TMB_IOCTL_MMAP			0
#define TMB_IOCTL_CYCLE_RECV		1

/* Bus word size definitions */
#define TMB_WORD_SIZE			2
#define TMB_TO_SIZE(len)		(len * TMB_WORD_SIZE)
#define TMB_TO_LEN(size)		(size / TMB_WORD_SIZE)

/* Protocol maximum transaction size */
#define TMB_TRANSACTION_MAX_LEN		(3 + 3 + 255)
#define TMB_TRANSACTION_MAX_SIZE	TMB_TO_SIZE(TMB_TRANSACTION_MAX_LEN)

/* Protocol checksum size */
#define TMB_CHECKSUM_LEN		1
#define TMB_CHECKSUM_SIZE		(TMB_CHECKSUM_LEN * TMB_WORD_SIZE)

/* Header word 0 */
#define TMB_DATA_SIZE_MSK	0xFF00
#define TMB_DATA_SIZE_SHF	8
#define TMB_FLAGS_MSK		0x00FF
#define TMB_FLAGS_OP_MSK	0x0001
#define TMB_FLAGS_OP_SHF	0
#define TMB_OP_WRITE		0
#define TMB_OP_READ		1
#define TMB_FLAGS_UNKNOWN_SIZE	(1 << 1)
#define TMB_FLAGS_MON_START	(1 << 2)
#define TMB_FLAGS_MON_STOP	(1 << 3)
#define TMB_FLAGS_ACK		(1 << 7)

/* Header word 1 */
#define TMB_MS_MSK		0x8000
#define TMB_MS_SHF		15
#define TMB_MS_MASTER		0
#define TMB_MS_SLAVE		1
#define TMB_ADDR_MSK		0x7F00
#define TMB_ADDR_SHF		8
#define TMB_AP_MSK		0x00FF
#define TMB_AP_SHF		0

/* Device address */
#define TMB_ADDR_MAX		0x7F
#define TMB_ADDR_MONITOR	0x7E
#define TMB_ADDR_BROADCAST	0x7F

/* Setsockopt options */
enum {
	TMB_RECV_CYCLIC,
	TMB_SET_PERIOD,
};

struct tmb_ctrl_word0 {
	unsigned char op:1;
	unsigned char odp:1;
	unsigned char special:2;
	unsigned char reserved:3;
	unsigned char ack:1;
	unsigned char size;
};

struct tmb_ctrl_word1 {
	unsigned char page;
	unsigned char dev:7;
	unsigned char ms:1;
};

#define TMB_WORD_TYPE_CTRL	0
#define TMB_WORD_TYPE_DATA	1

struct tmb_log_entry {
	unsigned short word1;
	unsigned short word2;
	union {
		unsigned int info;
		struct {
			unsigned int par1:1;
			unsigned int par2:1;
			unsigned int type1:1;
			unsigned int type2:1;
			unsigned int decode1:1;
			unsigned int decode2:1;
			unsigned int lag1:1;
			unsigned int lag2:1;
			unsigned int ts:12;
			unsigned int cnt:12;
		};
	};
};

/**
 *	struct sockaddr_tmb - address of a TMB socket
 *	@family: Protocol family (must be AF_TMB)
 *	@ifindex: Associated network interface index
 *	@addr: Device address
 *	@ap: Address Page index
 */
struct sockaddr_tmb {
	__kernel_sa_family_t family;
	/* The fields below must fit in 14 bytes! */
	unsigned char ifindex;
	unsigned char addr;
	unsigned char ap;
};
#define TMB_SOCKADDR_SIZE	(sizeof(struct sockaddr_tmb))

#endif /* _UAPI_TMB_H */
