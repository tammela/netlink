/*
 * libnetlink.c	RTnetlink service routines.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 */

/*
 * Modified libnetlink.c library for Rust
 * Removed extra functionality (Dumping mostly...)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/uio.h>
#include <linux/fib_rules.h>
#include <linux/if_addrlabel.h>
#include <linux/if_bridge.h>
#include <linux/nexthop.h>

#include "libnetlink.h"

#ifndef __aligned
#define __aligned(x)		__attribute__((aligned(x)))
#endif

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#include <libmnl/libmnl.h>

static const enum mnl_attr_data_type extack_policy[NLMSGERR_ATTR_MAX + 1] = {
	[NLMSGERR_ATTR_MSG]	= MNL_TYPE_NUL_STRING,
	[NLMSGERR_ATTR_OFFS]	= MNL_TYPE_U32,
};

static int err_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	uint16_t type;

	if (mnl_attr_type_valid(attr, NLMSGERR_ATTR_MAX) < 0) {
		fprintf(stderr, "Invalid extack attribute\n");
		return MNL_CB_ERROR;
	}

	type = mnl_attr_get_type(attr);
	if (mnl_attr_validate(attr, extack_policy[type]) < 0) {
		fprintf(stderr, "extack attribute %d failed validation\n",
			type);
		return MNL_CB_ERROR;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void print_ext_ack_msg(bool is_err, const char *msg)
{
	fprintf(stderr, "%s: %s", is_err ? "Error" : "Warning", msg);
	if (msg[strlen(msg) - 1] != '.')
		fprintf(stderr, ".");
	fprintf(stderr, "\n");
}

/* dump netlink extended ack error message */
int nl_dump_ext_ack(const struct nlmsghdr *nlh, nl_ext_ack_fn_t errfn)
{
	struct nlattr *tb[NLMSGERR_ATTR_MAX + 1] = {};
	const struct nlmsgerr *err = mnl_nlmsg_get_payload(nlh);
	const struct nlmsghdr *err_nlh = NULL;
	unsigned int hlen = sizeof(*err);
	const char *msg = NULL;
	uint32_t off = 0;

	/* no TLVs, nothing to do here */
	if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS))
		return 0;

	/* if NLM_F_CAPPED is set then the inner err msg was capped */
	if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
		hlen += mnl_nlmsg_get_payload_len(&err->msg);

	if (mnl_attr_parse(nlh, hlen, err_attr_cb, tb) != MNL_CB_OK)
		return 0;

	if (tb[NLMSGERR_ATTR_MSG])
		msg = mnl_attr_get_str(tb[NLMSGERR_ATTR_MSG]);

	if (tb[NLMSGERR_ATTR_OFFS]) {
		off = mnl_attr_get_u32(tb[NLMSGERR_ATTR_OFFS]);

		if (off > nlh->nlmsg_len) {
			fprintf(stderr,
				"Invalid offset for NLMSGERR_ATTR_OFFS\n");
			off = 0;
		} else if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
			err_nlh = &err->msg;
	}

	if (errfn)
		return errfn(msg, off, err_nlh);

	if (msg && *msg != '\0') {
		bool is_err = !!err->error;

		print_ext_ack_msg(is_err, msg);
		return is_err ? 1 : 0;
	}

	return 0;
}

int nl_dump_ext_ack_done(const struct nlmsghdr *nlh, int error)
{
	struct nlattr *tb[NLMSGERR_ATTR_MAX + 1] = {};
	unsigned int hlen = sizeof(int);
	const char *msg = NULL;

	if (mnl_attr_parse(nlh, hlen, err_attr_cb, tb) != MNL_CB_OK)
		return 0;

	if (tb[NLMSGERR_ATTR_MSG])
		msg = mnl_attr_get_str(tb[NLMSGERR_ATTR_MSG]);

	if (msg && *msg != '\0') {
		bool is_err = !!error;

		print_ext_ack_msg(is_err, msg);
		return is_err ? 1 : 0;
	}

	return 0;
}

int rtnl_add_nl_group(struct rtnl_handle *rth, unsigned int group)
{
	return setsockopt(rth->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
			  &group, sizeof(group));
}

void rtnl_close(struct rtnl_handle *rth)
{
	if (rth->fd >= 0) {
		close(rth->fd);
		rth->fd = -1;
	}
}

int rtnl_open_byproto(struct rtnl_handle *rth, unsigned int subscriptions,
		      int protocol)
{
	socklen_t addr_len;
	int bufsz = 32768;
	int one = 1;

	memset(rth, 0, sizeof(*rth));

	rth->proto = protocol;
	rth->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, protocol);
	if (rth->fd < 0) {
		perror("Cannot open netlink socket");
		return -1;
	}

	if (setsockopt(rth->fd, SOL_SOCKET, SO_SNDBUF,
		       &bufsz, sizeof(bufsz)) < 0) {
		perror("SO_SNDBUF");
		return -1;
	}

	if (setsockopt(rth->fd, SOL_SOCKET, SO_RCVBUF,
		       &bufsz, sizeof(bufsz)) < 0) {
		perror("SO_RCVBUF");
		return -1;
	}

	/* Older kernels may no support extended ACK reporting */
	setsockopt(rth->fd, SOL_NETLINK, NETLINK_EXT_ACK,
		   &one, sizeof(one));

	memset(&rth->local, 0, sizeof(rth->local));
	rth->local.nl_family = AF_NETLINK;
	rth->local.nl_groups = subscriptions;

	if (bind(rth->fd, (struct sockaddr *)&rth->local,
		 sizeof(rth->local)) < 0) {
		perror("Cannot bind netlink socket");
		return -1;
	}
	addr_len = sizeof(rth->local);
	if (getsockname(rth->fd, (struct sockaddr *)&rth->local,
			&addr_len) < 0) {
		perror("Cannot getsockname");
		return -1;
	}
	if (addr_len != sizeof(rth->local)) {
		fprintf(stderr, "Wrong address length %d\n", addr_len);
		return -1;
	}
	if (rth->local.nl_family != AF_NETLINK) {
		fprintf(stderr, "Wrong address family %d\n",
			rth->local.nl_family);
		return -1;
	}
	rth->seq = time(NULL);
	return 0;
}

int rtnl_open(struct rtnl_handle *rth, unsigned int subscriptions)
{
	return rtnl_open_byproto(rth, subscriptions, NETLINK_ROUTE);
}

int rtnl_send(struct rtnl_handle *rth, const void *buf, int len)
{
	return send(rth->fd, buf, len, 0);
}

int rtnl_send_check(struct rtnl_handle *rth, const void *buf, int len)
{
	struct nlmsghdr *h;
	int status;
	char resp[1024];

	status = send(rth->fd, buf, len, 0);
	if (status < 0)
		return status;

	/* Check for immediate errors */
	status = recv(rth->fd, resp, sizeof(resp), MSG_DONTWAIT|MSG_PEEK);
	if (status < 0) {
		if (errno == EAGAIN)
			return 0;
		return -1;
	}

	for (h = (struct nlmsghdr *)resp; NLMSG_OK(h, status);
	     h = NLMSG_NEXT(h, status)) {
		if (h->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);

			if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
				fprintf(stderr, "ERROR truncated\n");
			else
				errno = -err->error;
			return -1;
		}
	}

	return 0;
}

static int __rtnl_recvmsg(int fd, struct msghdr *msg, int flags)
{
	int len;

	do {
		len = recvmsg(fd, msg, flags);
	} while (len < 0 && (errno == EINTR || errno == EAGAIN));

	if (len < 0) {
		fprintf(stderr, "netlink receive error %s (%d)\n",
			strerror(errno), errno);
		return -errno;
	}

	if (len == 0) {
		fprintf(stderr, "EOF on netlink\n");
		return -ENODATA;
	}

	return len;
}

static int rtnl_recvmsg(int fd, struct msghdr *msg, char **answer)
{
	struct iovec *iov = msg->msg_iov;
	char *buf;
	int len;

	iov->iov_base = NULL;
	iov->iov_len = 0;

	len = __rtnl_recvmsg(fd, msg, MSG_PEEK | MSG_TRUNC);
	if (len < 0)
		return len;

	if (len < 32768)
		len = 32768;
	buf = malloc(len);
	if (!buf) {
		fprintf(stderr, "malloc error: not enough buffer\n");
		return -ENOMEM;
	}

	iov->iov_base = buf;
	iov->iov_len = len;

	len = __rtnl_recvmsg(fd, msg, 0);
	if (len < 0) {
		free(buf);
		return len;
	}

	if (answer)
		*answer = buf;
	else
		free(buf);

	return len;
}

/* Don't bother peeking and allocating a huge chunk */
static int rtnl_recvmsg_fast(int fd, struct msghdr *msg, char *buf, int sz)
{
	struct iovec *iov = msg->msg_iov;
	int len;

	iov->iov_base = buf;
	iov->iov_len = sz;

	len = __rtnl_recvmsg(fd, msg, 0);
	if (len < 0) {
		return len;
	}

	return len;
}

static void rtnl_talk_error(struct nlmsghdr *h, struct nlmsgerr *err,
			    nl_ext_ack_fn_t errfn)
{
	if (nl_dump_ext_ack(h, errfn))
		return;

	fprintf(stderr, "RTNETLINK answers: %s\n",
		strerror(-err->error));
}


static int __rtnl_talk_iov(struct rtnl_handle *rtnl, struct iovec *iov,
			   size_t iovlen, struct nlmsghdr **answer,
			   bool show_rtnl_err, nl_ext_ack_fn_t errfn)
{
	struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
	struct iovec riov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = iov,
		.msg_iovlen = iovlen,
	};
	unsigned int seq = 0;
        bool fast = *answer == NULL;
        char fastbuf[1024] = {0};
	struct nlmsghdr *h;
	int i, status;
	char *buf;

	for (i = 0; i < iovlen; i++) {
		h = iov[i].iov_base;
		h->nlmsg_seq = seq = ++rtnl->seq;
		if (answer == NULL)
			h->nlmsg_flags |= NLM_F_ACK;
	}

	status = sendmsg(rtnl->fd, &msg, 0);
	if (status < 0) {
		perror("Cannot talk to rtnetlink");
		return -1;
	}

	/* change msg to use the response iov */
	msg.msg_iov = &riov;
	msg.msg_iovlen = 1;
	i = 0;
	while (1) {
next:
                if (!fast) {
                   status = rtnl_recvmsg(rtnl->fd, &msg, &buf);
                } else {
                   status = rtnl_recvmsg_fast(rtnl->fd, &msg, &fastbuf, sizeof(fastbuf));
                   buf = &fastbuf;
                }
		++i;

		if (status < 0)
			return status;

		if (msg.msg_namelen != sizeof(nladdr)) {
			fprintf(stderr,
				"sender address length == %d\n",
				msg.msg_namelen);
			exit(1);
		}
		for (h = (struct nlmsghdr *)buf; status >= sizeof(*h); ) {
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);

			if (l < 0 || len > status) {
				if (msg.msg_flags & MSG_TRUNC) {
					fprintf(stderr, "Truncated message\n");
					if (!fast) free(buf);
					return -1;
				}
				fprintf(stderr,
					"!!!malformed message: len=%d\n",
					len);
				exit(1);
			}

			if (nladdr.nl_pid != 0 ||
			    h->nlmsg_pid != rtnl->local.nl_pid ||
			    h->nlmsg_seq > seq || h->nlmsg_seq < seq - iovlen) {
				/* Don't forget to skip that message. */
				status -= NLMSG_ALIGN(len);
				h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
				continue;
			}

			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);
				int error = err->error;

				if (l < sizeof(struct nlmsgerr)) {
					fprintf(stderr, "ERROR truncated\n");
					if (!fast) free(buf);
					return -1;
				}

				if (!error) {
					/* check messages from kernel */
					nl_dump_ext_ack(h, errfn);
				} else {
					errno = -error;

					if (rtnl->proto != NETLINK_SOCK_DIAG &&
					    show_rtnl_err)
						rtnl_talk_error(h, err, errfn);
				}

				if (answer)
					*answer = (struct nlmsghdr *)buf;

				if (i < iovlen)
					goto next;
				return error ? -i : 0;
			}

			if (answer) {
				*answer = (struct nlmsghdr *)buf;
				return 0;
			}

			fprintf(stderr, "Unexpected reply!!!\n");

			status -= NLMSG_ALIGN(len);
			h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
		}

		if (msg.msg_flags & MSG_TRUNC) {
			fprintf(stderr, "Message truncated\n");
			continue;
		}

		if (status) {
			fprintf(stderr, "!!!Remnant of size %d\n", status);
			exit(1);
		}
	}
}

static int __rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n,
		       struct nlmsghdr **answer,
		       bool show_rtnl_err, nl_ext_ack_fn_t errfn)
{
	struct iovec iov = {
		.iov_base = n,
		.iov_len = n->nlmsg_len
	};

	return __rtnl_talk_iov(rtnl, &iov, 1, answer, show_rtnl_err, errfn);
}

int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n,
	      struct nlmsghdr **answer)
{
	return __rtnl_talk(rtnl, n, answer, true, NULL);
}

int rtnl_talk_iov(struct rtnl_handle *rtnl, struct iovec *iovec, size_t iovlen,
		  struct nlmsghdr **answer)
{
	return __rtnl_talk_iov(rtnl, iovec, iovlen, answer, true, NULL);
}

int rtnl_talk_suppress_rtnl_errmsg(struct rtnl_handle *rtnl, struct nlmsghdr *n,
				   struct nlmsghdr **answer)
{
	return __rtnl_talk(rtnl, n, answer, false, NULL);
}

int addattr(struct nlmsghdr *n, int maxlen, int type)
{
	return addattr_l(n, maxlen, type, NULL, 0);
}

int addattr8(struct nlmsghdr *n, int maxlen, int type, __u8 data)
{
	return addattr_l(n, maxlen, type, &data, sizeof(__u8));
}

int addattr16(struct nlmsghdr *n, int maxlen, int type, __u16 data)
{
	return addattr_l(n, maxlen, type, &data, sizeof(__u16));
}

int addattr32(struct nlmsghdr *n, int maxlen, int type, __u32 data)
{
	return addattr_l(n, maxlen, type, &data, sizeof(__u32));
}

int addattr64(struct nlmsghdr *n, int maxlen, int type, __u64 data)
{
	return addattr_l(n, maxlen, type, &data, sizeof(__u64));
}

int addattrstrz(struct nlmsghdr *n, int maxlen, int type, const char *str)
{
	return addattr_l(n, maxlen, type, str, strlen(str)+1);
}

int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
	      int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		fprintf(stderr,
			"addattr_l ERROR: message exceeded bound of %d\n",
			maxlen);
		return -1;
	}
	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	if (alen)
		memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return 0;
}

int addraw_l(struct nlmsghdr *n, int maxlen, const void *data, int len)
{
	if (NLMSG_ALIGN(n->nlmsg_len) + NLMSG_ALIGN(len) > maxlen) {
		fprintf(stderr,
			"addraw_l ERROR: message exceeded bound of %d\n",
			maxlen);
		return -1;
	}

	memcpy(NLMSG_TAIL(n), data, len);
	memset((void *) NLMSG_TAIL(n) + len, 0, NLMSG_ALIGN(len) - len);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + NLMSG_ALIGN(len);
	return 0;
}

struct rtattr *addattr_nest(struct nlmsghdr *n, int maxlen, int type)
{
	struct rtattr *nest = NLMSG_TAIL(n);

	addattr_l(n, maxlen, type, NULL, 0);
	return nest;
}

int addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
	nest->rta_len = (void *)NLMSG_TAIL(n) - (void *)nest;
	return n->nlmsg_len;
}

struct rtattr *addattr_nest_compat(struct nlmsghdr *n, int maxlen, int type,
				   const void *data, int len)
{
	struct rtattr *start = NLMSG_TAIL(n);

	addattr_l(n, maxlen, type, data, len);
	addattr_nest(n, maxlen, type);
	return start;
}

int addattr_nest_compat_end(struct nlmsghdr *n, struct rtattr *start)
{
	struct rtattr *nest = (void *)start + NLMSG_ALIGN(start->rta_len);

	start->rta_len = (void *)NLMSG_TAIL(n) - (void *)start;
	addattr_nest_end(n, nest);
	return n->nlmsg_len;
}

int rta_addattr32(struct rtattr *rta, int maxlen, int type, __u32 data)
{
	int len = RTA_LENGTH(4);
	struct rtattr *subrta;

	if (RTA_ALIGN(rta->rta_len) + len > maxlen) {
		fprintf(stderr,
			"rta_addattr32: Error! max allowed bound %d exceeded\n",
			maxlen);
		return -1;
	}
	subrta = (struct rtattr *)(((char *)rta) + RTA_ALIGN(rta->rta_len));
	subrta->rta_type = type;
	subrta->rta_len = len;
	memcpy(RTA_DATA(subrta), &data, 4);
	rta->rta_len = NLMSG_ALIGN(rta->rta_len) + len;
	return 0;
}

int rta_addattr_l(struct rtattr *rta, int maxlen, int type,
		  const void *data, int alen)
{
	struct rtattr *subrta;
	int len = RTA_LENGTH(alen);

	if (RTA_ALIGN(rta->rta_len) + RTA_ALIGN(len) > maxlen) {
		fprintf(stderr,
			"rta_addattr_l: Error! max allowed bound %d exceeded\n",
			maxlen);
		return -1;
	}
	subrta = (struct rtattr *)(((char *)rta) + RTA_ALIGN(rta->rta_len));
	subrta->rta_type = type;
	subrta->rta_len = len;
	if (alen)
		memcpy(RTA_DATA(subrta), data, alen);
	rta->rta_len = NLMSG_ALIGN(rta->rta_len) + RTA_ALIGN(len);
	return 0;
}

int rta_addattr8(struct rtattr *rta, int maxlen, int type, __u8 data)
{
	return rta_addattr_l(rta, maxlen, type, &data, sizeof(__u8));
}

int rta_addattr16(struct rtattr *rta, int maxlen, int type, __u16 data)
{
	return rta_addattr_l(rta, maxlen, type, &data, sizeof(__u16));
}

int rta_addattr64(struct rtattr *rta, int maxlen, int type, __u64 data)
{
	return rta_addattr_l(rta, maxlen, type, &data, sizeof(__u64));
}

struct rtattr *rta_nest(struct rtattr *rta, int maxlen, int type)
{
	struct rtattr *nest = RTA_TAIL(rta);

	rta_addattr_l(rta, maxlen, type, NULL, 0);
	nest->rta_type |= NLA_F_NESTED;

	return nest;
}

int rta_nest_end(struct rtattr *rta, struct rtattr *nest)
{
	nest->rta_len = (void *)RTA_TAIL(rta) - (void *)nest;

	return rta->rta_len;
}

int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	return parse_rtattr_flags(tb, max, rta, len, 0);
}

int parse_rtattr_flags(struct rtattr *tb[], int max, struct rtattr *rta,
		       int len, unsigned short flags)
{
	unsigned short type;

	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		type = rta->rta_type & ~flags;
		if ((type <= max) && (!tb[type]))
			tb[type] = rta;
		rta = RTA_NEXT(rta, len);
	}
	if (len)
		fprintf(stderr, "!!!Deficit %d, rta_len=%d\n",
			len, rta->rta_len);
	return 0;
}

struct rtattr *parse_rtattr_one(int type, struct rtattr *rta, int len)
{
	while (RTA_OK(rta, len)) {
		if (rta->rta_type == type)
			return rta;
		rta = RTA_NEXT(rta, len);
	}

	if (len)
		fprintf(stderr, "!!!Deficit %d, rta_len=%d\n",
			len, rta->rta_len);
	return NULL;
}

int __parse_rtattr_nested_compat(struct rtattr *tb[], int max,
				 struct rtattr *rta,
				 int len)
{
	if (RTA_PAYLOAD(rta) < len)
		return -1;
	if (RTA_PAYLOAD(rta) >= RTA_ALIGN(len) + sizeof(struct rtattr)) {
		rta = RTA_DATA(rta) + RTA_ALIGN(len);
		return parse_rtattr_nested(tb, max, rta);
	}
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	return 0;
}

/* For Rust... */
void *nlmsg_data(struct nlmsghdr *n)
{
   return NLMSG_DATA(n);
}

void *nlmsg_tail(struct nlmsghdr *n)
{
   return NLMSG_TAIL(n);
}

__u8 rta_getattr_u8(const struct rtattr *rta)
{
	return *(__u8 *)RTA_DATA(rta);
}
__u16 rta_getattr_u16(const struct rtattr *rta)
{
	return *(__u16 *)RTA_DATA(rta);
}
__be16 rta_getattr_be16(const struct rtattr *rta)
{
	return ntohs(rta_getattr_u16(rta));
}
__u32 rta_getattr_u32(const struct rtattr *rta)
{
	return *(__u32 *)RTA_DATA(rta);
}
__be32 rta_getattr_be32(const struct rtattr *rta)
{
	return ntohl(rta_getattr_u32(rta));
}
__u64 rta_getattr_u64(const struct rtattr *rta)
{
	__u64 tmp;

	memcpy(&tmp, RTA_DATA(rta), sizeof(__u64));
	return tmp;
}
__s32 rta_getattr_s32(const struct rtattr *rta)
{
	return *(__s32 *)RTA_DATA(rta);
}
__s64 rta_getattr_s64(const struct rtattr *rta)
{
	__s64 tmp;

	memcpy(&tmp, RTA_DATA(rta), sizeof(tmp));
	return tmp;
}
const char *rta_getattr_str(const struct rtattr *rta)
{
	return (const char *)RTA_DATA(rta);
}
