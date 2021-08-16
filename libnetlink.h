/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Modified libnetlink.c library for Rust
 * Removed extra functionality (Dumping mostly...)
 *
 */

#ifndef __LIBNETLINK_H__
#define __LIBNETLINK_H__ 1

#include <stdio.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>
#include <linux/neighbour.h>
#include <linux/netconf.h>
#include <arpa/inet.h>

struct rtnl_handle {
	int			fd;
	struct sockaddr_nl	local;
	struct sockaddr_nl	peer;
	__u32			seq;
	__u32			dump;
	int			proto;
#define RTNL_HANDLE_F_LISTEN_ALL_NSID		0x01
#define RTNL_HANDLE_F_SUPPRESS_NLERR		0x02
#define RTNL_HANDLE_F_STRICT_CHK		0x04
	int			flags;
};

struct nlmsg_list {
	struct nlmsg_list *next;
	struct nlmsghdr   h;
};

struct nlmsg_chain {
	struct nlmsg_list *head;
	struct nlmsg_list *tail;
};

int rtnl_open(struct rtnl_handle *rth, unsigned int subscriptions)
	__attribute__((warn_unused_result));

int rtnl_open_byproto(struct rtnl_handle *rth, unsigned int subscriptions,
			     int protocol)
	__attribute__((warn_unused_result));
int rtnl_add_nl_group(struct rtnl_handle *rth, unsigned int group)
	__attribute__((warn_unused_result));
void rtnl_close(struct rtnl_handle *rth);

typedef int (*nl_ext_ack_fn_t)(const char *errmsg, uint32_t off,
			       const struct nlmsghdr *inner_nlh);

int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n,
	      struct nlmsghdr **answer)
	__attribute__((warn_unused_result));
int rtnl_talk_suppress_rtnl_errmsg(struct rtnl_handle *rtnl, struct nlmsghdr *n,
				   struct nlmsghdr **answer)
	__attribute__((warn_unused_result));
int rtnl_send(struct rtnl_handle *rth, const void *buf, int)
	__attribute__((warn_unused_result));
int rtnl_send_check(struct rtnl_handle *rth, const void *buf, int)
	__attribute__((warn_unused_result));
int nl_dump_ext_ack(const struct nlmsghdr *nlh, nl_ext_ack_fn_t errfn);
int nl_dump_ext_ack_done(const struct nlmsghdr *nlh, int error);

int addattr(struct nlmsghdr *n, int maxlen, int type);
int addattr8(struct nlmsghdr *n, int maxlen, int type, __u8 data);
int addattr16(struct nlmsghdr *n, int maxlen, int type, __u16 data);
int addattr32(struct nlmsghdr *n, int maxlen, int type, __u32 data);
int addattr64(struct nlmsghdr *n, int maxlen, int type, __u64 data);
int addattrstrz(struct nlmsghdr *n, int maxlen, int type, const char *data);

int addattr_l(struct nlmsghdr *n, int maxlen, int type,
	      const void *data, int alen);
int addraw_l(struct nlmsghdr *n, int maxlen, const void *data, int len);
struct rtattr *addattr_nest(struct nlmsghdr *n, int maxlen, int type);
int addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest);
struct rtattr *addattr_nest_compat(struct nlmsghdr *n, int maxlen, int type,
				   const void *data, int len);
int addattr_nest_compat_end(struct nlmsghdr *n, struct rtattr *nest);
int rta_addattr8(struct rtattr *rta, int maxlen, int type, __u8 data);
int rta_addattr16(struct rtattr *rta, int maxlen, int type, __u16 data);
int rta_addattr32(struct rtattr *rta, int maxlen, int type, __u32 data);
int rta_addattr64(struct rtattr *rta, int maxlen, int type, __u64 data);
int rta_addattr_l(struct rtattr *rta, int maxlen, int type,
		  const void *data, int alen);

int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len);
int parse_rtattr_flags(struct rtattr *tb[], int max, struct rtattr *rta,
			      int len, unsigned short flags);
struct rtattr *parse_rtattr_one(int type, struct rtattr *rta, int len);
int __parse_rtattr_nested_compat(struct rtattr *tb[], int max, struct rtattr *rta, int len);

struct rtattr *rta_nest(struct rtattr *rta, int maxlen, int type);
int rta_nest_end(struct rtattr *rta, struct rtattr *nest);

#define RTA_TAIL(rta) \
		((struct rtattr *) (((void *) (rta)) + \
				    RTA_ALIGN((rta)->rta_len)))

#define parse_rtattr_nested(tb, max, rta) \
	(parse_rtattr_flags((tb), (max), RTA_DATA(rta), RTA_PAYLOAD(rta), \
			    NLA_F_NESTED))

#define parse_rtattr_one_nested(type, rta) \
	(parse_rtattr_one(type, RTA_DATA(rta), RTA_PAYLOAD(rta)))

#define parse_rtattr_nested_compat(tb, max, rta, data, len) \
	({ data = RTA_PAYLOAD(rta) >= len ? RTA_DATA(rta) : NULL;	\
		__parse_rtattr_nested_compat(tb, max, rta, len); })

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#ifndef IFA_RTA
#define IFA_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ifaddrmsg))))
#endif
#ifndef IFA_PAYLOAD
#define IFA_PAYLOAD(n)	NLMSG_PAYLOAD(n, sizeof(struct ifaddrmsg))
#endif

#ifndef IFLA_RTA
#define IFLA_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))
#endif
#ifndef IFLA_PAYLOAD
#define IFLA_PAYLOAD(n)	NLMSG_PAYLOAD(n, sizeof(struct ifinfomsg))
#endif

#ifndef NDA_RTA
#define NDA_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif
#ifndef NDA_PAYLOAD
#define NDA_PAYLOAD(n)	NLMSG_PAYLOAD(n, sizeof(struct ndmsg))
#endif

#ifndef NDTA_RTA
#define NDTA_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ndtmsg))))
#endif
#ifndef NDTA_PAYLOAD
#define NDTA_PAYLOAD(n) NLMSG_PAYLOAD(n, sizeof(struct ndtmsg))
#endif

#ifndef NETNS_RTA
#define NETNS_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct rtgenmsg))))
#endif
#ifndef NETNS_PAYLOAD
#define NETNS_PAYLOAD(n)	NLMSG_PAYLOAD(n, sizeof(struct rtgenmsg))
#endif

#ifndef IFLA_STATS_RTA
#define IFLA_STATS_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct if_stats_msg))))
#endif

#ifndef BRVLAN_RTA
#define BRVLAN_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct br_vlan_msg))))
#endif

/* User defined nlmsg_type which is used mostly for logging netlink
 * messages from dump file */
#define NLMSG_TSTAMP	15

#define rtattr_for_each_nested(attr, nest) \
	for ((attr) = (void *)RTA_DATA(nest); \
	     RTA_OK(attr, RTA_PAYLOAD(nest) - ((char *)(attr) - (char *)RTA_DATA((nest)))); \
	     (attr) = RTA_TAIL((attr)))

/* For Rust... */
void *nlmsg_data(struct nlmsghdr *n);
void *nlmsg_tail(struct nlmsghdr *n);

__u8 rta_getattr_u8(const struct rtattr *rta);
__u16 rta_getattr_u16(const struct rtattr *rta);
__be16 rta_getattr_be16(const struct rtattr *rta);
__u32 rta_getattr_u32(const struct rtattr *rta);
__be32 rta_getattr_be32(const struct rtattr *rta);
__u64 rta_getattr_u64(const struct rtattr *rta);
__s32 rta_getattr_s32(const struct rtattr *rta);
__s64 rta_getattr_s64(const struct rtattr *rta);
const char *rta_getattr_str(const struct rtattr *rta);

#endif /* __LIBNETLINK_H__ */
