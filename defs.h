#ifndef _DEFS_WRAPPER_H
#define _DEFS_WRAPPER_H

/* Netlink constants and types */
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/* For filter constants */
#include <linux/pkt_cls.h>

/* For action constants */
#include <linux/tc_act/tc_vlan.h>
#include <linux/tc_act/tc_tunnel_key.h>
#include <linux/tc_act/tc_csum.h>
#include <linux/tc_act/tc_gate.h>
#include <linux/tc_act/tc_bpf.h>
#include <linux/tc_act/tc_nat.h>
#include <linux/tc_act/tc_ipt.h>
#include <linux/tc_act/tc_pedit.h>
#include <linux/tc_act/tc_skbedit.h>
#include <linux/tc_act/tc_ctinfo.h>
#include <linux/tc_act/tc_sample.h>
#include <linux/tc_act/tc_mpls.h>
#include <linux/tc_act/tc_gact.h>
#include <linux/tc_act/tc_mirred.h>
#include <linux/tc_act/tc_ife.h>
#include <linux/tc_act/tc_skbmod.h>
#include <linux/tc_act/tc_connmark.h>
#include <linux/tc_act/tc_ct.h>
#include <linux/tc_act/tc_defact.h>

#endif
