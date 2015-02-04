/*
 * KZorp netfilter netlink interface
 *
 * Copyright (C) 2006-2010, BalaBit IT Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#ifndef _KZORP_NETLINK_H
#define _KZORP_NETLINK_H

#include <linux/types.h>
#include "kzorp_internal.h"

typedef char ifname_t[IFNAMSIZ];

enum kznl_msg_types {
	KZNL_MSG_INVALID,
#define DEFINE_kznl_msg_type(NL_MSG_NAME, RECV_FUNC, DUMP_FUNC, ...) \
	KZNL_MSG_##NL_MSG_NAME,

	KZORP_MSG_LIST(DEFINE_kznl_msg_type, )

#undef DEFINE_kznl_msg_type
	KZNL_MSG_TYPE_COUNT
};

enum kznl_attr_types {
	KZNL_ATTR_INVALID,
	KZNL_ATTR_INSTANCE_NAME,
	KZNL_ATTR_ZONE_NAME,
	KZNL_ATTR_ZONE_UNAME,
	KZNL_ATTR_ZONE_PNAME,
	KZNL_ATTR_ZONE_RANGE,
	KZNL_ATTR_SERVICE_PARAMS,
	KZNL_ATTR_SERVICE_NAME,
	KZNL_ATTR_SERVICE_ROUTER_DST_ADDR,
	KZNL_ATTR_SERVICE_NAT_SRC,
	KZNL_ATTR_SERVICE_NAT_DST,
	KZNL_ATTR_SERVICE_NAT_MAP,
	KZNL_ATTR_SERVICE_SESSION_CNT,
	KZNL_ATTR_DISPATCHER_NAME,
	KZNL_ATTR_QUERY_PARAMS,
	KZNL_ATTR_QUERY_REPLY_CLIENT_ZONE,
	KZNL_ATTR_QUERY_REPLY_SERVER_ZONE,
	KZNL_ATTR_DISPATCHER_N_DIMENSION_PARAMS,
	KZNL_ATTR_N_DIMENSION_RULE_ID,
	KZNL_ATTR_N_DIMENSION_RULE_SERVICE,
	KZNL_ATTR_N_DIMENSION_IFACE,
	KZNL_ATTR_N_DIMENSION_PROTO,
	KZNL_ATTR_N_DIMENSION_SRC_PORT,
	KZNL_ATTR_N_DIMENSION_DST_PORT,
	KZNL_ATTR_N_DIMENSION_SRC_IP,
	KZNL_ATTR_N_DIMENSION_SRC_ZONE,
	KZNL_ATTR_N_DIMENSION_DST_IP,
	KZNL_ATTR_N_DIMENSION_DST_ZONE,
	KZNL_ATTR_N_DIMENSION_IFGROUP,
	KZNL_ATTR_CONFIG_COOKIE,
	KZNL_ATTR_INET_ADDR,
	KZNL_ATTR_INET_SUBNET,
	KZNL_ATTR_INET6_ADDR,
	KZNL_ATTR_INET6_SUBNET,
	KZNL_ATTR_N_DIMENSION_SRC_IP6,
	KZNL_ATTR_N_DIMENSION_DST_IP6,
	KZNL_ATTR_QUERY_PARAMS_SRC_IP,
	KZNL_ATTR_QUERY_PARAMS_DST_IP,
	KZNL_ATTR_SERVICE_ROUTER_DST_PORT,
	KZNL_ATTR_BIND_ADDR,
	KZNL_ATTR_BIND_PORT,
	KZNL_ATTR_BIND_PROTO,
	KZNL_ATTR_MAJOR_VERSION,
	KZNL_ATTR_COMPAT_VERSION,
	KZNL_ATTR_SERVICE_DENY_IPV4_METHOD,
	KZNL_ATTR_SERVICE_DENY_IPV6_METHOD,
	KZNL_ATTR_N_DIMENSION_DST_IFACE,
	KZNL_ATTR_N_DIMENSION_DST_IFGROUP,
	KZNL_ATTR_N_DIMENSION_REQID,
	KZNL_ATTR_QUERY_PARAMS_REQID,
	KZNL_ATTR_N_DIMENSION_PROTO_TYPE,
	KZNL_ATTR_N_DIMENSION_PROTO_SUBTYPE,
	KZNL_ATTR_QUERY_PARAMS_SRC_PORT,
	KZNL_ATTR_QUERY_PARAMS_DST_PORT,
	KZNL_ATTR_QUERY_PARAMS_PROTO_TYPE,
	KZNL_ATTR_QUERY_PARAMS_PROTO_SUBTYPE,
	KZNL_ATTR_ZONE_SUBNET,
	KZNL_ATTR_ZONE_SUBNET_NUM,
	KZNL_ATTR_ZONE_IP,
	KZNL_ATTR_ACCOUNTING_COUNTER_NUM,
	KZNL_ATTR_TYPE_COUNT
};

#define KZ_ATTR_NAME_MAX_LENGTH 1023

/* global instance name */
#define KZ_INSTANCE_GLOBAL ".global"
#define KZ_INSTANCE_GLOBAL_STRLEN 7

/* generic attributes */
struct kza_name {
	__be16 length;
	char name[0];
} __attribute__ ((packed));

struct kza_port_range {
	__be16 from;
	__be16 to;
} __attribute__ ((packed));

/* service attributes */
enum kz_service_type {
	KZ_SERVICE_INVALID,
	KZ_SERVICE_PROXY,
	KZ_SERVICE_FORWARD,
	KZ_SERVICE_DENY,
	KZ_SERVICE_TYPE_COUNT
};

enum kzf_service_params_flags {
	KZF_SERVICE_TRANSPARENT  = 1 << 0,
	KZF_SERVICE_FORGE_ADDR   = 1 << 1,
	KZF_SERVICE_LOGGING      = 1 << 2,
	KZF_SERVICE_PUBLIC_FLAGS = KZF_SERVICE_TRANSPARENT |
				   KZF_SERVICE_FORGE_ADDR |
				   KZF_SERVICE_LOGGING
};

struct kza_service_params {
	__be32 flags;
	__u8 type;
} __attribute__ ((packed));

enum kzf_service_nat_params_flags {
	KZF_SERVICE_NAT_MAP_IPS		   = 1 << 0,
	KZF_SERVICE_NAT_MAP_PROTO_SPECIFIC = 1 << 1,
	KZF_SERVICE_NAT_MAP_PUBLIC_FLAGS   = KZF_SERVICE_NAT_MAP_IPS |
					     KZF_SERVICE_NAT_MAP_PROTO_SPECIFIC
};

struct kza_service_nat_params {
	__be32 flags;
	__be32 min_ip, max_ip;
	__be16 min_port, max_port;
} __attribute__ ((packed));

struct kza_service_session_cnt {
	__be64 count;
} __attribute__ ((packed));

enum kz_service_ipv4_deny_method {
	KZ_SERVICE_DENY_METHOD_V4_DROP,
	KZ_SERVICE_DENY_METHOD_V4_TCP_RESET,
	KZ_SERVICE_DENY_METHOD_ICMP_NET_UNREACHABLE,
	KZ_SERVICE_DENY_METHOD_ICMP_HOST_UNREACHABLE,
	KZ_SERVICE_DENY_METHOD_ICMP_PROTO_UNREACHABLE,
	KZ_SERVICE_DENY_METHOD_ICMP_PORT_UNREACHABLE,
	KZ_SERVICE_DENY_METHOD_ICMP_NET_PROHIBITED,
	KZ_SERVICE_DENY_METHOD_ICMP_HOST_PROHIBITED,
	KZ_SERVICE_DENY_METHOD_ICMP_ADMIN_PROHIBITED,
	KZ_SERVICE_DENY_METHOD_V4_COUNT
};

enum kz_service_ipv6_deny_method {
	KZ_SERVICE_DENY_METHOD_V6_DROP,
	KZ_SERVICE_DENY_METHOD_V6_TCP_RESET,
	KZ_SERVICE_DENY_METHOD_ICMPV6_NO_ROUTE,
	KZ_SERVICE_DENY_METHOD_ICMPV6_ADMIN_PROHIBITED,
	KZ_SERVICE_DENY_METHOD_ICMPV6_ADDR_UNREACHABLE,
	KZ_SERVICE_DENY_METHOD_ICMPV6_PORT_UNREACHABLE,
	KZ_SERVICE_DENY_METHOD_V6_COUNT
};

struct kza_dispatcher_n_dimension_params {
	__be32 num_rules;
} __attribute__ ((packed));

struct kza_n_dimension_rule_params {
	__be32 id;
} __attribute__ ((packed));

struct kza_query_params {
	char ifname[IFNAMSIZ];
	__u8 proto;
} __attribute__ ((packed));

#endif
