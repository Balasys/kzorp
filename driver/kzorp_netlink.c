/*
 * KZorp netlink interface
 *
 * Copyright (C) 2006-2010, BalaBit IT Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/notifier.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/proc_fs.h>
#include "kzorp_netlink.h"
#include "kzorp.h"

#include <net/ipv6.h>
#include <net/sock.h>
#include <net/genetlink.h>

#define list_nth(pos, head, member, n) \
	list_for_each_entry(pos, head, member) { \
		if (n-- == 0) \
			break; \
	}

#define list_find_or_first(pos, head, member, elem) \
	{ \
		list_for_each_entry(pos, head, member) { \
			if (pos == elem) \
				break; \
		} \
		if (&pos->member == head) \
			pos = list_first_entry(head, typeof(*(pos)), member); \
	}

/***********************************************************
 * Transactions
 ***********************************************************/

/* we have at most 1 transaction running at the same time */
/* the config only changes through transaction; when we start one,
   we can store pointer to the config and assume it stable till closed

   if that changes, refcount or rcu lock must be applied to kz_transaction->cfg !

*/
static struct kz_transaction transaction;
static bool transaction_open = 0;

static void __init
transaction_init(void)
{
	memset(&transaction, 0, sizeof(transaction));
	INIT_LIST_HEAD(&transaction.op);
	transaction_open = 0;
}

/* !!! must be called with the transaction mutex held !!! */
inline static struct kz_transaction *
transaction_lookup(int peer_pid)
{
	if (transaction_open && transaction.peer_pid == peer_pid)
		return &transaction;
	else
		return NULL;
}

/* !!! must be called with the transaction mutex held !!! */
static struct kz_transaction *
transaction_create(const netlink_port_t peer_pid, const unsigned int instance_id, u_int64_t config_cookie)
{
	pr_debug("pid='%d', instance_id='%d', config_cookie='%llu'\n",
		 peer_pid, instance_id, config_cookie);

	if (transaction_open) {
		pr_err_ratelimited("transaction already exists;\n");
		return NULL;
	}

	transaction_open = 1;
	transaction.instance_id = instance_id;
	transaction.peer_pid = peer_pid;
	transaction.flags = 0;
	transaction.cookie = config_cookie;
	transaction.cfg = kz_config_rcu; /* lock and protocol ensures no rcu_lock needed */

	return &transaction;
}

static void transaction_cleanup_op(struct kz_transaction *);

/* !!! must be called with the transaction mutex held !!! */
static void
transaction_destroy(struct kz_transaction *t)
{
	pr_debug("instance_id='%d' peer_id='%d'\n", t->instance_id, t->peer_pid);

	BUG_ON(t != &transaction);

	transaction_cleanup_op(t);

	BUG_ON(!list_empty(&t->op));

	transaction_open = 0;
}

/***********************************************************
 * Transaction operations
 ***********************************************************/

/* caller must mutex the passed transaction! */
static int
transaction_add_op(struct kz_transaction *tr,
		   enum kznl_op_data_type type,
		   void * const data,
		   void (*cleanup_func)(void *))
{
	struct kz_operation *o;

	o = kzalloc(sizeof(struct kz_operation), GFP_KERNEL);
	if (o == NULL) {
		if (cleanup_func && data)
			cleanup_func(data);
		return -ENOMEM;
	}

	o->type = type;
	o->data = data;
	o->data_destroy = cleanup_func;
	list_add(&o->list, &tr->op);
	pr_debug("add op; type='%d'\n", type);

	return 0;
}

/* cleanup functions passed */
static void
transaction_destroy_zone(void *data)
{
	kz_zone_put((struct kz_zone *)data);
}

static void
transaction_destroy_service(void *data)
{
	kz_service_put((struct kz_service *)data);
}

static void
transaction_destroy_dispatcher(void *data)
{
	kz_dispatcher_put((struct kz_dispatcher *)data);
}

static void
transaction_destroy_bind(void *data)
{
	kz_bind_destroy((struct kz_bind *)data);
}

static inline void
kz_operation_remove(struct kz_operation *operation)
{
	list_del(&operation->list);

	if (operation->data && operation->data_destroy)
		operation->data_destroy(operation->data);

	kfree(operation);
}

/* caller must mutex the passed transaction! */
static void
transaction_cleanup_op(struct kz_transaction *tr)
{
	struct kz_operation *o, *p;

	list_for_each_entry_safe(o, p, &tr->op, list) {
		kz_operation_remove(o);
	}
}

/* caller must mutex the passed transaction! */
static struct kz_zone *
transaction_zone_lookup(const struct kz_transaction * const tr,
			const char *name)
{
	const struct kz_operation *i;

	list_for_each_entry(i, &tr->op, list) {
		if (i->type == KZNL_OP_ADD_ZONE) {
			struct kz_zone *z = (struct kz_zone *)i->data;

			if (strcmp(z->name, name) == 0)
				return z;
		}
	}

	return NULL;
}

/* caller must mutex the passed transaction! */
static struct kz_service *
transaction_service_lookup(const struct kz_transaction * const tr,
			   const char *name)
{
	const struct kz_operation *i;

	list_for_each_entry(i, &tr->op, list) {
		if (i->type == KZNL_OP_ADD_SERVICE) {
			struct kz_service *s = (struct kz_service *)i->data;

			if (strcmp(s->name, name) == 0)
				return s;
		}
	}

	return NULL;
}

/* caller must mutex the passed transaction! */
static struct kz_dispatcher *
transaction_dispatcher_lookup(const struct kz_transaction * const tr,
			   const char *name)
{
	const struct kz_operation *i;

	list_for_each_entry(i, &tr->op, list) {
		if (i->type == KZNL_OP_ADD_DISPATCHER) {
			struct kz_dispatcher *d = (struct kz_dispatcher *)i->data;

			if (strcmp(d->name, name) == 0)
				return d;
		}
	}

	return NULL;
}

static inline bool
kz_bind_eq(const struct kz_bind * const a, const struct kz_bind * const b)
{
	return (a->port == b->port &&
		a->proto == b->proto &&
		a->family == b->family &&
		nf_inet_addr_cmp(&a->addr, &b->addr));
}

/* !!! must be called with the instance mutex held !!! */
static struct kz_bind *
transaction_bind_lookup(const struct kz_transaction * const tr,
			const struct kz_bind *bind)
{
	const struct kz_operation *i;

	kz_bind_debug(bind, "lookup item");

	list_for_each_entry(i, &tr->op, list) {
		if (i->type == KZNL_OP_ADD_BIND) {
			struct kz_bind *b = (struct kz_bind *) i->data;

			kz_bind_debug(b, "check item");

			if (kz_bind_eq(b, bind))
				return b;
		}
	}

	return NULL;
}

/**
 * transaction_rule_lookup - look up dispatcher and the rule in the transaction
 * @tr: transaction
 * @dispatcher_name: name of the dispatcher to look for
 * @id: rule id to look for
 *
 * NOTE: caller must mutex the passed transaction!
 *
 * This function checks if we have a dispatcher named @dispatcher_name
 * in the transaction operation list and if it has a rule with ID
 * @id. Rules must be uploaded so that their IDs are in increasing
 * order, failing to do so is an error. Because of this, this function
 * simply checks if the rule ID of the rule last added matches @id.
 */
static struct kz_rule *
transaction_rule_lookup(const struct kz_transaction * const tr,
			const char *dispatcher_name, u_int32_t id)
{
	const struct kz_operation *i;

	pr_debug("dispatcher_name='%s', id='%u'\n", dispatcher_name, id);

	list_for_each_entry(i, &tr->op, list) {
		if (i->type == KZNL_OP_ADD_DISPATCHER) {
			struct kz_dispatcher *d;
			struct kz_rule *rule = NULL;

			d = (struct kz_dispatcher *) i->data;

			if (strcmp(d->name, dispatcher_name))
				continue;

			/* we have found the dispatcher, check if the ID of
			 * the last rule matches @id */
			if (d->num_rule > 0)
				rule = &d->rule[d->num_rule - 1];
			if (rule && (id == rule->id))
				return rule;

			return NULL;
		}
	}

	return NULL;
}

/***********************************************************
 * Object lookup utility functions
 ***********************************************************/

/**
 * lookup_zone_merged - look up a zone by name in the transaction + current config
 * @tr: transaction
 * @name: name of the zone
 *
* This function looks up a zone by name in a merged view of the
 * current transaction and the current configuration. It looks up the
 * config only if the transaction does not have the flush zones bit
 * set, that is, there is no chance that the looked-up service will be
 * removed by a subsequent commit.
 */
static inline struct kz_zone *
lookup_zone_merged(const struct kz_transaction * const tr, const char *name)
{
	struct kz_zone *zone = transaction_zone_lookup(tr, name);

	if (zone == NULL && !(tr->flags & KZF_TRANSACTION_FLUSH_ZONES))
		zone = kz_zone_lookup_name(tr->cfg, name);

	return zone;
}

/**
 * lookup_service_merged - look up a service by name in the transaction + current config
 * @tr: transaction
 * @name: name to look for
 *
 * This function looks up a service by name in a merged view of the
 * current transaction and the current configuration. It looks up the
 * config only if the transaction does not have the flush services bit
 * set, that is, there is no chance that the looked-up service will be
 * removed by a subsequent commit.
 **/
static inline struct kz_service *
lookup_service_merged(const struct kz_transaction * const tr, const char *name)
{
	struct kz_service *service = transaction_service_lookup(tr, name);

	if (service == NULL && !(tr->flags & KZF_TRANSACTION_FLUSH_SERVICES))
		service = kz_service_lookup_name(tr->cfg, name);

	return service;
}

/***********************************************************
 * Netlink attribute parsing
 ***********************************************************/

static inline int
kznl_parse_name(const struct nlattr *attr, char *name, unsigned long nsize)
{
	struct kza_name *a = nla_data(attr);
	unsigned long length;

	length = (unsigned long) ntohs(a->length);
	if (nsize < length + 1) {
		pr_err_ratelimited("invalid target length; dst_size='%lu', len='%lu'\n", nsize, length);
		return -EINVAL;
	}

	memcpy(name, a->name, length);
	name[length] = 0;

	return 0;
}

static int
kznl_parse_name_alloc(const struct nlattr *attr, char **name)
{
	struct kza_name *a = nla_data(attr);
	char *n;
	int res;
	unsigned long length = ntohs(a->length);

	if (length == 0 || length > KZ_ATTR_NAME_MAX_LENGTH)
		return -EINVAL;

	n = kzalloc(length + 1, GFP_KERNEL);
	if (n == NULL)
		return -ENOMEM;

	res = kznl_parse_name(attr, n, length + 1);
	if (res >= 0)
		*name = n;

	return res;
}

static int
kznl_parse_count(const struct nlattr *attr, u_int64_t *_count)
{
	u_int64_t count = be64_to_cpu(nla_get_u64(attr));

	*_count = count;

	return 0;
}

static inline int
kznl_parse_in_addr(const struct nlattr *attr, struct in_addr *addr)
{
	struct kz_in_subnet *a = nla_data(attr);

	addr->s_addr = a->addr.s_addr;

	pr_debug("parsed IPv4 address='%pI4'\n", addr);

	return 0;
}

static inline int
kznl_parse_in6_addr(const struct nlattr *attr, struct in6_addr *addr)
{
	struct kz_in6_subnet *a = nla_data(attr);

	*addr = a->addr;

	pr_debug("parsed IPv6 address='%pI6c'\n", addr);

	return 0;
}

static const struct nla_policy inet_addr_nla_policy[KZNL_ATTR_TYPE_COUNT + 1] = {
	[KZNL_ATTR_INET_ADDR]	= { .type = NLA_NESTED },
	[KZNL_ATTR_INET6_ADDR]	= { .type = NLA_NESTED },
};

static inline int
kznl_parse_inet_addr(const struct nlattr *attr, union nf_inet_addr *addr, sa_family_t *family)
{
	int res = 0;
	struct nlattr *tb[KZNL_ATTR_TYPE_COUNT + 1];

	res = nla_parse_nested(tb, KZNL_ATTR_TYPE_COUNT, attr, inet_addr_nla_policy);
	if (res < 0) {
		pr_err_ratelimited("failed to parse nested attribute\n");
		return res;
	}

	pr_debug ("nested attributes: %p %p", tb[KZNL_ATTR_INET_ADDR], tb[KZNL_ATTR_INET6_ADDR]);
	if (tb[KZNL_ATTR_INET_ADDR]) {
		res = kznl_parse_in_addr(tb[KZNL_ATTR_INET_ADDR], &addr->in);
		if (res < 0) {
			pr_err_ratelimited("failed to parse IPv4 address\n");
			return res;
		} else {
			*family = AF_INET;
		}
	}
	else if (tb[KZNL_ATTR_INET6_ADDR]) {
		res = kznl_parse_in6_addr(tb[KZNL_ATTR_INET6_ADDR], &addr->in6);
		if (res < 0) {
			pr_err_ratelimited("failed to parse IPv6 address\n");
			return res;
		} else {
			*family = AF_INET6;
		}
	} else {
		pr_err_ratelimited("required attributes missing: address\n");
		res = -EINVAL;
	}

	return res;
}



static inline int
kznl_parse_in_subnet(const struct nlattr *attr, struct in_addr *subnet_addr, struct in_addr *subnet_mask)
{
	struct kz_in_subnet *a = nla_data(attr);
	u_int32_t mask, i;

	subnet_addr->s_addr = a->addr.s_addr;
	subnet_mask->s_addr = a->mask.s_addr;

	pr_debug("address='%pI4', mask='%pI4'\n", subnet_addr, subnet_mask);

	mask = ntohl(subnet_mask->s_addr);
	for (i = 1 << 31; i && (mask & i); i >>= 1)
		;
	if (i && (i - 1) & mask)
		return -EINVAL;

	return 0;
}

static inline int
kznl_parse_in6_subnet(const struct nlattr *attr, struct in6_addr *addr, struct in6_addr *mask)
{
	struct kz_in6_subnet *a = nla_data(attr);
	struct in6_addr pfx;
	int prefixlen;

	*addr = a->addr;
	*mask = a->mask;

	pr_debug("address='%pI6c', mask='%pI6c'\n", addr, mask);

	ipv6_addr_set(&pfx, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff);
	prefixlen = ipv6_addr_diff(mask, &pfx);
	ipv6_addr_prefix(&pfx, mask, prefixlen);
	if (!ipv6_addr_equal(&pfx, mask))
		return -EINVAL;

	return 0;
}

static const struct nla_policy inet_subnet_nla_policy[KZNL_ATTR_TYPE_COUNT + 1] = {
	[KZNL_ATTR_INET_SUBNET]		= { .type = NLA_NESTED },
	[KZNL_ATTR_INET6_SUBNET]	= { .type = NLA_NESTED },
};

static inline int
kznl_parse_inet_subnet(const struct nlattr *attr, union nf_inet_addr *addr, union nf_inet_addr *mask, sa_family_t *family)
{
	int res = 0;
	struct nlattr *tb[KZNL_ATTR_TYPE_COUNT + 1];

	res = nla_parse_nested(tb, KZNL_ATTR_TYPE_COUNT, attr, inet_subnet_nla_policy);
	if (res < 0) {
		pr_err_ratelimited("failed to parse nested attribute\n");
		return res;
	}

	if (tb[KZNL_ATTR_INET_SUBNET]) {
		res = kznl_parse_in_subnet(tb[KZNL_ATTR_INET_SUBNET], &addr->in, &mask->in);
		if (res < 0) {
			pr_err_ratelimited("failed to parse IPv4 subnet\n");
			return res;
		} else {
			*family = AF_INET;
		}
	}
	else if (tb[KZNL_ATTR_INET6_SUBNET]) {
		res = kznl_parse_in6_subnet(tb[KZNL_ATTR_INET6_SUBNET], &addr->in6, &mask->in6);
		if (res < 0) {
			pr_err_ratelimited("failed to parse IPv6 subnet\n");
			return res;
		} else {
			*family = AF_INET6;
		}
	} else {
		pr_err_ratelimited("required attributes missing: subnet\n");
		res = -EINVAL;
	}

	return res;
}

static inline int
kznl_parse_port(const struct nlattr *attr, __u16 *_port)
{
	__u16 port;

	port = ntohs(nla_get_be16(attr));
	if (port == 0) {
		pr_err_ratelimited("invalid port number received; port='%hu'", port);
		return -EINVAL;
	}

	*_port = port;

	return 0;
}

static inline int
kznl_parse_port_range(const struct nlattr *attr, u_int16_t *range_from, u_int16_t *range_to)
{
	struct kza_port_range *a = nla_data(attr);
	const u_int16_t from = ntohs(a->from);
	const u_int16_t to = ntohs(a->to);

	if (to < from)
		return -EINVAL;

	*range_from = from;
	*range_to = to;

	return 0;
}

static inline int
kznl_parse_proto(const struct nlattr *attr, __u8 *_proto)
{
	*_proto = nla_get_u8(attr);

	return 0;
}

static inline int
kznl_parse_reqid(const struct nlattr *attr, __u32 *_reqid)
{
	*_reqid = ntohl(nla_get_be32(attr));

	return 0;
}

static inline int
kznl_parse_proto_type(const struct nlattr *attr, u_int8_t proto, __u32 *proto_type)
{
	const u_int32_t _proto_type = ntohl(nla_get_be32(attr));
	if ((proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6) && _proto_type > 255) {
		pr_err_ratelimited("invalid protocol type received; proto_type='%hu'", _proto_type);
		return -EINVAL;
	}

	*proto_type = _proto_type;

	return 0;
}

static inline int
kznl_parse_proto_subtype(const struct nlattr *attr, u_int8_t proto, __u32 *proto_subtype)
{
	const u_int32_t _proto_subtype = ntohl(nla_get_be32(attr));
	if ((proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6) && _proto_subtype > 255) {
		pr_err_ratelimited("invalid protocol type received; proto_subtype='%hu'", _proto_subtype);
		return -EINVAL;
	}

	*proto_subtype = _proto_subtype;

	return 0;
}



static inline int
kznl_parse_service_params(const struct nlattr *attr, struct kz_service *svc)
{
	struct kza_service_params *a = nla_data(attr);
	u_int32_t new_flags = ntohl(a->flags);

	if (a->type <= KZ_SERVICE_INVALID || a->type >= KZ_SERVICE_TYPE_COUNT)
		return -EINVAL;
	if ((new_flags | KZF_SERVICE_PUBLIC_FLAGS) != KZF_SERVICE_PUBLIC_FLAGS)
		return -EINVAL;

	svc->type = (enum kz_service_type) a->type;
	svc->flags = new_flags;

	return 0;
}

static inline int
kznl_parse_service_router_dst(struct nlattr *cda[], struct kz_service *svc)
{
	int res;

	res = kznl_parse_inet_addr(cda[KZNL_ATTR_SERVICE_ROUTER_DST_ADDR], &svc->a.fwd.router_dst_addr, &svc->a.fwd.router_dst_addr_family);
	if (res < 0) {
		pr_err_ratelimited("failed to parse dst ip nested attribute\n");
		goto error;
	}
	res = kznl_parse_port(cda[KZNL_ATTR_SERVICE_ROUTER_DST_PORT], &svc->a.fwd.router_dst_port);
	if (res < 0) {
		pr_err_ratelimited("failed to parse dst port attribute\n");
		goto error;
	}

	return 0;
error:
	return res;
}

static inline int
kznl_parse_service_nat_params(const struct nlattr *attr, struct nf_nat_range *range)
{
	const struct kza_service_nat_params *a = nla_data(attr);
	u_int32_t flags = ntohl(a->flags);

	if ((flags | KZF_SERVICE_NAT_MAP_PUBLIC_FLAGS) != KZF_SERVICE_NAT_MAP_PUBLIC_FLAGS)
		return -EINVAL;

	if (flags & KZF_SERVICE_NAT_MAP_IPS)
		range->flags |= NF_NAT_RANGE_MAP_IPS;
	if (flags & KZF_SERVICE_NAT_MAP_PROTO_SPECIFIC)
		range->flags |= NF_NAT_RANGE_PROTO_SPECIFIED;

	kz_nat_range_set_min_ip(range, a->min_ip);
	kz_nat_range_set_max_ip(range, a->max_ip);
	kz_nat_range_set_min_port(range, a->min_port);
	kz_nat_range_set_max_port(range, a->max_port);

	return 0;
}

static inline int
kznl_parse_service_deny_method(const struct nlattr *attr, unsigned int *type)
{
	*type = nla_get_u8(attr);

	return 0;
}

static inline int
kznl_parse_service_ipv4_deny_method(const struct nlattr *attr, unsigned int *_type)
{
	unsigned int type;
	int res;

	res = kznl_parse_service_deny_method(attr, &type);
	if (res < 0)
		return res;

	if (type >= KZ_SERVICE_DENY_METHOD_V4_COUNT)
		return -EINVAL;

	*_type = type;

	return 0;
}

static inline int
kznl_parse_service_ipv6_deny_method(const struct nlattr *attr, unsigned int *_type)
{
	unsigned int type;
	int res;

	res = kznl_parse_service_deny_method(attr, &type);
	if (res < 0)
		return res;

	if (type > KZ_SERVICE_DENY_METHOD_V6_COUNT)
		return -EINVAL;

	*_type = type;

	return 0;
}

static inline int
kznl_check_port_ranges(u_int32_t num_ranges, u_int16_t ranges[])
{
	unsigned int i;

	for (i = 0; i < num_ranges; i++) {
		if (ranges[2 * i] > ranges[2 * i + 1])
			return -EINVAL;
	}

	return 0;
}

static int
kznl_parse_dispatcher_n_dimension(const struct nlattr *attr, struct kz_dispatcher *n_dimension)
{
	struct kza_dispatcher_n_dimension_params *a = nla_data(attr);

	return kz_dispatcher_alloc_rule_array(n_dimension, ntohl(a->num_rules));
}

static int
kznl_parse_rule_id(struct nlattr *attrs[],
		   u_int32_t *rule_id)
{
	u_int32_t _rule_id;

	if ((_rule_id = ntohl(nla_get_be32(attrs[KZNL_ATTR_N_DIMENSION_RULE_ID]))) == 0) {
		pr_err_ratelimited("invalid rule id; id='%u'\n", _rule_id);
		return -EINVAL;
	}

	*rule_id = _rule_id;

	return 0;
}

static int
kznl_parse_dispatcher_n_dimension_rule(struct nlattr *attrs[],
				       struct kz_rule *rule)
{
	int res;
	u_int64_t count;

	if ((res = kznl_parse_rule_id(attrs, &rule->id)) < 0)
		return res;

	if (attrs[KZNL_ATTR_ACCOUNTING_COUNTER_NUM]) {
		if (kznl_parse_count(attrs[KZNL_ATTR_ACCOUNTING_COUNTER_NUM], &count) < 0) {
			pr_err_ratelimited("failed to parse rule acoouting counter\n");
			return -EINVAL;
		}
		atomic64_set(&rule->count, count);
	}

	return 0;
}

static int
kznl_parse_dispatcher_n_dimension_rule_entry(struct nlattr *attrs[],
					     struct kz_rule_entry_params *rule_entry)
{
	int res;

	if ((res = kznl_parse_rule_id(attrs, &rule_entry->rule_id)) < 0)
		return res;

	return 0;
}

static inline int
kznl_parse_query_params(const struct nlattr *attr, u_int8_t *proto, char *ifname)
{
	struct kza_query_params *a = nla_data(attr);

	*proto = a->proto;
	memcpy(ifname, a->ifname, IFNAMSIZ);

	return 0;
}

/***********************************************************
 * Netlink attribute dumping
 ***********************************************************/

static int
kznl_dump_name(struct sk_buff *skb, unsigned int attr, const char *name)
{
	size_t len = strlen(name);

	{
		struct {
			struct kza_name hdr;
			char name[len];
		} msg;

		msg.hdr.length = htons(len);
		memcpy(&msg.name, name, len);
		if (nla_put(skb, attr, sizeof(struct kza_name) + len, &msg))
			goto nla_put_failure;
	}

	return 0;

nla_put_failure:
	return -1;
}

static int
kznl_dump_count(struct sk_buff *skb, unsigned int attr, u_int64_t count)
{
	if (nla_put_u64(skb, attr, cpu_to_be64(count)))
		goto nla_put_failure;

	return 0;

nla_put_failure:
	return -1;
}

static inline int
kznl_dump_port(struct sk_buff *skb, unsigned int attr, __u16 port)
{
	if (port == 0)
		return -1;

	if (nla_put_be16(skb, attr, htons(port)))
		goto nla_put_failure;

	return 0;

nla_put_failure:
	return -1;
}

static int
kznl_dump_port_range(struct sk_buff *skb, unsigned int attr,
		     const struct kz_port_range * const range)
{
	struct kza_port_range r;

	r.from = htons(range->from);
	r.to = htons(range->to);

	if (nla_put(skb, attr, sizeof(struct kza_port_range), &r))
		goto nla_put_failure;

	return 0;

nla_put_failure:
	return -1;
}

static int
kznl_dump_in_subnet(struct sk_buff *skb, unsigned int attr,
		    const struct in_addr * const addr,
		    const struct in_addr * const mask)
{
	struct kz_in_subnet a;

	a.addr.s_addr = addr->s_addr;
	a.mask.s_addr = mask->s_addr;

	if (nla_put(skb, attr, sizeof(struct kz_in_subnet), &a))
		goto nla_put_failure;

	return 0;

nla_put_failure:
	return -1;
}

static int
kznl_dump_in6_subnet(struct sk_buff *skb, unsigned int attr,
		     const struct in6_addr * const addr,
		     const struct in6_addr * const mask)
{
	struct kz_in6_subnet a;

	a.addr = *addr;
	a.mask = *mask;

	if (nla_put(skb, attr, sizeof(struct kz_in6_subnet), &a))
		goto nla_put_failure;

	return 0;

nla_put_failure:
	return -1;
}

static int
kznl_dump_inet_subnet(struct sk_buff *skb, unsigned int attr,
		      sa_family_t family, const union nf_inet_addr *addr, const union nf_inet_addr *mask)
{
	int res = 0;
	struct nlattr *nest_helper;

	nest_helper = nla_nest_start(skb, attr | NLA_F_NESTED);
	if (!nest_helper)
		return -1;

	if (family == AF_INET) {
		pr_debug("dump inet subnet; address='%pI4', mask='%pI4'\n", &addr->in, &mask->in);
		res = kznl_dump_in_subnet(skb, KZNL_ATTR_INET_SUBNET, &addr->in, &mask->in);
		if (res < 0)
			goto nla_put_failure;
	}
	else if (family == AF_INET6) {
		pr_debug("dump inet subnet; address='%pI6c', mask='%pI6c'\n", &addr->in6, &mask->in6);
		res = kznl_dump_in6_subnet(skb, KZNL_ATTR_INET6_SUBNET, &addr->in6, &mask->in6);
		if (res < 0)
			goto nla_put_failure;
	} else {
		BUG();
	}

nla_put_failure:

	nla_nest_end(skb, nest_helper);

	return res;
}

static int
kznl_dump_inet_addr(struct sk_buff *skb, unsigned int attr,
		    sa_family_t family, const union nf_inet_addr *addr)
{
	int res = 0;
	struct nlattr *nest_helper;

	nest_helper = nla_nest_start(skb, attr | NLA_F_NESTED);
	if (!nest_helper)
		return -1;

	if (family == AF_INET) {
		pr_debug("dump inet addr; address='%pI4'\n", &addr->in);
		res = nla_put(skb, KZNL_ATTR_INET_ADDR, sizeof(struct in_addr), &addr->in);
		if (res < 0)
			goto nla_put_failure;
	}
	else if (family == AF_INET6) {
		pr_debug("dump inet addr; address='%pI6c'\n", &addr->in6);
		res = nla_put(skb, KZNL_ATTR_INET6_ADDR, sizeof(struct in6_addr), &addr->in6);
		if (res < 0)
			goto nla_put_failure;
	} else {
		BUG();
	}

nla_put_failure:

	nla_nest_end(skb, nest_helper);

	return res;
}

static inline int
kznl_dump_service_deny_method(struct sk_buff *skb, unsigned int attr,
			      unsigned int method)
{
	if (nla_put_u8(skb, attr, (method & 0xff)))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return -1;
}

static inline int
kznl_dump_service_nat_entry(struct kza_service_nat_params *a, struct nf_nat_range *range)
{
	if (range->flags & NF_NAT_RANGE_MAP_IPS)
		a->flags |= KZF_SERVICE_NAT_MAP_IPS;
	if (range->flags & NF_NAT_RANGE_PROTO_SPECIFIED)
		a->flags |= KZF_SERVICE_NAT_MAP_PROTO_SPECIFIC;

	a->flags = htons(a->flags);
	a->min_ip = *kz_nat_range_get_min_ip(range);
	a->max_ip = *kz_nat_range_get_max_ip(range);
	a->min_port = *kz_nat_range_get_min_port(range);
	a->max_port = *kz_nat_range_get_max_port(range);

	return 0;
}

/***********************************************************
 * Netlink message processing
 ***********************************************************/

static struct genl_family kznl_family = {
	.id = GENL_ID_GENERATE,
	.name = "kzorp",
	.version = 2,
	.maxattr = KZNL_ATTR_TYPE_COUNT,
};

static int
kznl_recv_start(struct sk_buff *skb, struct genl_info *info)
{
	int res = 0;
	struct kz_instance *ins;
	struct kz_transaction *tr;
	char *ins_name;
	u_int64_t config_cookie = 0UL;

	if (!info->attrs[KZNL_ATTR_INSTANCE_NAME]) {
		pr_err_ratelimited("required attributes missing\n");
		res = -EINVAL;
		goto error;
	}

	/* parse attributes */
	if (kznl_parse_name_alloc(info->attrs[KZNL_ATTR_INSTANCE_NAME], &ins_name) < 0) {
		pr_err_ratelimited("error while parsing name attribute\n");
		res = -EINVAL;
		goto error;
	}

	/* parse config cookie if present */
	if (info->attrs[KZNL_ATTR_CONFIG_COOKIE]) {
		config_cookie = be64_to_cpu(nla_get_u64(info->attrs[KZNL_ATTR_CONFIG_COOKIE]));
	}

	LOCK_TRANSACTIONS();

	/* look up pid in transactions */
	tr = transaction_lookup(info->snd_portid);
	if (tr != NULL) {
		/* problem: we already have a transaction running with this PID as peer */
		pr_err_ratelimited("transaction pending for this PID\n");
		res = -EINVAL;
		goto error_unlock_tr;
	}

	/* look up/create instance */
	ins = kz_instance_lookup(ins_name);
	if (ins == NULL) {
		ins = kz_instance_create(ins_name, strlen(ins_name), info->snd_portid);
		if (ins == NULL) {
			pr_err_ratelimited("failed to create new instance\n");
			res = -EINVAL;
			goto error_unlock_tr;
		}
	}

	if (ins->flags & KZF_INSTANCE_TRANS) {
		/* the instance already has an associated transaction */
		pr_err_ratelimited("the instance already has a pending transaction\n");
		res = -EEXIST;
		goto error_unlock_tr;
	}

	/* create transaction */
	tr = transaction_create(info->snd_portid, ins->id, config_cookie);
	if (tr == NULL) {
		pr_err_ratelimited("failed to create transaction\n");
		res = -EINVAL;
		goto error_unlock_tr;
	}

	/* mark instance */
	ins->flags |= KZF_INSTANCE_TRANS;

	pr_debug("transaction started; transaction='%p'\n", tr);

error_unlock_tr:
	UNLOCK_TRANSACTIONS();

	if (ins_name != NULL)
		kfree(ins_name);

error:
	return res;
}

static int
kz_commit_transaction_check(const struct kz_transaction *tr)
/* preliminary sanity checks */
{
	const struct kz_operation *io;

	/* append dispatcherss created in the transaction */
	list_for_each_entry(io, &tr->op, list) {
		if (io->type == KZNL_OP_ADD_DISPATCHER) {
			const struct kz_dispatcher *dispatcher = (struct kz_dispatcher *) io->data;

			if (dispatcher->num_rule != dispatcher->alloc_rule) {
				pr_err_ratelimited("rule number mismatch; dispatcher='%s', alloc_rules='%u', num_rules='%u'\n",
					dispatcher->name, dispatcher->alloc_rule, dispatcher->num_rule);
				return -EINVAL;
			}
		}
	}

	return 0;
}

static int
kz_commit_transaction_process_services(const struct kz_transaction *tr, struct kz_config *new)
{
	const struct kz_config * const old = tr->cfg;
	struct kz_operation *io, *po;
	struct kz_service *i, *svc, *orig;

	/* clone existing services */
	list_for_each_entry(i, &old->services.head, list) {
		/* skip service if the FLUSH flag is set and it belongs
		 * to the same instance */
		if ((tr->flags & KZF_TRANSACTION_FLUSH_SERVICES) &&
		    (i->instance_id == tr->instance_id)) {
			continue;
		}

		svc = kz_service_clone(i);
		if (svc == NULL)
			return -ENOMEM;
		pr_debug("cloned service; name='%s'\n", svc->name);
		list_add_tail(&svc->list, &new->services.head);
		atomic64_set(&svc->count, kz_service_lock(i));
	}

	/* add services in the transaction */
	list_for_each_entry_safe(io, po, &tr->op, list) {
		if (io->type == KZNL_OP_ADD_SERVICE) {
			svc = (struct kz_service *)(io->data);
			list_del(&io->list);
			list_add_tail(&svc->list, &new->services.head);
			kfree(io);
			pr_debug("add service; name='%s'\n", svc->name);
			orig = kz_service_lookup_name(old, svc->name);
			if (orig != NULL) {
				pr_debug("migrate service session count\n");
				atomic64_set(&svc->count, kz_service_lock(orig));
				svc->id = orig->id; /* use the original ID! */
			}
		}
	}

	return 0;
}

static bool
kznl_zone_apply_delete_operation(struct kz_zone *deletable_zone, const struct list_head const *operations)
{
	struct kz_operation *operation, *n;
	/* append zones created in the transaction */
	list_for_each_entry_safe(operation, n, operations, list) {
		if (operation->type == KZNL_OP_DELETE_ZONE) {
			const struct kz_zone const * updater_zone = (const struct kz_zone const *) operation->data;
			if (strcmp(updater_zone->name, deletable_zone->name) == 0) {
				kz_operation_remove(operation);
				return true;
			}
		}
	}
	return false;
}

static int
kz_commit_transaction_delete_zones(const struct kz_transaction *tr, struct kz_config *new)
{
	const struct kz_config * const old = tr->cfg;
	struct kz_zone *i, *zone;
	struct kz_operation *io;

	/* clone existing zones */
	if (tr->flags & KZF_TRANSACTION_FLUSH_ZONES) {
		list_for_each_entry(io, &tr->op, list) {
			if (io->type == KZNL_OP_DELETE_ZONE) {
				pr_err_ratelimited("transaction problem: zone delete cannot be used with flush\n");
				return -EINVAL;
			}
		}
	} else {
		list_for_each_entry(i, &old->zones.head, list) {
			if (kznl_zone_apply_delete_operation(i, &tr->op)) {
				pr_debug("not cloned zone; name='%s', depth='%u'\n", i->name, i->depth);
			} else {
				zone = kz_zone_clone(i);
				if (zone == NULL)
					return -ENOMEM;
				pr_debug("cloned zone; name='%s', depth='%u'\n", zone->name, zone->depth);
				list_add_tail(&zone->list, &new->zones.head);
			}
		}
	}

	list_for_each_entry(io, &tr->op, list) {
		if (io->type == KZNL_OP_DELETE_ZONE) {
			const struct kz_zone const * deletable_zone = (const struct kz_zone const *) io->data;
			pr_err_ratelimited("transaction problem: unapplied zone delete operation found; name='%s' depth='%u'\n",
			       deletable_zone->name, deletable_zone->depth);
			return -EINVAL;
		}
	}


	return 0;
}

static int
kz_commit_transaction_add_zones(const struct kz_transaction *tr, struct kz_config *new)
{
	struct kz_operation *io, *po;

	/* append zones created in the transaction */
	list_for_each_entry_safe(io, po, &tr->op, list) {
		if (io->type == KZNL_OP_ADD_ZONE) {
			struct kz_zone *zone = (struct kz_zone *)(io->data);
			const struct kz_zone *existing_zone;

			existing_zone = __kz_zone_lookup_name(&new->zones.head, zone->name);
			if (existing_zone != NULL) {
				pr_err_ratelimited("zone with the same name already exists; name='%s'\n", existing_zone->name);
				return -EEXIST;
			}

			list_del(&io->list);
			list_add_tail(&zone->list, &new->zones.head);
			kfree(io);
			pr_debug("add zone; name='%s', depth='%u'\n", zone->name, zone->depth);
		}
	}

	return 0;
}

static int
kz_commit_transaction_consolidate_zones(const struct kz_transaction *tr, struct kz_config *new)
{
	struct kz_zone *i;

	/* consolidate admin_parent links - must point to zones in new list */
	list_for_each_entry(i, &new->zones.head, list) {
		if (i->admin_parent != NULL) {
			struct kz_zone *parent;

			parent = __kz_zone_lookup_name(&new->zones.head, i->admin_parent->name);
			if (parent == NULL) {
				/* oops, its admin parent was deleted, this is an
				 * internal error */
				pr_err_ratelimited("transaction problem: internal error, aborting\n");
				return -EINVAL;
			}

			kz_zone_get(parent);
			kz_zone_put(i->admin_parent);
			i->admin_parent = parent;
			pr_debug("set admin-parent for zone; name='%s' parent='%s', depth='%u', parent_depth='%u'\n", i->name, parent->name, i->depth, parent->depth);
		}
	}

	return 0;
}

static int
kz_commit_transaction_process_zones(const struct kz_transaction *tr, struct kz_config *new)
{
	int res;

	if ((res = kz_commit_transaction_delete_zones(tr, new)) < 0)
		return res;
	if ((res = kz_commit_transaction_add_zones(tr, new)) < 0)
		return res;
	if ((res = kz_commit_transaction_consolidate_zones(tr, new)) < 0)
		return res;

	return 0;
}

static int
kz_commit_transaction_process_dispatchers(const struct kz_transaction *tr, struct kz_config *new)
{
	const struct kz_config * const old = tr->cfg;
	struct kz_dispatcher *i, *dpt;
	struct kz_operation *io, *po;
	int error;

	/* clone existing dispatchers */
	list_for_each_entry(i, &old->dispatchers.head, list) {
		/* skip service if the FLUSH flag is set and it belongs
		 * to the same instance */
		if ((tr->flags & KZF_TRANSACTION_FLUSH_DISPATCHERS) &&
		    (i->instance->id == tr->instance_id))
			continue;

		pr_debug("cloning dispatcher; name='%s', alloc_rules='%u'\n", i->name, i->alloc_rule);

		dpt = kz_dispatcher_clone(i);
		if (dpt == NULL)
			return -ENOMEM;
		list_add_tail(&dpt->list, &new->dispatchers.head);
	}

	/* append dispatcherss created in the transaction */
	list_for_each_entry_safe(io, po, &tr->op, list) {
		if (io->type == KZNL_OP_ADD_DISPATCHER) {
			struct kz_dispatcher *dispatcher = (struct kz_dispatcher *) io->data;
			pr_debug("add dispatcher; name='%s', alloc_rules='%u', num_rules='%u'\n", dispatcher->name, dispatcher->alloc_rule, dispatcher->num_rule);
			list_del(&io->list);
			list_add_tail(&dispatcher->list, &new->dispatchers.head);
			kfree(io);
		}
	}

	/* consolidate content */
	list_for_each_entry(i, &new->dispatchers.head, list) {
		error = kz_dispatcher_relink(i, &new->zones.head, &new->services.head);
		if (error != 0)
			return error;
	}

	return 0;
}


/* this is a SINGLE point that changes the config (should that change, review what thinks so)

   we could just collect operations raw, and do all the checks here. for historic reasons we
   instead do preliminary checks as they come in. We have some expectations, and limit what can be done.

   Important limitation is the messages that set flush flag -- it must arrive early, if not, some checks may get mislead
   the semantic of those flags is ALWAYS as if they arrived at start.

   elements that refer to each other must arrive in proper order (what is checked on arrival)

   the transaction_op list have a mix of services, zones, dispatchers;

   reference-setting messages can come only to the "newly added" items. If no flush, we inherit from the previous config,
   though the referent list of those can change indirectly (i.e we have Zone1 that refers Svc1 and Svc2. We send config
   that flushes services, not flush zones, sends Svc1 and no Svc2. This results config having (old) Zone1 refering (new) Svc1.

   dependencies are ordered:
     service: none
     zone -> service  [inbound, outbound] by id; zone -> zone [admin-parent] by pointer
     dispatcher -> zone, service  [server-zone, client-zone, service] by pointers

   procedure:
     - alloc new config struct
     - copy services from old/transactions, retain id from old if name present; clear session counts;
     - copy zone DAC from old to transactions if required by flag; old overrides new, no consolidation!
     - copy zones from old/transactions
     - consolidate admin-parents in zones to refer inside new config
     - check service links in zones, drop missing
     - copy dispatchers from old/transactions
     - consolidate pointers in css
     - init lookup helper structures
     - swap in the new config (old gets nuked on rcu unlock)

   any problems en-route mean just dropping out, freeing anything in new config and transaction,
   the old config stays. The transaction is always closed.

   this function is called having transaction_mutex
*/
static int
kznl_recv_commit_transaction(struct kz_instance *instance, struct kz_transaction *tr)
{
	int res = 0;
	const struct kz_config * const old = tr->cfg;
	struct kz_config *new ;

	if ((res = kz_commit_transaction_check(tr)) < 0)
		return res;

	/* the new config instance */
	new = kz_config_new();
	if (new == NULL)
		return -ENOMEM;

	if ((res = kz_commit_transaction_process_services(tr, new)) < 0)
		goto error;
	if ((res = kz_commit_transaction_process_zones(tr, new)) < 0)
		goto error;
	if ((res = kz_commit_transaction_process_dispatchers(tr, new)) < 0)
		goto error;

	/* remove binds of transaction owner process */
	kz_instance_remove_bind(instance, tr->peer_pid, tr);

	/* build lookup structures */
	res = kz_head_zone_build(&new->zones);
	if (res < 0) {
		pr_err_ratelimited("failed to build zone lookup data structures, aborting\n");
		goto error;
	}

	res = kz_head_dispatcher_build(&new->dispatchers);
	if (res < 0) {
		pr_err_ratelimited("error building dispatcher lookup structures\n");
		goto error;
	}

	/* all ok, commit finally */
	pr_info("reloading configuration\n");
	kz_config_swap(new);
	res = 0;
	goto free_locals;

error:
	if (res == -ENOMEM)
		pr_err_ratelimited("memory exhausted during kzorp config commit");

	/* unlock services in old */
	{
		struct kz_service *i;
		list_for_each_entry(i, &old->services.head, list) {
			kz_service_unlock(i);
		}
	}

	kz_config_destroy(new);

free_locals:
	return res;
}

static int
kznl_recv_commit(struct sk_buff *skb, struct genl_info *info)
{
	int res = 0;
	struct kz_transaction *tr;
	struct kz_instance *inst;

	LOCK_TRANSACTIONS();

	tr = transaction_lookup(info->snd_portid);
	if (tr == NULL) {
		/* we have no transaction associated with this peer */
		pr_err_ratelimited("no transaction found; pid='%d'\n", info->snd_portid);
		res = -ENOENT;
		goto error_unlock_tr;
	}

	inst = kz_instance_lookup_id(tr->instance_id);
	res = kznl_recv_commit_transaction(inst, tr);

	if (inst != NULL)
		inst->flags &= ~KZF_INSTANCE_TRANS;
	transaction_destroy(tr);

error_unlock_tr:
	UNLOCK_TRANSACTIONS();
	return res;
}

static int
kznl_recv_setflag(struct sk_buff *skb, struct genl_info *info, unsigned int flag)
{
	int res = 0;
	struct kz_transaction *tr;

	LOCK_TRANSACTIONS();

	tr = transaction_lookup(info->snd_portid);
	if (tr == NULL) {
		/* we have no transaction associated with this peer */
		pr_err_ratelimited("no transaction found; pid='%d'\n", info->snd_portid);
		res = -ENOENT;
		goto error_unlock_tr;
	}

	/* set the flag in the transaction */
	tr->flags |= flag;

error_unlock_tr:
	UNLOCK_TRANSACTIONS();

	return res;
}

static int
kznl_recv_flush_z(struct sk_buff *skb, struct genl_info *info)
{
	return kznl_recv_setflag(skb, info, KZF_TRANSACTION_FLUSH_ZONES);
}

static int
kznl_recv_flush_s(struct sk_buff *skb, struct genl_info *info)
{
	return kznl_recv_setflag(skb, info, KZF_TRANSACTION_FLUSH_SERVICES);
}

static int
kznl_recv_flush_d(struct sk_buff *skb, struct genl_info *info)
{
	return kznl_recv_setflag(skb, info, KZF_TRANSACTION_FLUSH_DISPATCHERS);
}

static int
kznl_recv_flush_b(struct sk_buff *skb, struct genl_info *info)
{
	return kznl_recv_setflag(skb, info, KZF_TRANSACTION_FLUSH_BIND);
}

static int
kznl_parse_add_zone_params(struct nlattr * const * const attrs, struct kz_zone **_zone, char **parent_name)
{
	int res = 0;
	u_int64_t count;
	struct kz_zone *zone;

	/* parse attributes */
	if (!attrs[KZNL_ATTR_ZONE_SUBNET_NUM]) {
		pr_err_ratelimited("required attribute missing: subnet num\n");
		res = -EINVAL;
		goto error;
	}

	if (!attrs[KZNL_ATTR_ZONE_NAME]) {
		pr_err_ratelimited("required attribute missing: name\n");
		res = -EINVAL;
		goto error;
	}

	/* allocate zone structure */
	zone = kz_zone_new();
	if (zone == NULL) {
		pr_err_ratelimited("failed to allocate zone structure\n");
		res = -ENOMEM;
		goto error;
	}

	/* fill fields */
	if (attrs[KZNL_ATTR_ACCOUNTING_COUNTER_NUM]) {
		res = kznl_parse_count(attrs[KZNL_ATTR_ACCOUNTING_COUNTER_NUM], &count);
		if (res < 0) {
			pr_err_ratelimited("failed to parse service acoouting counter\n");
			goto error_put_zone;
		}
		atomic64_set(&zone->count, count);
	}

	res = kznl_parse_name_alloc(attrs[KZNL_ATTR_ZONE_NAME], &zone->name);
	if (res < 0) {
		pr_err_ratelimited("failed to parse zone name\n");
		goto error_put_zone;
	}

	if (attrs[KZNL_ATTR_ZONE_PNAME]) {
		res = kznl_parse_name_alloc(attrs[KZNL_ATTR_ZONE_PNAME], parent_name);
		if (res < 0) {
			pr_err_ratelimited("failed to parse parent name\n");
			goto error_put_zone;
		}
	}

	zone->alloc_subnet = ntohl(nla_get_be32(attrs[KZNL_ATTR_ZONE_SUBNET_NUM]));

	if (_zone)
		*_zone = zone;
	return 0;

error_put_zone:
	kz_zone_put(zone);

error:
	return res;
}

static int
kznl_zone_set_from_parent(struct kz_zone *zone,
			  const char *parent_name,
			  struct kz_transaction *tr)
{
	struct kz_zone *parent_zone;

	/* look up parent zone by name:
	 * it's either been added in this transaction or is present in the global
	 * zone list (should check iff the transaction does not have the FLUSH
	 * flag set) */
	if (parent_name != NULL) {
		parent_zone = lookup_zone_merged(tr, parent_name);
		if (parent_zone == NULL) {
			pr_err_ratelimited("parent zone not found; name='%s'\n", parent_name);
			return -ENOENT;
		}

		zone->admin_parent = kz_zone_get(parent_zone);
		/* there's an implicit dependency here on the zones being ordered
		 * so that we've already set up the depth of the parent zone */
		zone->depth = parent_zone->depth + 1;
	}

	return 0;
}

static int
kznl_lock_transaction(u32 snd_pid, struct kz_transaction **_tr)
{
	struct kz_transaction *tr;

	/* look up transaction */
	LOCK_TRANSACTIONS();

	tr = transaction_lookup(snd_pid);
	if (tr == NULL) {
		pr_err_ratelimited("no transaction found; pid='%d'\n", snd_pid);
		return -ENOENT;
	}

	*_tr = tr;
	return 0;
}


static int
kznl_recv_add_zone_subnet(struct sk_buff *skb, struct genl_info *info)
{
	int res = 0;
	char *zone_name = NULL;
	struct kz_zone *zone;
	struct kz_subnet zone_subnet;
	struct kz_transaction *tr;

	if (!info->attrs[KZNL_ATTR_ZONE_NAME]) {
		pr_err_ratelimited("required attribtues missing; attr='zone name'\n");
		res = -EINVAL;
		goto error;
	}

	if (!info->attrs[KZNL_ATTR_ZONE_SUBNET]) {
		pr_err_ratelimited("required attribtues missing; attr='zone subnet'\n");
		res = -EINVAL;
		goto error;
	}

	res = kznl_parse_name_alloc(info->attrs[KZNL_ATTR_ZONE_NAME], &zone_name);
	if (res < 0) {
		pr_err_ratelimited("failed to parse zone name\n");
		goto error;
	}

	kznl_parse_inet_subnet(info->attrs[KZNL_ATTR_ZONE_SUBNET], &zone_subnet.addr, &zone_subnet.mask, &zone_subnet.family);
	if (res < 0) {
		pr_err_ratelimited("failed to parse zone subnet\n");
		goto error_free_names;
	}

	/* look up transaction */
	LOCK_TRANSACTIONS();

	tr = transaction_lookup(info->snd_portid);
	if (tr == NULL) {
		pr_err_ratelimited("no transaction found; pid='%d'\n", info->snd_portid);
		res = -ENOENT;
		goto error_unlock_tr;
	}

	/* look up zone */
	zone = lookup_zone_merged(tr, zone_name);
	if (zone == NULL) {
		pr_err_ratelimited("zone not found; name='%s'\n", zone_name);
		res = -ENOENT;
		goto error_unlock_zone;
	}

	res = kz_add_zone_subnet(zone, &zone_subnet);
	if (res < 0) {
		pr_err_ratelimited("failed to add subnet to zone; zone_name='%s'", zone_name);
		goto error_unlock_zone;
	}

error_unlock_zone:
error_unlock_tr:
	UNLOCK_TRANSACTIONS();

error_free_names:
	kfree(zone_name);

error:
	return res;

}

static int
kznl_recv_add_zone(struct sk_buff *skb, struct genl_info *info)
{
	int res = 0;
	struct kz_zone *zone;
	struct kz_transaction *tr;
	char *parent_name = NULL;

	if ((res = kznl_parse_add_zone_params(info->attrs, &zone, &parent_name)))
		return res;

	if ((res = kznl_lock_transaction(info->snd_portid, &tr)) < 0)
		goto error_unlock_tr;

	if ((res = kznl_zone_set_from_parent(zone, parent_name, tr)) < 0)
		goto error_unlock_op;

	if ((res = kz_add_zone(zone)) < 0)
		goto error_unlock_op;

	if ((res = transaction_add_op(tr, KZNL_OP_ADD_ZONE, kz_zone_get(zone), transaction_destroy_zone)) < 0)
		pr_err_ratelimited("failed to queue transaction operation\n");

error_unlock_op:
error_unlock_tr:
	UNLOCK_TRANSACTIONS();

	if (parent_name != NULL)
		kfree(parent_name);

	kz_zone_put(zone);

	return res;
}

static int
kznl_validate_update_zone_params(struct kz_zone *zone,
				 struct kz_transaction *tr)
{
	/* check that we don't yet have a zone with the same name */
	if (lookup_zone_merged(tr, zone->name) == NULL) {
		pr_err_ratelimited("zone with the given name not found; name='%s'\n", zone->name);
		return -ENOENT;
	}

	return 0;
}

static int
kznl_parse_delete_zone_params(struct nlattr * const * const attrs, struct kz_zone **_zone)
{
	int res = 0;
	struct kz_zone *zone;

	if (!attrs[KZNL_ATTR_ZONE_NAME]) {
		pr_err_ratelimited("required attribute missing: name\n");
		res = -EINVAL;
		goto error;
	}

	/* allocate zone structure */
	zone = kz_zone_new();
	if (zone == NULL) {
		pr_err_ratelimited("failed to allocate zone structure\n");
		res = -ENOMEM;
		goto error;
	}

	if ((res = kznl_parse_name_alloc(attrs[KZNL_ATTR_ZONE_NAME], &zone->name)) < 0) {
		pr_err_ratelimited("failed to parse name\n");
		goto error_put_zone;
	}

	if (_zone)
		*_zone = zone;
	return 0;

error_put_zone:
	kz_zone_put(zone);

error:
	return res;
}

static int
kznl_validate_delete_zone_params(struct kz_zone *zone,
				 struct kz_transaction *tr)
{
	return kznl_validate_update_zone_params(zone, tr);
}


static int
kznl_recv_delete_zone(struct sk_buff *skb, struct genl_info *info)
{
	int res = 0;
	struct kz_zone *zone = NULL;
	struct kz_transaction *tr;

	if ((res = kznl_parse_delete_zone_params(info->attrs, &zone)) < 0)
		return res;

	if ((res = kznl_lock_transaction(info->snd_portid, &tr)) < 0)
		goto error_unlock_tr;

	if ((res = kznl_validate_delete_zone_params(zone, tr)) < 0)
		goto error_unlock_op;

	if ((res = transaction_add_op(tr, KZNL_OP_DELETE_ZONE, kz_zone_get(zone), transaction_destroy_zone)) < 0)
		pr_err_ratelimited("failed to queue transaction operation\n");

error_unlock_op:
error_unlock_tr:
	UNLOCK_TRANSACTIONS();

	kz_zone_put(zone);

	return res;
}

/* zone dumps */

static int
kznl_build_zone_add_subnet(struct sk_buff *skb, u_int32_t pid, u_int32_t seq,
			   int flags, enum kznl_msg_types msg,
			   const struct kz_zone * const zone,
			   const struct kz_subnet * const subnet)
{
	void *hdr;

	hdr = genlmsg_put(skb, pid, seq, &kznl_family, flags, msg);
	if (!hdr)
		goto nla_put_failure;

	if (kznl_dump_name(skb, KZNL_ATTR_ZONE_NAME, zone->name) < 0)
		goto nla_put_failure;

	if (kznl_dump_inet_subnet(skb, KZNL_ATTR_ZONE_SUBNET, subnet->family, &subnet->addr, &subnet->mask) < 0)
		goto nla_put_failure;

	genlmsg_end(skb, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -1;
}


static int
kznl_build_zone_add(struct sk_buff *skb, netlink_port_t pid, u_int32_t seq, int flags,
		    enum kznl_msg_types msg, const struct kz_zone *zone)
{
	void *hdr;

	hdr = genlmsg_put(skb, pid, seq, &kznl_family, flags, msg);
	if (!hdr)
		goto nla_put_failure;

	if (kznl_dump_name(skb, KZNL_ATTR_ZONE_NAME, zone->name) < 0)
		goto nla_put_failure;

	if (nla_put_be32(skb, KZNL_ATTR_ZONE_SUBNET_NUM, htonl(zone->num_subnet)))
		goto nla_put_failure;

	if (zone->admin_parent != NULL) {
		if (kznl_dump_name(skb, KZNL_ATTR_ZONE_PNAME, zone->admin_parent->name) < 0)
			goto nla_put_failure;
	}

	if (kznl_dump_count(skb, KZNL_ATTR_ACCOUNTING_COUNTER_NUM, atomic64_read(&zone->count)))
		goto nla_put_failure;

	genlmsg_end(skb, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -1;
}

enum {
	ZONE_DUMP_ARG_CURRENT_ZONE,
	ZONE_DUMP_ARG_SUBNET_SUBPART,
	ZONE_DUMP_ARG_STATE,
	ZONE_DUMP_ARG_CONFIG_GENERATION,
};

enum {
	ZONE_DUMP_STATE_FIRST_CALL,
	ZONE_DUMP_STATE_HAVE_CONFIG,
	ZONE_DUMP_STATE_NO_MORE_WORK,
};

static int
kznl_build_zone(struct sk_buff *skb, u_int32_t pid, u_int32_t seq, int flags,
		      const struct kz_zone *zone, long *part_idx)
{
	unsigned char *msg_start, *msg_rollback;

	/* part_idx: inout param; must be set to item to resume on next call or 0 for completion */

	msg_start = skb_tail_pointer(skb);
	msg_rollback = msg_start;

	pr_debug("part_idx=%ld, num_subnet=%d", *part_idx, zone->num_subnet);
	if (*part_idx == ZONE_DUMP_STATE_FIRST_CALL) {
		msg_rollback = skb_tail_pointer(skb);
		/* *part_idx and *entry_idx is left pointing the failed item */
		if (kznl_build_zone_add(skb, pid, seq, flags, KZNL_MSG_ADD_ZONE, zone) < 0)
			goto nlmsg_failure;
		*part_idx = ZONE_DUMP_STATE_HAVE_CONFIG;
	}

	/* dump rule structures */
	pr_debug("part_idx=%ld, num_subnet=%d", *part_idx, zone->num_subnet);
	for (; (*part_idx) <= (long) zone->num_subnet; ++(*part_idx)) {
		const struct kz_subnet const * subnet = &zone->subnet[(*part_idx) - 1];
		pr_debug("part_idx=%ld", *part_idx);

		msg_rollback = skb_tail_pointer(skb);
		if (kznl_build_zone_add_subnet(skb, pid, seq, flags,
					   KZNL_MSG_ADD_ZONE_SUBNET,
					   zone, subnet) < 0)
			goto nlmsg_failure;
	}

	*part_idx = ZONE_DUMP_STATE_FIRST_CALL;
	return skb_tail_pointer(skb) - msg_start;

nlmsg_failure:
	/* *part_idx is left pointing the failed item */
	skb_trim(skb, msg_rollback - skb->data);
	return -1;
}

static int
kznl_dump_zones(struct sk_buff *skb, struct netlink_callback *cb)
{
	const struct kz_zone *i = NULL;
	const struct kz_config * cfg;

	/*
	 * race condition recovery: restart dump
	 * (if this turns to be a problem, cfg shall be refcounted!)
	 *
	 * on first entry cb->args is all-0
	 */

	/* check if we've finished the dump */
	if (cb->args[ZONE_DUMP_ARG_STATE] == ZONE_DUMP_STATE_NO_MORE_WORK)
		return skb->len;

	rcu_read_lock();
	cfg = rcu_dereference(kz_config_rcu);
	if (cb->args[ZONE_DUMP_ARG_STATE] == ZONE_DUMP_STATE_FIRST_CALL ||
	    !kz_generation_valid(cfg, cb->args[ZONE_DUMP_ARG_CONFIG_GENERATION])) {
		cb->args[ZONE_DUMP_ARG_CURRENT_ZONE] = (long) list_first_entry(&cfg->zones.head, struct kz_zone, list);
		cb->args[ZONE_DUMP_ARG_SUBNET_SUBPART] = 0;
		cb->args[ZONE_DUMP_ARG_STATE] = ZONE_DUMP_STATE_HAVE_CONFIG;
		cb->args[ZONE_DUMP_ARG_CONFIG_GENERATION] = kz_generation_get(cfg);
	}

	list_find_or_first(i, &cfg->zones.head, list, (struct kz_zone *) cb->args[ZONE_DUMP_ARG_CURRENT_ZONE]);
	list_for_each_entry_from(i, &cfg->zones.head, list) {
		pr_debug("zone name: '%s'", i->name);
		if (kznl_build_zone(skb, NETLINK_CB(cb->skb).portid,
				   cb->nlh->nlmsg_seq, 0, i, &cb->args[ZONE_DUMP_ARG_SUBNET_SUBPART]) < 0) {
			/* zone dump failed, try to continue from here next time */
			cb->args[ZONE_DUMP_ARG_CURRENT_ZONE] = (long) i;
			goto out;
		}
	}

	/* done */
	cb->args[ZONE_DUMP_ARG_STATE] = ZONE_DUMP_STATE_NO_MORE_WORK;

out:
	rcu_read_unlock();

	return skb->len;
}

static int
kznl_recv_get_zone(struct sk_buff *skb, struct genl_info *info)
{
	int res = 0;
	long idx = 0;
	char *zone_name = NULL;
	struct kz_zone *zone;
	struct sk_buff *nskb = NULL;
	const struct kz_config * cfg;

	/* parse attributes */
	if (!info->attrs[KZNL_ATTR_ZONE_UNAME]) {
		pr_err_ratelimited("required name attribute missing\n");
		res = -EINVAL;
		goto error;
	}

	res = kznl_parse_name_alloc(info->attrs[KZNL_ATTR_ZONE_UNAME], &zone_name);
	if (res < 0) {
		pr_err_ratelimited("failed to parse zone name\n");
		goto error;
	}

	rcu_read_lock();
	cfg = rcu_dereference(kz_config_rcu);

	zone = kz_zone_lookup_name(cfg, zone_name);
	if (zone == NULL) {
		pr_debug("no such zone found\n");
		res = -ENOENT;
		goto error_unlock_zone;
	}

	/* create skb and dump */
	nskb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!nskb) {
		pr_err_ratelimited("failed to allocate reply message\n");
		res = -ENOMEM;
		goto error_unlock_zone;
	}

	if (kznl_build_zone(nskb, info->snd_portid,
			    info->snd_seq, 0, zone, &idx) < 0) {
		/* data did not fit in a single entry -- for now no support of continuation
		   we could loop and multicast; we chose not to send the partial info */
		pr_err_ratelimited("failed to create zone messages\n");
		nlmsg_free(nskb);
		res = -ENOMEM;
	} else {
		res = genlmsg_reply(nskb, info);
	}

error_unlock_zone:
	rcu_read_unlock();

	if (zone_name != NULL)
		kfree(zone_name);

error:
	return res;
}

static int
kznl_recv_add_service(struct sk_buff *skb, struct genl_info *info)
{
	int res = 0;
	struct kz_service *svc, *p;
	struct kz_transaction *tr;
	u_int64_t count;

	if (!info->attrs[KZNL_ATTR_SERVICE_PARAMS] || !info->attrs[KZNL_ATTR_SERVICE_NAME]) {
		pr_err_ratelimited("required attributes missing\n");
		res = -EINVAL;
		goto error;
	}

	/* allocate service structure */
	svc = kz_service_new();
	if (svc == NULL) {
		pr_err_ratelimited("failed to allocate service structure\n");
		res = -ENOMEM;
		goto error;
	}

	/* fill fields */
	res = kznl_parse_service_params(info->attrs[KZNL_ATTR_SERVICE_PARAMS], svc);
	if (res < 0 ||
	    (svc->type != KZ_SERVICE_PROXY && svc->type != KZ_SERVICE_FORWARD && svc->type != KZ_SERVICE_DENY)) {
		pr_err_ratelimited("failed to parse service parameters\n");
		goto error_put_svc;
	}

	/* forwarded service, not transparent -> we need router destination */
	if (svc->type == KZ_SERVICE_FORWARD && !(svc->flags & KZF_SERVICE_TRANSPARENT)) {
		if (!info->attrs[KZNL_ATTR_SERVICE_ROUTER_DST_PORT]) {
			pr_err_ratelimited("required router destination port attribute missing\n");
			res = -EINVAL;
			goto error_put_svc;
		}
		if (!info->attrs[KZNL_ATTR_SERVICE_ROUTER_DST_ADDR]) {
			pr_err_ratelimited("required router destination address attribute missing\n");
			res = -EINVAL;
			goto error_put_svc;
		}
	}

	/* for deny service we require the reject type to be specified */
	if (svc->type == KZ_SERVICE_DENY) {
		if (!info->attrs[KZNL_ATTR_SERVICE_DENY_IPV4_METHOD]) {
			pr_err_ratelimited("required IPv4 reject method attribute missing\n");
			res = -EINVAL;
			goto error_put_svc;
		}
		if (!info->attrs[KZNL_ATTR_SERVICE_DENY_IPV6_METHOD]) {
			pr_err_ratelimited("required IPv6 reject method attribute missing\n");
			res = -EINVAL;
			goto error_put_svc;
		}
	}

	res = kznl_parse_name_alloc(info->attrs[KZNL_ATTR_SERVICE_NAME], &svc->name);
	if (res < 0) {
		pr_err_ratelimited("failed to parse service name\n");
		goto error_put_svc;
	}

	if (info->attrs[KZNL_ATTR_ACCOUNTING_COUNTER_NUM]) {
		res = kznl_parse_count(info->attrs[KZNL_ATTR_ACCOUNTING_COUNTER_NUM], &count);
		if (res < 0) {
			pr_err_ratelimited("failed to parse service acoouting counter\n");
			goto error_put_svc;
		}
		atomic64_set(&svc->count, count);
	}

	switch (svc->type) {
	case KZ_SERVICE_PROXY:
		pr_debug("service structure created, proxy type\n");
		break;

	case KZ_SERVICE_FORWARD:
		INIT_LIST_HEAD(&svc->a.fwd.snat);
		INIT_LIST_HEAD(&svc->a.fwd.dnat);

		/* for non-transparent services we also need the router target address */
		if (!(svc->flags & KZF_SERVICE_TRANSPARENT)) {
			res = kznl_parse_service_router_dst(info->attrs, svc);
			if (res < 0) {
				pr_err_ratelimited("failed to parse router target address\n");
				goto error_put_svc;
			}
		}

		pr_debug("service structure created, forwarded type\n");
		break;

	case KZ_SERVICE_DENY:
		res = kznl_parse_service_ipv4_deny_method(info->attrs[KZNL_ATTR_SERVICE_DENY_IPV4_METHOD],
							  &svc->a.deny.ipv4_reject_method);
		if (res < 0) {
			pr_err_ratelimited("failed to parse deny service IPv4 reject method\n");
			goto error_put_svc;
		}

		res = kznl_parse_service_ipv6_deny_method(info->attrs[KZNL_ATTR_SERVICE_DENY_IPV6_METHOD],
							  &svc->a.deny.ipv6_reject_method);
		if (res < 0) {
			pr_err_ratelimited("failed to parse deny service IPv6 reject method\n");
			goto error_put_svc;
		}

		pr_debug("service structure created, deny type\n");
		break;

	default:
		pr_err_ratelimited("invalid service type specified; type='%d'\n", svc->type);
		res = -EINVAL;
		goto error_put_svc;
	}

	/* look up transaction */
	LOCK_TRANSACTIONS();

	tr = transaction_lookup(info->snd_portid);
	if (tr == NULL) {
		pr_err_ratelimited("no transaction found; pid='%d'\n", info->snd_portid);
		res = -ENOENT;
		goto error_unlock_tr;
	}

	svc->instance_id = tr->instance_id;

	/* check that we don't yet have a service with the same name */
	p = transaction_service_lookup(tr, svc->name);
	if (p != NULL) {
		pr_err_ratelimited("service with the same name already present; name='%s'\n", svc->name);
		res = -EEXIST;
		goto error_unlock_op;
	}

	p = kz_service_lookup_name(tr->cfg, svc->name);
	if (p != NULL) {
		if ((p->instance_id != tr->instance_id) ||
		    !(tr->flags & KZF_TRANSACTION_FLUSH_SERVICES)) {
			pr_err_ratelimited("service with the same name already present; name='%s'\n", svc->name);
			res = -EEXIST;
			goto error_unlock_op;
		}
	}

	res = transaction_add_op(tr, KZNL_OP_ADD_SERVICE, kz_service_get(svc), transaction_destroy_service);
	if (res < 0) {
		pr_err_ratelimited("failed to queue transaction operation\n");
	}

error_unlock_op:
error_unlock_tr:
	UNLOCK_TRANSACTIONS();

error_put_svc:
	kz_service_put(svc);

error:
	return res;
}

static int
kznl_recv_add_service_nat(struct sk_buff *skb, struct genl_info *info, bool snat)
{
	int res = 0;
	struct kz_service *svc;
	struct kz_transaction *tr;
	char *service_name = NULL;
	struct nf_nat_range src, dst, map;
	sa_family_t family;
	sa_family_t tmp_family;

	if (info->genlhdr->version != 2) {
		pr_err_ratelimited("Version %d of KZNL_MSG_ADD_SERVICE_NAT_* is not supported in this version of KZorp\n", info->genlhdr->version);
		res = -EINVAL;
		goto error;
	}

	/* SERVICE_NAME */
	if (!info->attrs[KZNL_ATTR_SERVICE_NAME]) {
		pr_err_ratelimited("required attribute SERVICE_NAME missing\n");
		res = -EINVAL;
		goto error;
	}
	res = kznl_parse_name_alloc(info->attrs[KZNL_ATTR_SERVICE_NAME],
				    &service_name);
	if (res < 0) {
		pr_err_ratelimited("failed to parse SERVICE_NAME\n");
		goto error;
	}

	/* SERVICE_NAT_SRC_* */
	if (!info->attrs[KZNL_ATTR_SERVICE_NAT_SRC_MIN_IP] ||
	    !info->attrs[KZNL_ATTR_SERVICE_NAT_SRC_MAX_IP]) {
		pr_err_ratelimited
		    ("required attribute SERVICE_NAT_SRC_{MIN,MAX} missing\n");
		res = -EINVAL;
		goto error;
	}
	memset(&src, 0, sizeof(src));
	res = kznl_parse_inet_addr(info->attrs[KZNL_ATTR_SERVICE_NAT_SRC_MIN_IP],
				   &src.min_addr, &family);
	if (res < 0) {
		pr_err_ratelimited("failed to parse SERVICE_NAT_SRC_MIN_IP\n");
		goto error;
	}
	res = kznl_parse_inet_addr(info->attrs[KZNL_ATTR_SERVICE_NAT_SRC_MAX_IP],
				   &src.max_addr, &tmp_family);
	if (res < 0) {
		pr_err_ratelimited("failed to parse SERVICE_NAT_SRC_MAX_IP\n");
		goto error;
	}
	if (tmp_family != family) {
		pr_err_ratelimited("inconsistent IP version\n");
		goto error;
	}
	family = tmp_family;
	src.flags = NF_NAT_RANGE_MAP_IPS;

	/* SERVICE_NAT_DST_* */
	memset(&dst, 0, sizeof(dst));
	if (!info->attrs[KZNL_ATTR_SERVICE_NAT_DST_MIN_IP] ||
	    !info->attrs[KZNL_ATTR_SERVICE_NAT_DST_MAX_IP]) {
		pr_err_ratelimited
		    ("required attribute SERVICE_NAT_DST_{MIN,MAX} missing\n");
		res = -EINVAL;
		goto error;
	}
	res = kznl_parse_inet_addr(info->attrs[KZNL_ATTR_SERVICE_NAT_DST_MIN_IP],
				   &dst.min_addr, &tmp_family);
	if (res < 0) {
		pr_err_ratelimited("failed to parse SERVICE_NAT_DST_MIN_IP\n");
		goto error;
	}
	if (tmp_family != family) {
		pr_err_ratelimited("inconsistent IP version\n");
		goto error;
	}
	family = tmp_family;
	res = kznl_parse_inet_addr(info->attrs[KZNL_ATTR_SERVICE_NAT_DST_MAX_IP],
				   &dst.max_addr, &tmp_family);
	if (res < 0) {
		pr_err_ratelimited("failed to parse SERVICE_NAT_DST_MAX_IP\n");
		goto error;
	}
	if (tmp_family != family) {
		pr_err_ratelimited("inconsistent IP version\n");
		goto error;
	}
	family = tmp_family;
	dst.flags = NF_NAT_RANGE_MAP_IPS;

	/* SERVICE_NAT_MAP_* */
	if (!info->attrs[KZNL_ATTR_SERVICE_NAT_MAP_MIN_IP] ||
	    !info->attrs[KZNL_ATTR_SERVICE_NAT_MAP_MAX_IP]) {
		pr_err_ratelimited
		    ("required attribute SERVICE_NAT_MAP_{MIN,MAX} missing\n");
		res = -EINVAL;
		goto error;
	}
	memset(&map, 0, sizeof(map));
	res = kznl_parse_inet_addr(info->attrs[KZNL_ATTR_SERVICE_NAT_MAP_MIN_IP],
				   &map.min_addr, &tmp_family);
	if (res < 0) {
		pr_err_ratelimited("failed to parse SERVICE_NAT_MAP_MIN_IP\n");
		goto error;
	}
	if (tmp_family != family) {
		pr_err_ratelimited("inconsistent IP version\n");
		goto error;
	}
	family = tmp_family;
	res = kznl_parse_inet_addr(info->attrs[KZNL_ATTR_SERVICE_NAT_MAP_MAX_IP],
				   &map.max_addr, &tmp_family);
	if (res < 0) {
		pr_err_ratelimited("failed to parse SERVICE_NAT_MAP_MAX_IP\n");
		goto error;
	}
	if (tmp_family != family) {
		pr_err_ratelimited("inconsistent IP version\n");
		goto error;
	}
	family = tmp_family;
	map.flags = NF_NAT_RANGE_MAP_IPS;

	/* look up transaction */
	LOCK_TRANSACTIONS();

	tr = transaction_lookup(info->snd_portid);
	if (tr == NULL) {
		pr_err_ratelimited("no transaction found; pid='%u'\n", info->snd_portid);
		res = -ENOENT;
		goto error_unlock_tr;
	}

	/* look up service */
	svc = transaction_service_lookup(tr, service_name);
	if (svc == NULL) {
		pr_err_ratelimited("no such service found; name='%s'\n", service_name);
		res = -ENOENT;
		goto error_unlock_tr;
	}

	if (snat)
		res = kz_service_add_nat_entry(&svc->a.fwd.snat, &src,
					       &dst, &map,
					       family == AF_INET ? NFPROTO_IPV4 : NFPROTO_IPV6);
	else
		res = kz_service_add_nat_entry(&svc->a.fwd.dnat, &src,
					       &dst, &map,
					       family == AF_INET ? NFPROTO_IPV4 : NFPROTO_IPV6);

error_unlock_tr:
	UNLOCK_TRANSACTIONS();

error:
	if (service_name != NULL)
		kfree(service_name);
	return res;
}

static int
kznl_recv_add_service_nat_src(struct sk_buff *skb, struct genl_info *info)
{
	return kznl_recv_add_service_nat(skb, info, true);
}

static int
kznl_recv_add_service_nat_dst(struct sk_buff *skb, struct genl_info *info)
{
	return kznl_recv_add_service_nat(skb, info, false);
}

static int
kznl_build_service_add_nat(struct sk_buff *skb, netlink_port_t pid,
			   u_int32_t seq, int flags, enum kznl_msg_types msg,
			   const struct kz_service *svc,
			   struct kz_service_nat_entry *entry)
{
	void *hdr;

	hdr = genlmsg_put(skb, pid, seq, &kznl_family, flags, msg);
	if (!hdr)
		goto nla_put_failure;

	if (kznl_dump_name(skb, KZNL_ATTR_SERVICE_NAME, svc->name) < 0)
		goto nlmsg_failure;

	if (kznl_dump_inet_addr(skb, KZNL_ATTR_SERVICE_NAT_SRC_MIN_IP,
				entry->l3proto == NFPROTO_IPV4 ? AF_INET : AF_INET6,
				&entry->src.min_addr))
		goto nlmsg_failure;
	if (kznl_dump_inet_addr(skb, KZNL_ATTR_SERVICE_NAT_SRC_MAX_IP,
				entry->l3proto == NFPROTO_IPV4 ? AF_INET : AF_INET6,
				&entry->src.max_addr))
		goto nlmsg_failure;

	if (kznl_dump_inet_addr(skb, KZNL_ATTR_SERVICE_NAT_DST_MIN_IP,
				entry->l3proto == NFPROTO_IPV4 ? AF_INET : AF_INET6,
				&entry->dst.min_addr))
		goto nlmsg_failure;
	if (kznl_dump_inet_addr(skb, KZNL_ATTR_SERVICE_NAT_DST_MAX_IP,
				entry->l3proto == NFPROTO_IPV4 ? AF_INET : AF_INET6,
				&entry->dst.max_addr))
		goto nlmsg_failure;

	if (kznl_dump_inet_addr(skb, KZNL_ATTR_SERVICE_NAT_MAP_MIN_IP,
				entry->l3proto == NFPROTO_IPV4 ? AF_INET : AF_INET6,
				&entry->map.min_addr))
		goto nlmsg_failure;
	if (kznl_dump_inet_addr(skb, KZNL_ATTR_SERVICE_NAT_MAP_MAX_IP,
				entry->l3proto == NFPROTO_IPV4 ? AF_INET : AF_INET6,
				&entry->map.max_addr))
		goto nlmsg_failure;

	genlmsg_end(skb, hdr);
	return 0;

nlmsg_failure:
nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -1;
}

static int
kznl_build_service_add(struct sk_buff *skb, netlink_port_t pid, u_int32_t seq, int flags,
		       enum kznl_msg_types msg, const struct kz_service *svc)
{
	void *hdr;
	struct kza_service_params params;

	hdr = genlmsg_put(skb, pid, seq, &kznl_family, flags, msg);
	if (!hdr)
		goto nla_put_failure;

	params.type = svc->type;
	params.flags = htonl(svc->flags & KZF_SERVICE_PUBLIC_FLAGS);
	if (nla_put(skb, KZNL_ATTR_SERVICE_PARAMS, sizeof(params), &params))
		goto nla_put_failure;

	if (kznl_dump_name(skb, KZNL_ATTR_SERVICE_NAME, svc->name) < 0)
		goto nla_put_failure;

	switch (svc->type) {
	case KZ_SERVICE_PROXY:
		/* no extra attributes for proxy services */
		break;

	case KZ_SERVICE_FORWARD:
		if (!(svc->flags & KZF_SERVICE_TRANSPARENT)) {
			if (kznl_dump_inet_addr(skb, KZNL_ATTR_SERVICE_ROUTER_DST_ADDR,
						svc->a.fwd.router_dst_addr_family,
						&svc->a.fwd.router_dst_addr) < 0)
				goto nla_put_failure;
			if (kznl_dump_port(skb, KZNL_ATTR_SERVICE_ROUTER_DST_PORT,
					   svc->a.fwd.router_dst_port) < 0)
				goto nla_put_failure;
		}
		break;

	case KZ_SERVICE_DENY:
		if (kznl_dump_service_deny_method(skb, KZNL_ATTR_SERVICE_DENY_IPV4_METHOD,
						  svc->a.deny.ipv4_reject_method) < 0)
			goto nla_put_failure;
		if (kznl_dump_service_deny_method(skb, KZNL_ATTR_SERVICE_DENY_IPV6_METHOD,
						  svc->a.deny.ipv6_reject_method) < 0)
			goto nla_put_failure;
		break;

	case KZ_SERVICE_INVALID:
	case KZ_SERVICE_TYPE_COUNT:
		BUG();
		break;
	}

	if (kznl_dump_count(skb, KZNL_ATTR_ACCOUNTING_COUNTER_NUM, atomic64_read(&svc->count)))
		goto nla_put_failure;

	genlmsg_end(skb, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -1;
}

static int
kznl_build_service(struct sk_buff *skb, netlink_port_t pid, u_int32_t seq, int flags,
		   const struct kz_service *svc)
{
	struct kz_service_nat_entry *entry;
	unsigned char *msg_start;

	msg_start = skb_tail_pointer(skb);

	if (kznl_build_service_add(skb, pid, seq, flags, KZNL_MSG_ADD_SERVICE, svc) < 0)
		goto nlmsg_failure;

	/* NAT entries */
	if (svc->type == KZ_SERVICE_FORWARD) {
		/* source */
		list_for_each_entry(entry, &svc->a.fwd.snat, list)
			if (kznl_build_service_add_nat(skb, pid, seq, flags,
						       KZNL_MSG_ADD_SERVICE_NAT_SRC,
						       svc, entry) < 0)
				goto nlmsg_failure;
		/* destination */
		list_for_each_entry(entry, &svc->a.fwd.dnat, list)
			if (kznl_build_service_add_nat(skb, pid, seq, flags,
						       KZNL_MSG_ADD_SERVICE_NAT_DST,
						       svc, entry) < 0)
				goto nlmsg_failure;
	}

	return skb_tail_pointer(skb) - msg_start;

nlmsg_failure:
	skb_trim(skb, msg_start - skb->data);
	return -1;
}

/* callback argument allocation for service dump */
enum {
	SERVICE_DUMP_CURRENT_SERVICE = 0,
	SERVICE_DUMP_STATE = 3,
	SERVICE_DUMP_CONFIG_GEN = 4,
} kznl_service_dump_args;

/* service dump states */
enum {
	SERVICE_DUMP_STATE_FIRST_CALL = 0,
	SERVICE_DUMP_STATE_HAVE_CONFIG_GEN = 1,
	SERVICE_DUMP_STATE_NO_MORE_WORK = 2,
} kznl_service_dump_state;

static int
kznl_dump_services(struct sk_buff *skb, struct netlink_callback *cb)
{
	const struct kz_service *i, *last;
	const struct kz_config * cfg;

	/*
	 * race condition recovery: restart dump
	 * (if this turns to be a problem, cfg shall be refcounted!)
	 *
	 * on first entry cb->args is all-0
	 */

	/* check if we've finished the dump */
	if (cb->args[SERVICE_DUMP_STATE] == SERVICE_DUMP_STATE_NO_MORE_WORK)
		return skb->len;

	rcu_read_lock();
	cfg = rcu_dereference(kz_config_rcu);
	if (cb->args[SERVICE_DUMP_STATE] == SERVICE_DUMP_STATE_FIRST_CALL ||
	    !kz_generation_valid(cfg, cb->args[SERVICE_DUMP_CONFIG_GEN])) {
		cb->args[SERVICE_DUMP_CONFIG_GEN] = kz_generation_get(cfg);
		cb->args[SERVICE_DUMP_STATE] = SERVICE_DUMP_STATE_HAVE_CONFIG_GEN;
		cb->args[SERVICE_DUMP_CURRENT_SERVICE] = 0;
	}

restart:
	last = (const struct kz_service *)cb->args[SERVICE_DUMP_CURRENT_SERVICE];
	list_for_each_entry(i, &cfg->services.head, list) {
		/* check if we're continuing from a given entry */
		if (last != NULL) {
			if (i == last) {
				/* ok, this was the last entry we've tried to dump */
				cb->args[SERVICE_DUMP_CURRENT_SERVICE] = 0;
				last = NULL;
			} else
				continue;
		}

		if (kznl_build_service(skb, NETLINK_CB(cb->skb).portid,
				       cb->nlh->nlmsg_seq, NLM_F_MULTI, i) < 0) {
			/* service dump failed, try to continue from here next time */
			cb->args[SERVICE_DUMP_CURRENT_SERVICE] = (long) i;
			goto out;
		}
	}

	if (last != NULL) {
		/* we've tried to continue an interrupted dump but did not find the
		 * restart point. cannot do any better but start again. */
		cb->args[SERVICE_DUMP_CURRENT_SERVICE] = 0;
		goto restart;
	}

	/* done */
	cb->args[SERVICE_DUMP_STATE] = SERVICE_DUMP_STATE_NO_MORE_WORK;;

out:
	rcu_read_unlock();
	return skb->len;
}

static int
kznl_recv_get_service(struct sk_buff *skb, struct genl_info *info)
{
	int res = 0;
	char *service_name = NULL;
	struct kz_service *svc;
	struct sk_buff *nskb = NULL;

	/* parse attributes */
	if (!info->attrs[KZNL_ATTR_SERVICE_NAME]) {
		pr_err_ratelimited("required name attribute missing\n");
		res = -EINVAL;
		goto error;
	}

	res = kznl_parse_name_alloc(info->attrs[KZNL_ATTR_SERVICE_NAME], &service_name);
	if (res < 0) {
		pr_err_ratelimited("failed to parse service name\n");
		goto error;
	}

	rcu_read_lock();

	svc = kz_service_lookup_name(rcu_dereference(kz_config_rcu), service_name);
	if (svc == NULL) {
		pr_debug("no such service found; name='%s'\n", service_name);
		res = -ENOENT;
		goto error_unlock_svc;
	}

	/* create skb and dump */
	nskb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!nskb) {
		pr_err_ratelimited("failed to allocate reply message\n");
		res = -ENOMEM;
		goto error_unlock_svc;
	}

	if (kznl_build_service(nskb, info->snd_portid,
			       info->snd_seq, 0, svc) < 0) {
		pr_err_ratelimited("failed to create service messages\n");
		nlmsg_free(nskb);
		res = -ENOMEM;
	} else {
		res = genlmsg_reply(nskb, info);
	}

error_unlock_svc:
	rcu_read_unlock();

	if (service_name != NULL)
		kfree(service_name);

error:
	return res;
}

static int
kznl_recv_add_dispatcher(struct sk_buff *skb, struct genl_info *info)
{
	int res = 0;
	struct kz_dispatcher *dpt, *p;
	struct kz_transaction *tr;

	if (!info->attrs[KZNL_ATTR_DISPATCHER_NAME]) {
		pr_err_ratelimited("required attribtues missing\n");
		res = -EINVAL;
		goto error;
	}

	/* allocate dispatcher structure */
	dpt = kz_dispatcher_new();
	if (dpt == NULL) {
		pr_err_ratelimited("failed to allocate dispatcher structure\n");
		res = -ENOMEM;
		goto error;
	}

	/* fill fields */
	res = kznl_parse_name_alloc(info->attrs[KZNL_ATTR_DISPATCHER_NAME], &dpt->name);
	if (res < 0) {
		pr_err_ratelimited("failed to parse dispatcher name\n");
		goto error_put_dpt;
	}

	if (!info->attrs[KZNL_ATTR_DISPATCHER_N_DIMENSION_PARAMS]) {
		pr_err_ratelimited("required attribute missing: n dimension info\n");
		res = -EINVAL;
		goto error_put_dpt;
	}

	res = kznl_parse_dispatcher_n_dimension(info->attrs[KZNL_ATTR_DISPATCHER_N_DIMENSION_PARAMS], dpt);
	if (res < 0) {
		pr_err_ratelimited("failed to parse n dimension attribute\n");
		goto error_put_dpt;
	}

	/* look up transaction */
	LOCK_TRANSACTIONS();

	tr = transaction_lookup(info->snd_portid);
	if (tr == NULL) {
		pr_err_ratelimited("no transaction found; pid='%d'\n", info->snd_portid);
		res = -ENOENT;
		goto error_unlock_tr;
	}

	dpt->instance = kz_instance_lookup_id(tr->instance_id);

	/* check that we don't yet have a dispatcher with the same name */
	p = transaction_dispatcher_lookup(tr, dpt->name);
	if (p != NULL) {
		pr_err_ratelimited("dispatcher with the same name already present; name='%s'\n", dpt->name);
		res = -EEXIST;
		goto error_unlock_op;
	}

	res = transaction_add_op(tr, KZNL_OP_ADD_DISPATCHER, kz_dispatcher_get(dpt), transaction_destroy_dispatcher);
	if (res < 0) {
		pr_err_ratelimited("failed to queue transaction operation\n");
	}

error_unlock_op:
error_unlock_tr:
	UNLOCK_TRANSACTIONS();

error_put_dpt:
	kz_dispatcher_put(dpt);

error:
	return res;
}

static int
kznl_recv_add_n_dimension_rule(struct sk_buff *skb, struct genl_info *info)
{
	int res = 0;
	char *dpt_name = NULL;
	char *svc_name = NULL;
	struct kz_service *svc;
	enum kznl_attr_types attr_type;
	struct kz_dispatcher *dpt;
	struct kz_transaction *tr;
	struct kz_rule rule;

	if (!info->attrs[KZNL_ATTR_N_DIMENSION_RULE_ID]) {
		pr_err_ratelimited("required attribtues missing; attr='rule id'\n");
		res = -EINVAL;
		goto error;
	}

	if (!info->attrs[KZNL_ATTR_DISPATCHER_NAME]) {
		pr_err_ratelimited("required attribtues missing; attr='dispatcher name'\n");
		res = -EINVAL;
		goto error;
	}

	if (!info->attrs[KZNL_ATTR_N_DIMENSION_RULE_SERVICE]) {
		pr_err_ratelimited("required attribtues missing; attr='service name'\n");
		res = -EINVAL;
		goto error;
	}

	res = kznl_parse_name_alloc(info->attrs[KZNL_ATTR_DISPATCHER_NAME], &dpt_name);
	if (res < 0) {
		pr_err_ratelimited("failed to parse dispatcher name\n");
		goto error;
	}

	res = kznl_parse_name_alloc(info->attrs[KZNL_ATTR_N_DIMENSION_RULE_SERVICE], &svc_name);
	if (res < 0) {
		pr_err_ratelimited("failed to parse service name\n");
		goto error_free_dpt_name;
	}

	/* parse attributes */
	memset(&rule, 0, sizeof(struct kz_rule));

	res = kznl_parse_dispatcher_n_dimension_rule(info->attrs, &rule);
	if (res < 0) {
		goto error_free_svc_name;
	}

	for (attr_type = KZNL_ATTR_INVALID; attr_type < KZNL_ATTR_TYPE_COUNT; attr_type++) {
		if (!info->attrs[attr_type])
			continue;

		switch (attr_type) {
#define GENERATE_case_n_dimension_rule_alloc_value_set(DIM_NAME, NL_ATTR_NAME, _, NL_TYPE, ...) \
		case KZNL_ATTR_N_DIMENSION_##NL_ATTR_NAME: \
			rule.alloc_##DIM_NAME = ntohl(*(__be32 *) nla_data(info->attrs[attr_type])); \
			break;

		KZORP_DIM_LIST(GENERATE_case_n_dimension_rule_alloc_value_set, ;);

#undef GENERATE_case_n_dimension_rule_alloc_value_set

		case KZNL_ATTR_DISPATCHER_NAME:
		case KZNL_ATTR_N_DIMENSION_RULE_ID:
		case KZNL_ATTR_N_DIMENSION_RULE_SERVICE:
		case KZNL_ATTR_ACCOUNTING_COUNTER_NUM:
			/* Skip attribute types handled above. */
			break;
		case KZNL_ATTR_INVALID:
		case KZNL_ATTR_INSTANCE_NAME:
		case KZNL_ATTR_ZONE_NAME:
		case KZNL_ATTR_ZONE_UNAME:
		case KZNL_ATTR_ZONE_PNAME:
		case KZNL_ATTR_ZONE_RANGE:
		case KZNL_ATTR_SERVICE_PARAMS:
		case KZNL_ATTR_SERVICE_NAME:
		case KZNL_ATTR_SERVICE_NAT_SRC:
		case KZNL_ATTR_SERVICE_NAT_DST:
		case KZNL_ATTR_SERVICE_NAT_MAP:
		case KZNL_ATTR_SERVICE_SESSION_CNT:
		case KZNL_ATTR_QUERY_PARAMS:
		case KZNL_ATTR_QUERY_REPLY_CLIENT_ZONE:
		case KZNL_ATTR_QUERY_REPLY_SERVER_ZONE:
		case KZNL_ATTR_DISPATCHER_N_DIMENSION_PARAMS:
		case KZNL_ATTR_CONFIG_COOKIE:
		case KZNL_ATTR_INET_ADDR:
		case KZNL_ATTR_INET_SUBNET:
		case KZNL_ATTR_INET6_ADDR:
		case KZNL_ATTR_INET6_SUBNET:
		case KZNL_ATTR_QUERY_PARAMS_SRC_IP:
		case KZNL_ATTR_QUERY_PARAMS_DST_IP:
		case KZNL_ATTR_QUERY_PARAMS_REQID:
		case KZNL_ATTR_QUERY_PARAMS_SRC_PORT:
		case KZNL_ATTR_QUERY_PARAMS_DST_PORT:
		case KZNL_ATTR_QUERY_PARAMS_PROTO_TYPE:
		case KZNL_ATTR_QUERY_PARAMS_PROTO_SUBTYPE:
		case KZNL_ATTR_SERVICE_ROUTER_DST_ADDR:
		case KZNL_ATTR_SERVICE_ROUTER_DST_PORT:
		case KZNL_ATTR_BIND_PROTO:
		case KZNL_ATTR_BIND_PORT:
		case KZNL_ATTR_BIND_ADDR:
		case KZNL_ATTR_MAJOR_VERSION:
		case KZNL_ATTR_COMPAT_VERSION:
		case KZNL_ATTR_SERVICE_DENY_IPV4_METHOD:
		case KZNL_ATTR_SERVICE_DENY_IPV6_METHOD:
		case KZNL_ATTR_ZONE_SUBNET:
		case KZNL_ATTR_ZONE_SUBNET_NUM:
		case KZNL_ATTR_ZONE_IP:
		case KZNL_ATTR_SERVICE_NAT_SRC_MIN_IP:
		case KZNL_ATTR_SERVICE_NAT_SRC_MAX_IP:
		case KZNL_ATTR_SERVICE_NAT_DST_MIN_IP:
		case KZNL_ATTR_SERVICE_NAT_DST_MAX_IP:
		case KZNL_ATTR_SERVICE_NAT_MAP_MIN_IP:
		case KZNL_ATTR_SERVICE_NAT_MAP_MAX_IP:
		case KZNL_ATTR_TYPE_COUNT:
			pr_err_ratelimited("invalid attribute type; attr_type='%d'", attr_type);
			res = -EINVAL;
			goto error_free_svc_name;
		}
	}

	/* look up transaction */
	LOCK_TRANSACTIONS();

	tr = transaction_lookup(info->snd_portid);
	if (tr == NULL) {
		pr_err_ratelimited("no transaction found; pid='%d'\n", info->snd_portid);
		res = -ENOENT;
		goto error_unlock_tr;
	}

	/* check that we have a dispatcher with the same name */
	dpt = transaction_dispatcher_lookup(tr, dpt_name);
	if (dpt == NULL) {
		pr_err_ratelimited("dispatcher not found for the rule; name='%s'\n", dpt_name);
		res = -ENOENT;
		goto error_unlock_tr;
	}

	if (transaction_rule_lookup(tr, dpt_name, rule.id) != NULL) {
		pr_err_ratelimited("rule with the same id already present; id='%u'\n", rule.id);
		res = -EEXIST;
		goto error_unlock_tr;
	}

	svc = lookup_service_merged(tr, svc_name);
	if (svc == NULL) {
		pr_err_ratelimited("service not found; name='%s'\n", svc_name);
		res = -ENOENT;
		goto error_unlock_svc;
	}

	res = kz_dispatcher_add_rule(dpt, svc, &rule);
	if (res < 0) {
		pr_err_ratelimited("failed to add rule; dpt_name='%s', rule_id='%d'\n",
		       dpt_name, rule.id);
		goto error_unlock_svc;
	}

error_unlock_svc:
error_unlock_tr:
	UNLOCK_TRANSACTIONS();

error_free_svc_name:
	kfree(svc_name);

error_free_dpt_name:
	kfree(dpt_name);

error:
	return res;
}

#define KZNL_PARSE_DIMENSION(NAME, TYPE, CONVERTER) \
			TYPE *NAME = nla_data(info->attrs[attr_type]); \
			rule_entry.NAME = CONVERTER(*NAME); \
			rule_entry.has_##NAME = true; \

static int
kznl_recv_add_n_dimension_rule_entry(struct sk_buff *skb, struct genl_info *info)
{
	int res = 0;
	char *dpt_name = NULL, *src_zone_name = NULL, *dst_zone_name = NULL;
	enum kznl_attr_types attr_type;
	struct kz_dispatcher *dpt;
	struct kz_transaction *tr;
	struct kz_rule *rule;
	struct kz_rule_entry_params rule_entry;

	if (!info->attrs[KZNL_ATTR_DISPATCHER_NAME]) {
		pr_err_ratelimited("required attribtues missing; attr='dispatcher name'\n");
		res = -EINVAL;
		goto error;
	}

	if (!info->attrs[KZNL_ATTR_N_DIMENSION_RULE_ID]) {
		pr_err_ratelimited("required attribtues missing; attr='rule id'\n");
		res = -EINVAL;
		goto error;
	}

	res = kznl_parse_name_alloc(info->attrs[KZNL_ATTR_DISPATCHER_NAME], &dpt_name);
	if (res < 0) {
		pr_err_ratelimited("failed to parse dispatcher name\n");
		goto error;
	}

	memset(&rule_entry, 0, sizeof(rule_entry));

	if ((res = kznl_parse_dispatcher_n_dimension_rule_entry(info->attrs, &rule_entry)) < 0)
		goto error_free_names;

	for (attr_type = KZNL_ATTR_INVALID; attr_type < KZNL_ATTR_TYPE_COUNT; attr_type++) {
		if (!info->attrs[attr_type])
			continue;

		switch (attr_type) {
		case KZNL_ATTR_N_DIMENSION_IFACE: {
			res = kznl_parse_name(info->attrs[attr_type], (char *) &rule_entry.ifname, sizeof(rule_entry.ifname));
			if (res < 0) {
				pr_err_ratelimited("failed to parse interface name\n");
				goto error_free_names;
			}
			rule_entry.has_ifname = true;
			break;
		}
		case KZNL_ATTR_N_DIMENSION_IFGROUP: {
			__be32 *ifgroup = nla_data(info->attrs[attr_type]);
			rule_entry.ifgroup = ntohl(*ifgroup);
			rule_entry.has_ifgroup = true;
			break;
		}
		case KZNL_ATTR_N_DIMENSION_PROTO: {
			u_int8_t *proto = nla_data(info->attrs[attr_type]);
			rule_entry.proto = *proto;
			rule_entry.has_proto = true;
			break;
		}
		case KZNL_ATTR_N_DIMENSION_PROTO_TYPE: {
			KZNL_PARSE_DIMENSION(proto_type, __be32, ntohl);
			break;
		}
		case KZNL_ATTR_N_DIMENSION_PROTO_SUBTYPE: {
			KZNL_PARSE_DIMENSION(proto_subtype, __be32, ntohl);
			break;
		}
		case KZNL_ATTR_N_DIMENSION_SRC_PORT: {
			res = kznl_parse_port_range(info->attrs[attr_type], &rule_entry.src_port.from, &rule_entry.src_port.to);
			if (res < 0) {
				pr_err_ratelimited("failed to parse source port range\n");
				goto error_free_names;
			}
			rule_entry.has_src_port = true;
			break;
		}
		case KZNL_ATTR_N_DIMENSION_DST_PORT: {
			res = kznl_parse_port_range(info->attrs[attr_type], &rule_entry.dst_port.from, &rule_entry.dst_port.to);
			if (res < 0) {
				pr_err_ratelimited("failed to parse source port range\n");
				goto error_free_names;
			}
			rule_entry.has_dst_port = true;
			break;
		}
		case KZNL_ATTR_N_DIMENSION_SRC_IP: {
			res = kznl_parse_in_subnet(info->attrs[attr_type], &rule_entry.src_in_subnet.addr, &rule_entry.src_in_subnet.mask);
			if (res < 0) {
				pr_err_ratelimited("failed to parse source subnet\n");
				goto error_free_names;
			}
			rule_entry.has_src_in_subnet = true;
			break;
		}
		case KZNL_ATTR_N_DIMENSION_SRC_ZONE: {
			res = kznl_parse_name_alloc(info->attrs[attr_type], &src_zone_name);
			if (res < 0) {
				pr_err_ratelimited("failed to parse source zone name\n");
				goto error_free_names;
			}
			rule_entry.has_src_zone = true;
			break;
		}
		case KZNL_ATTR_N_DIMENSION_DST_IP: {
			res = kznl_parse_in_subnet(info->attrs[attr_type], &rule_entry.dst_in_subnet.addr, &rule_entry.dst_in_subnet.mask);
			if (res < 0) {
				pr_err_ratelimited("failed to parse destination subnet\n");
				goto error_free_names;
			}
			rule_entry.has_dst_in_subnet = true;
			break;
		}
		case KZNL_ATTR_N_DIMENSION_DST_ZONE: {
			res = kznl_parse_name_alloc(info->attrs[attr_type], &dst_zone_name);
			if (res < 0) {
				pr_err_ratelimited("failed to parse destination zone name\n");
				goto error_free_names;
			}
			rule_entry.has_dst_zone = true;
			break;
		}
		case KZNL_ATTR_N_DIMENSION_SRC_IP6: {
			res = kznl_parse_in6_subnet(info->attrs[attr_type], &rule_entry.src_in6_subnet.addr, &rule_entry.src_in6_subnet.mask);
			if (res < 0) {
				pr_err_ratelimited("failed to parse source IPv6 subnet\n");
				goto error_free_names;
			}
			rule_entry.has_src_in6_subnet = true;
			break;
		}
		case KZNL_ATTR_N_DIMENSION_DST_IP6: {
			res = kznl_parse_in6_subnet(info->attrs[attr_type], &rule_entry.dst_in6_subnet.addr, &rule_entry.dst_in6_subnet.mask);
			if (res < 0) {
				pr_err_ratelimited("failed to parse destination IPv6 subnet\n");
				goto error_free_names;
			}
			rule_entry.has_dst_in6_subnet = true;
			break;
		}
		case KZNL_ATTR_N_DIMENSION_DST_IFACE: {
			res = kznl_parse_name(info->attrs[attr_type], (char *) &rule_entry.dst_ifname, sizeof(rule_entry.dst_ifname));
			if (res < 0) {
				pr_err_ratelimited("failed to parse interface name\n");
				goto error_free_names;
			}
			rule_entry.has_dst_ifname = true;
			break;
		}
		case KZNL_ATTR_N_DIMENSION_DST_IFGROUP: {
			__be32 *dst_ifgroup = nla_data(info->attrs[attr_type]);
			rule_entry.dst_ifgroup = ntohl(*dst_ifgroup);
			rule_entry.has_dst_ifgroup = true;
			break;
		}
		case KZNL_ATTR_N_DIMENSION_REQID: {
			res = kznl_parse_reqid(info->attrs[attr_type], &rule_entry.reqid);
			if (res < 0) {
				pr_err_ratelimited("failed to parse request id\n");
				goto error_free_names;
			}
			rule_entry.has_reqid = true;
			break;
		}
		case KZNL_ATTR_DISPATCHER_NAME:
		case KZNL_ATTR_N_DIMENSION_RULE_ID:
		case KZNL_ATTR_N_DIMENSION_RULE_SERVICE:
			/* Skip attribute types handled above. */
			break;
		case KZNL_ATTR_INVALID:
		case KZNL_ATTR_INSTANCE_NAME:
		case KZNL_ATTR_ZONE_NAME:
		case KZNL_ATTR_ZONE_UNAME:
		case KZNL_ATTR_ZONE_PNAME:
		case KZNL_ATTR_ZONE_RANGE:
		case KZNL_ATTR_SERVICE_PARAMS:
		case KZNL_ATTR_SERVICE_NAME:
		case KZNL_ATTR_SERVICE_NAT_SRC:
		case KZNL_ATTR_SERVICE_NAT_DST:
		case KZNL_ATTR_SERVICE_NAT_MAP:
		case KZNL_ATTR_SERVICE_SESSION_CNT:
		case KZNL_ATTR_QUERY_PARAMS:
		case KZNL_ATTR_QUERY_REPLY_CLIENT_ZONE:
		case KZNL_ATTR_QUERY_REPLY_SERVER_ZONE:
		case KZNL_ATTR_DISPATCHER_N_DIMENSION_PARAMS:
		case KZNL_ATTR_CONFIG_COOKIE:
		case KZNL_ATTR_INET_ADDR:
		case KZNL_ATTR_INET_SUBNET:
		case KZNL_ATTR_INET6_ADDR:
		case KZNL_ATTR_INET6_SUBNET:
		case KZNL_ATTR_QUERY_PARAMS_SRC_IP:
		case KZNL_ATTR_QUERY_PARAMS_DST_IP:
		case KZNL_ATTR_QUERY_PARAMS_REQID:
		case KZNL_ATTR_QUERY_PARAMS_SRC_PORT:
		case KZNL_ATTR_QUERY_PARAMS_DST_PORT:
		case KZNL_ATTR_QUERY_PARAMS_PROTO_TYPE:
		case KZNL_ATTR_QUERY_PARAMS_PROTO_SUBTYPE:
		case KZNL_ATTR_SERVICE_ROUTER_DST_ADDR:
		case KZNL_ATTR_SERVICE_ROUTER_DST_PORT:
		case KZNL_ATTR_BIND_PROTO:
		case KZNL_ATTR_BIND_PORT:
		case KZNL_ATTR_BIND_ADDR:
		case KZNL_ATTR_MAJOR_VERSION:
		case KZNL_ATTR_COMPAT_VERSION:
		case KZNL_ATTR_SERVICE_DENY_IPV4_METHOD:
		case KZNL_ATTR_SERVICE_DENY_IPV6_METHOD:
		case KZNL_ATTR_ZONE_SUBNET:
		case KZNL_ATTR_ZONE_SUBNET_NUM:
		case KZNL_ATTR_ZONE_IP:
		case KZNL_ATTR_ACCOUNTING_COUNTER_NUM:
		case KZNL_ATTR_SERVICE_NAT_SRC_MIN_IP:
		case KZNL_ATTR_SERVICE_NAT_SRC_MAX_IP:
		case KZNL_ATTR_SERVICE_NAT_DST_MIN_IP:
		case KZNL_ATTR_SERVICE_NAT_DST_MAX_IP:
		case KZNL_ATTR_SERVICE_NAT_MAP_MIN_IP:
		case KZNL_ATTR_SERVICE_NAT_MAP_MAX_IP:
		case KZNL_ATTR_TYPE_COUNT:
			pr_err_ratelimited("invalid attribute type; attr_type='%d'", attr_type);
			res = -EINVAL;
			goto error_free_names;
		}
	}

	/* look up transaction */
	LOCK_TRANSACTIONS();

	tr = transaction_lookup(info->snd_portid);
	if (tr == NULL) {
		pr_err_ratelimited("no transaction found; pid='%d'\n", info->snd_portid);
		res = -ENOENT;
		goto error_unlock_tr;
	}

	rule = transaction_rule_lookup(tr, dpt_name, rule_entry.rule_id);
	if (rule == NULL) {
		pr_err_ratelimited("rule not found; id='%d'\n", rule_entry.rule_id);
		res = -ENOENT;
		goto error_unlock_tr;
	}

	/* look up zones */
	if (src_zone_name != NULL) {
		rule_entry.src_zone = lookup_zone_merged(tr, src_zone_name);
		if (rule_entry.src_zone == NULL) {
			pr_err_ratelimited("source zone not found; name='%s'\n", src_zone_name);
			res = -ENOENT;
			goto error_unlock_zone;
		}
	}
	if (dst_zone_name != NULL) {
		rule_entry.dst_zone = lookup_zone_merged(tr, dst_zone_name);
		if (rule_entry.dst_zone == NULL) {
			pr_err_ratelimited("destination zone not found; name='%s'\n", dst_zone_name);
			res = -ENOENT;
			goto error_unlock_zone;
		}
	}

	/* check that we have a dispatcher with the same name */
	dpt = transaction_dispatcher_lookup(tr, dpt_name);
	if (dpt == NULL) {
		pr_err_ratelimited("dispatcher not found for the rule; name='%s'\n", dpt_name);
		res = -ENOENT;
		goto error_unlock_dpt;
	}

	res = kz_dispatcher_add_rule_entry(rule, &rule_entry);
	if (res < 0) {
		pr_err_ratelimited("failed to add rule; dpt_name='%s', rule_id='%d'\n",
		       dpt_name, rule_entry.rule_id);
		goto error_unlock_dpt;
	}

error_unlock_dpt:
error_unlock_zone:
error_unlock_tr:
	UNLOCK_TRANSACTIONS();

error_free_names:
	kfree(dpt_name);
	if (src_zone_name)
		kfree(src_zone_name);
	if (dst_zone_name)
		kfree(dst_zone_name);

error:
	return res;
}

/* !!! must be called with the instance mutex held !!! */
struct kz_bind *
kz_bind_lookup_instance(const struct kz_instance *instance, const struct kz_bind *bind)
{
	struct kz_bind *i;

	kz_bind_debug(bind, "lookup item");
	list_for_each_entry(i, &instance->bind_lookup->list_bind, list) {
		kz_bind_debug(i, "check item");

		if (kz_bind_eq(i, bind))
			return i;
	}

	return NULL;
}

static inline int
kznl_parse_bind_alloc(struct nlattr *attrs[], unsigned int instance_id, struct kz_instance **instance, struct kz_bind **_bind)
{
	int res = 0;
	struct kz_bind *bind;
	char *instance_name = NULL;

	if (!attrs[KZNL_ATTR_INSTANCE_NAME]) {
		pr_err_ratelimited("required attribtues missing; attr='instance'\n");
		res = -EINVAL;
		goto error;
	}

	if (!attrs[KZNL_ATTR_BIND_PROTO]) {
		pr_err_ratelimited("required attribtues missing; attr='protocol'\n");
		res = -EINVAL;
		goto error;
	}

	if (!attrs[KZNL_ATTR_BIND_ADDR]) {
		pr_err_ratelimited("required attribtues missing; attr='bind addr'\n");
		res = -EINVAL;
		goto error;
	}

	if (!attrs[KZNL_ATTR_BIND_PORT]) {
		pr_err_ratelimited("required attribtues missing; attr='bind port'\n");
		res = -EINVAL;
		goto error;
	}

	res = kznl_parse_name_alloc(attrs[KZNL_ATTR_INSTANCE_NAME], &instance_name);
	if (res < 0) {
		pr_err_ratelimited("failed to parse instance name\n");
		goto error;
	}

	*instance = kz_instance_lookup(instance_name);
	if (*instance == NULL) {
		pr_debug("no such instance found; name='%s'\n", instance_name);
		res = -ENOENT;
		goto error_free_name;
	}

	if ((*instance)->id != instance_id) {
		pr_debug("transaction instance id and instance id differs; instance_id='%d' tr_instance_id'%d'\n", (*instance)->id, instance_id);
		res = -EINVAL;
		goto error_free_name;
	}

	bind = kz_bind_new();

	if (kznl_parse_proto(attrs[KZNL_ATTR_BIND_PROTO], &bind->proto) < 0) {
		res = -EINVAL;
		goto error_free_bind;
	}

	if (bind->proto != IPPROTO_TCP && bind->proto != IPPROTO_UDP) {
		pr_err_ratelimited("only TCP and UDP protocols are supported; proto='%d'\n", bind->proto);
		res = -EINVAL;
		goto error_free_bind;
	}

	if (kznl_parse_port(attrs[KZNL_ATTR_BIND_PORT], &bind->port) < 0) {
		res = -EINVAL;
		goto error_free_bind;
	}

	if (kznl_parse_inet_addr(attrs[KZNL_ATTR_BIND_ADDR], &bind->addr, &bind->family) < 0) {
		res = -EINVAL;
		goto error_free_bind;
	}

	*_bind = bind;
	kfree(instance_name);

	return 0;

error_free_bind:
	kfree(bind);
error_free_name:
	kfree(instance_name);
error:
	return res;
}

static int
kznl_recv_add_bind(struct sk_buff *skb, struct genl_info *info)
{
	int res = 0;
	struct kz_transaction *tr;
	struct kz_instance *instance;
	struct kz_bind *bind = NULL, *found_bind;

	/* look up transaction */
	LOCK_TRANSACTIONS();

	tr = transaction_lookup(info->snd_portid);
	if (tr == NULL) {
		pr_err_ratelimited("no transaction found; pid='%d'\n", info->snd_portid);
		res = -ENOENT;
		goto error_unlock_tr;
	}

	res = kznl_parse_bind_alloc(info->attrs, tr->instance_id, &instance, &bind);
	if (res < 0)
		goto error_unlock_tr;
	bind->peer_pid = info->snd_portid;

	found_bind = kz_bind_lookup_instance(instance, bind);
	if (found_bind && !(found_bind->peer_pid == bind->peer_pid && (tr->flags & KZF_TRANSACTION_FLUSH_BIND))) {
		kz_bind_debug(bind, "bind with the same parameters already present in the instance");
		res = -EEXIST;
		goto error_free_bind;
	}

	if (transaction_bind_lookup(tr, bind)) {
		kz_bind_debug(bind, "bind with the same parameters already present in the transaction");
		res = -EEXIST;
		goto error_free_bind;
	}

	res = transaction_add_op(tr, KZNL_OP_ADD_BIND, bind, transaction_destroy_bind);
	if (res < 0) {
		pr_err_ratelimited("failed to queue transaction operation\n");
		goto error_free_bind;
	} else {
		kz_bind_debug(bind, "bind added to transaction operation queue");
	}

error_free_bind:
	if (res < 0)
		kfree(bind);
error_unlock_tr:
	UNLOCK_TRANSACTIONS();

	return res;
}


static int
kznl_dump_bind(struct sk_buff *skb, netlink_port_t pid, u_int32_t seq, int flags,
	       enum kznl_msg_types msg_type, const struct kz_instance *instance, const struct kz_bind *bind)
{
	void *hdr;

	hdr = genlmsg_put(skb, pid, seq, &kznl_family, flags, msg_type);
	if (!hdr)
		goto nla_put_failure;

	kz_bind_debug(bind, "dump bind");

	if (nla_put_u8(skb, KZNL_ATTR_BIND_PROTO, bind->proto))
		goto nla_put_failure;
	if (nla_put_be16(skb, KZNL_ATTR_BIND_PORT, htons(bind->port)))
		goto nla_put_failure;

	if (kznl_dump_name(skb, KZNL_ATTR_INSTANCE_NAME, instance->name) < 0)
		goto nla_put_failure;

	if (kznl_dump_inet_addr(skb, KZNL_ATTR_BIND_ADDR, bind->family, &bind->addr) < 0)
		goto nla_put_failure;

	genlmsg_end(skb, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -1;
}


static int
kznl_build_instance_bind(struct sk_buff *skb, u_int32_t pid, u_int32_t seq, int flags,
			 const struct kz_instance **instance, const struct kz_bind **bind)
{
	const struct kz_instance *last_instance;
	const struct kz_bind *last_bind;

	last_instance = *instance;
	if (last_instance) {
		list_for_each_entry((*instance), &kz_instances, list) {
			if (*instance == last_instance)
				break;
		}
	}
	if (!*instance)
		*instance = list_first_entry(&kz_instances, struct kz_instance, list);

	last_bind = *bind;
	if (last_bind) {
		list_for_each_entry((*bind), &(*instance)->bind_lookup->list_bind, list) {
			if (*bind == last_bind)
				break;
		}
	}
	if (!*bind)
		*bind = list_first_entry(&(*instance)->bind_lookup->list_bind, struct kz_bind, list);

	last_instance = *instance;
	list_for_each_entry_from((*instance), &kz_instances, list) {
		if (*instance != last_instance)
			*bind = list_first_entry(&(*instance)->bind_lookup->list_bind, struct kz_bind, list);

		list_for_each_entry_from((*bind), &(*instance)->bind_lookup->list_bind, list) {
			if (kznl_dump_bind(skb, pid, seq, false,
					   KZNL_MSG_ADD_BIND, *instance, *bind) < 0) {
				goto error;
			}

		}
	}

	return 0;

error:
	return -1;
}

enum kz_bind_dump_arg {
	BIND_DUMP_ARG_INSTANCE,
	BIND_DUMP_ARG_BIND,
	BIND_DUMP_ARG_STATE,
	BIND_DUMP_ARG_CONFIG_GENERATION
};

enum kz_dump_state {
	BIND_DUMP_STATE_FIRST_CALL,
        BIND_DUMP_STATE_HAVE_CONFIG_GEN,
	BIND_DUMP_STATE_LAST_CALL
};

static int
kznl_dump_binds(struct sk_buff *skb, struct netlink_callback *cb)
{
	const struct kz_config *config;
	const struct kz_instance **instance;
	const struct kz_bind **bind;

	/* check if we've finished the dump */
	if (cb->args[BIND_DUMP_ARG_STATE] == BIND_DUMP_STATE_LAST_CALL)
		return skb->len;

	rcu_read_lock();
	config = rcu_dereference(kz_config_rcu);
	if (cb->args[BIND_DUMP_ARG_STATE] == BIND_DUMP_STATE_FIRST_CALL ||
	    !kz_generation_valid(config, cb->args[BIND_DUMP_ARG_CONFIG_GENERATION])) {
		cb->args[BIND_DUMP_ARG_INSTANCE] = 0;
		cb->args[BIND_DUMP_ARG_BIND] = 0;
		cb->args[BIND_DUMP_ARG_STATE] = BIND_DUMP_STATE_HAVE_CONFIG_GEN;
		cb->args[BIND_DUMP_ARG_CONFIG_GENERATION] = kz_generation_get(config);
	}

	instance = (const struct kz_instance **) &cb->args[BIND_DUMP_ARG_INSTANCE];
	bind = (const struct kz_bind **) &cb->args[BIND_DUMP_ARG_BIND];
	if (kznl_build_instance_bind(skb, NETLINK_CB(cb->skb).portid,
				     cb->nlh->nlmsg_seq, NLM_F_MULTI,
				     instance, bind) >= 0)
		cb->args[BIND_DUMP_ARG_STATE] = BIND_DUMP_STATE_LAST_CALL;

	rcu_read_unlock();
	return skb->len;
}

#define kznl_build_dispatcher_rule_entry_value(dim_name, attr_name)	\
	if (rule->num_##dim_name > entry_num) {				\
		if (sizeof(rule->dim_name[entry_num]) == 1) {		\
			if (nla_put_u8(skb, KZNL_ATTR_N_DIMENSION_##attr_name, \
				       rule->dim_name[entry_num]))		\
				goto nla_put_failure;			   \
		}							\
		else if (sizeof(rule->dim_name[entry_num]) == 2) {	\
			if (nla_put_be16(skb, KZNL_ATTR_N_DIMENSION_##attr_name, \
				     htons(rule->dim_name[entry_num])))	 \
				goto nla_put_failure;			   \
		}							\
		else if (sizeof(rule->dim_name[entry_num]) == 4) {	\
			if (nla_put_be32(skb, KZNL_ATTR_N_DIMENSION_##attr_name, \
				     htonl(rule->dim_name[entry_num])))	 \
				goto nla_put_failure;			   \
		}							\
		else {							\
			BUG();						\
		}							\
	}

#define kznl_build_dispatcher_rule_entry_string(dim_name, attr_name)	\
	if (rule->num_##dim_name > entry_num)				\
		if (kznl_dump_name(skb, KZNL_ATTR_N_DIMENSION_##attr_name, \
				   rule->dim_name[entry_num]->name) < 0) \
			goto nla_put_failure;

#define kznl_build_dispatcher_rule_entry_portrange(dim_name, attr_name) \
	if (rule->num_##dim_name > entry_num)				\
		if (kznl_dump_port_range(skb, KZNL_ATTR_N_DIMENSION_##attr_name, \
					 &rule->dim_name[entry_num]) < 0) \
			goto nla_put_failure;

#define kznl_build_dispatcher_rule_entry_in_subnet(dim_name, attr_name)	\
	if (rule->num_##dim_name > entry_num)				\
		if (kznl_dump_in_subnet(skb, KZNL_ATTR_N_DIMENSION_##attr_name, \
				     &rule->dim_name[entry_num].addr, &rule->dim_name[entry_num].mask) < 0)	\
			goto nla_put_failure;

#define kznl_build_dispatcher_rule_entry_in6_subnet(dim_name, attr_name)	\
	if (rule->num_##dim_name > entry_num)				\
		if (kznl_dump_in6_subnet(skb, KZNL_ATTR_N_DIMENSION_##attr_name, \
				     &rule->dim_name[entry_num].addr, &rule->dim_name[entry_num].mask) < 0)	\
			goto nla_put_failure;

#define kznl_build_dispatcher_rule_entry_ifname(dim_name, attr_name) \
	if (rule->num_##dim_name > entry_num)				\
		if (kznl_dump_name(skb, KZNL_ATTR_N_DIMENSION_##attr_name, \
				   rule->dim_name[entry_num]) < 0)	\
			goto nla_put_failure;

static int
kznl_build_dispatcher_add_rule_entry(struct sk_buff *skb, u_int32_t pid, u_int32_t seq,
				     int flags, enum kznl_msg_types msg,
				     const struct kz_dispatcher * const dpt,
				     const struct kz_rule *rule,
				     u_int32_t entry_num)
{
	void *hdr;

	hdr = genlmsg_put(skb, pid, seq, &kznl_family, flags, msg);
	if (!hdr)
		goto nla_put_failure;

	if (kznl_dump_name(skb, KZNL_ATTR_DISPATCHER_NAME, dpt->name) < 0)
		goto nla_put_failure;

	if (nla_put_be32(skb, KZNL_ATTR_N_DIMENSION_RULE_ID, htonl(rule->id)))
		goto nla_put_failure;

#define CALL_kznl_build_dispatcher_rule_entry(DIM_NAME, NL_ATTR_NAME, _, NL_TYPE, ...) \
	kznl_build_dispatcher_rule_entry_##NL_TYPE(DIM_NAME, NL_ATTR_NAME)

	KZORP_DIM_LIST(CALL_kznl_build_dispatcher_rule_entry, ;);

#undef CALL_kznl_build_dispatcher_rule_entry

	genlmsg_end(skb, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -1;
}

static int
kznl_build_dispatcher_add_rule(struct sk_buff *skb, u_int32_t pid, u_int32_t seq,
			       int flags, enum kznl_msg_types msg,
			       const struct kz_dispatcher *dpt,
			       const struct kz_rule *rule)
{
	void *hdr;

	hdr = genlmsg_put(skb, pid, seq, &kznl_family, flags, msg);
	if (!hdr)
		goto nla_put_failure;

	if (kznl_dump_name(skb, KZNL_ATTR_DISPATCHER_NAME, dpt->name) < 0)
		goto nla_put_failure;

	if (nla_put_be32(skb, KZNL_ATTR_N_DIMENSION_RULE_ID, htonl(rule->id)))
		goto nla_put_failure;

	if (kznl_dump_name(skb, KZNL_ATTR_N_DIMENSION_RULE_SERVICE, rule->service->name) < 0)
		goto nla_put_failure;

	if (kznl_dump_count(skb, KZNL_ATTR_ACCOUNTING_COUNTER_NUM, atomic64_read(&rule->count)))
		goto nla_put_failure;

#define KZNL_BUILD_DISPATCHER_RULE_DIMENSION(DIM_NAME, NL_ATTR_NAME, ...)	\
	if (rule->num_##DIM_NAME > 0)	\
		if (nla_put_be32(skb, KZNL_ATTR_N_DIMENSION_##NL_ATTR_NAME, htonl(rule->num_##DIM_NAME))) \
			goto nla_put_failure;

	KZORP_DIM_LIST(KZNL_BUILD_DISPATCHER_RULE_DIMENSION, ;);

#undef KZNL_BUILD_DISPATCHER_RULE_DIMENSION

	genlmsg_end(skb, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -1;
}

static int
kznl_build_dispatcher_add(struct sk_buff *skb, u_int32_t pid, u_int32_t seq, int flags,
			  enum kznl_msg_types msg, const struct kz_dispatcher *dpt)
{
	void *hdr;
	struct kza_dispatcher_n_dimension_params n_dimension;

	hdr = genlmsg_put(skb, pid, seq, &kznl_family, flags, msg);

	if (kznl_dump_name(skb, KZNL_ATTR_DISPATCHER_NAME, dpt->name) < 0)
		goto nla_put_failure;

	n_dimension.num_rules = htonl(dpt->num_rule);
	if (nla_put(skb, KZNL_ATTR_DISPATCHER_N_DIMENSION_PARAMS, sizeof(n_dimension), &n_dimension))
		goto nla_put_failure;

	genlmsg_end(skb, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -1;
}

static int
kznl_build_dispatcher(struct sk_buff *skb, u_int32_t pid, u_int32_t seq, int flags,
		      const struct kz_dispatcher *dpt, long *part_idx, long *rule_entry_idx)
{
	unsigned char *msg_start, *msg_rollback;

	/*
		part_idx: inout param; must be set to item to resume on next call or 0 for completion
		  if dispatcher is N_DIMENSION
			0: means the dispatcher head
			1..: means the rule index
		  else
			0: means the dispatcher head
			1..: means the CSS index
		rule_entry_idx: inout param; must be set to item to resume on next call or 0 for completion
			0: means n_dimension rule
			1..: means the rule entry index

	*/

	msg_start = skb_tail_pointer(skb);
	msg_rollback = msg_start;

	if(*part_idx == 0) {
		msg_rollback = skb_tail_pointer(skb);
		if (kznl_build_dispatcher_add(skb, pid, seq, flags, KZNL_MSG_ADD_DISPATCHER, dpt) < 0)
			goto nlmsg_failure;
		*part_idx = 1;
	}

	/* dump rule structures */
	for (; (*part_idx) <= (long) dpt->num_rule; ++(*part_idx)) {
		u_int32_t max_entry_num = 0;
		const struct kz_rule *rule = &dpt->rule[(*part_idx) - 1];
		pr_debug("part_idx=%ld, rule_entry_idx=%ld", *part_idx, *rule_entry_idx);

		if (*rule_entry_idx == 0) {
			msg_rollback = skb_tail_pointer(skb);
			if (kznl_build_dispatcher_add_rule(skb, pid, seq, flags,
							   KZNL_MSG_ADD_RULE,
							   dpt, rule) < 0)
				goto nlmsg_failure;
			*rule_entry_idx = 1;
		}

#define UPDATE_MAX_ENTRY_NUM(DIM_NAME, ...) \
	max_entry_num = max(max_entry_num, rule->num_##DIM_NAME)

	KZORP_DIM_LIST(UPDATE_MAX_ENTRY_NUM, ;);

#undef UPDATE_MAX_ENTRY_NUM

		for (; (*rule_entry_idx) <= max_entry_num; ++(*rule_entry_idx)) {
			pr_debug("rule_entry_idx=%ld", *rule_entry_idx);
			msg_rollback = skb_tail_pointer(skb);
			if (kznl_build_dispatcher_add_rule_entry(skb, pid, seq, flags,
								 KZNL_MSG_ADD_RULE_ENTRY,
								 dpt, rule, (*rule_entry_idx) - 1) < 0)
				goto nlmsg_failure;
		}

		*rule_entry_idx = 0;

	}

	*part_idx = 0;
	*rule_entry_idx = 0;
	return skb_tail_pointer(skb) - msg_start;

nlmsg_failure:
	/* *part_idx is left pointing the failed item */
	skb_trim(skb, msg_rollback - skb->data);
	return -1;
}

enum {
	DISPATCHER_DUMP_ARG_CURRENT_DISPATCHER,
	DISPATCHER_DUMP_ARG_SUBPART,
	DISPATCHER_DUMP_ARG_RULE_ENTRY_SUBPART,
	DISPATCHER_DUMP_ARG_STATE,
	DISPATCHER_DUMP_ARG_CONFIG_GENERATION,
};

enum {
	DISPATCHER_DUMP_STATE_FIRST_CALL,
	DISPATCHER_DUMP_STATE_HAVE_CONFIG,
	DISPATCHER_DUMP_STATE_NO_MORE_WORK,
};

static int
kznl_dump_dispatchers(struct sk_buff *skb, struct netlink_callback *cb)
{
	const struct kz_dispatcher *i, *last;
	const struct kz_config * cfg;

/*
cb->args allocation:
  [0]: pointer to dispatcher item to be sent; stability from config
  [1]:  index of dispatcher subpart to send:
	if dispatcher is N_DIMENSION (0: head, 1..n: rules 0..n-1)
	else (0: head, 1..n: CSS entries 0..n-1)
  [2]: if [1] is N_DIMENSION dispatcher, index of rule entry subpart to send (0: rule, 1..n: rule entries)
  [3]: 0: first call, 1: have config generation, 2: no more work
  [4]: config generation

race condition recovery: restart dump
  (if this turns to be a problem, cfg shall be refcounted!)

on first entry cb->args is all-0
*/

	/* check if we've finished the dump */
	if (cb->args[DISPATCHER_DUMP_ARG_STATE] == DISPATCHER_DUMP_STATE_NO_MORE_WORK)
		return skb->len;

	rcu_read_lock();

	/* check config generation and re-get config if necessary */
	cfg = rcu_dereference(kz_config_rcu);
	if (cb->args[DISPATCHER_DUMP_ARG_STATE] == DISPATCHER_DUMP_STATE_FIRST_CALL ||
	    !kz_generation_valid(cfg, cb->args[DISPATCHER_DUMP_ARG_CONFIG_GENERATION])) {
		cb->args[DISPATCHER_DUMP_ARG_CONFIG_GENERATION] = kz_generation_get(cfg);
		cb->args[DISPATCHER_DUMP_ARG_STATE] = DISPATCHER_DUMP_STATE_HAVE_CONFIG;
		cb->args[DISPATCHER_DUMP_ARG_CURRENT_DISPATCHER] = 0;
		cb->args[DISPATCHER_DUMP_ARG_SUBPART] = 0;
		cb->args[DISPATCHER_DUMP_ARG_RULE_ENTRY_SUBPART] = 0;
	}

restart:
	last = (const struct kz_dispatcher *) cb->args[DISPATCHER_DUMP_ARG_CURRENT_DISPATCHER];
	list_for_each_entry(i, &cfg->dispatchers.head, list) {
		/* check if we're continuing the dump from a given entry */
		if (last != NULL) {
			if (i == last) {
				/* ok, this was the last entry we've tried to dump */
				cb->args[DISPATCHER_DUMP_ARG_CURRENT_DISPATCHER] = 0;
				/* cb->args[1] is left as found to resume! */
				last = NULL;
			} else /* seek over start */
				continue;
		}

		if (kznl_build_dispatcher(skb, NETLINK_CB(cb->skb).portid,
					  cb->nlh->nlmsg_seq, NLM_F_MULTI, i,
					  &cb->args[DISPATCHER_DUMP_ARG_SUBPART],
					  &cb->args[DISPATCHER_DUMP_ARG_RULE_ENTRY_SUBPART]) < 0) {
			/* dispatcher dump failed, try to continue from here next time */
			cb->args[DISPATCHER_DUMP_ARG_CURRENT_DISPATCHER] = (long) i;
			/* cb->args[DISPATCHER_DUMP_ARG_SUBPART] was set by the call! */
			goto out;
		}
	}

	if (last != NULL) {
		/* we've tried to continue an interrupted dump but did not found the
		 * restart point. cannot do any better but start again. */
		cb->args[DISPATCHER_DUMP_ARG_CURRENT_DISPATCHER] =
			cb->args[DISPATCHER_DUMP_ARG_SUBPART] =
			cb->args[DISPATCHER_DUMP_ARG_RULE_ENTRY_SUBPART] = 0;
		goto restart;
	}

	/* done */
	cb->args[DISPATCHER_DUMP_ARG_STATE] = DISPATCHER_DUMP_STATE_NO_MORE_WORK;

out:
	rcu_read_unlock();
	return skb->len;
}

static int
kznl_recv_get_dispatcher(struct sk_buff *skb, struct genl_info *info)
{
	int res = 0;
	int ret = 0;
	char *dpt_name = NULL;
	struct kz_dispatcher *dpt;
	struct sk_buff *nskb = NULL;
	long dpt_item_idx = 0;
	long rule_entry_idx = 0;

	/* parse attributes */
	if (!info->attrs[KZNL_ATTR_DISPATCHER_NAME]) {
		pr_err_ratelimited("required name attribute missing\n");
		res = -EINVAL;
		goto error;
	}

	res = kznl_parse_name_alloc(info->attrs[KZNL_ATTR_DISPATCHER_NAME], &dpt_name);
	if (res < 0) {
		pr_err_ratelimited("failed to parse dispatcher name\n");
		goto error;
	}

	rcu_read_lock();

	dpt = kz_dispatcher_lookup_name(rcu_dereference(kz_config_rcu), dpt_name);
	if (dpt == NULL) {
		pr_debug("no such dispatcher found; name='%s'\n", dpt_name);
		res = -ENOENT;
		goto error_unlock_dpt;
	}

	/* NOTE: this loops always terminates because one single
	 * message is guaranteed to fit an NLMSG_GOODSIZE-sized
	 * buffer. This means that kznl_build_dispatcher() will always
	 * output at least one netlink message and thus we must
	 * always call netlink_unicast() on nskb.
	 */
	do {
		pr_debug("dpt_item_idx=%ld, rule_entry_idx=%ld", dpt_item_idx, rule_entry_idx);
		/* create skb and dump */
		nskb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
		if (!nskb) {
			pr_err_ratelimited("failed to allocate reply message\n");
			res = -ENOMEM;
			goto error_unlock_dpt;
		}

		ret = kznl_build_dispatcher(nskb, info->snd_portid,
					    info->snd_seq, 0,
					    dpt, &dpt_item_idx, &rule_entry_idx);
		res = genlmsg_reply(nskb, info);

	} while ((ret < 0) && (ret >= 0));

error_unlock_dpt:
	rcu_read_unlock();

	if (dpt_name != NULL)
		kfree(dpt_name);

error:
	return res;
}

static int
kznl_build_query_resp(struct sk_buff *skb, u_int32_t pid, u_int32_t seq, int flags,
		      enum kznl_msg_types msg,
		      const struct kz_zone *client_zone, const struct kz_zone *server_zone,
		      const struct kz_service *service, const struct kz_dispatcher *dispatcher)
{
	void *hdr;

	hdr = genlmsg_put(skb, pid, seq, &kznl_family, flags, msg);

	if (dispatcher && kznl_dump_name(skb, KZNL_ATTR_DISPATCHER_NAME, dispatcher->name) < 0)
		goto nfattr_failure;
	if (client_zone && kznl_dump_name(skb, KZNL_ATTR_QUERY_REPLY_CLIENT_ZONE, client_zone->name) < 0)
		goto nfattr_failure;
	if (server_zone && kznl_dump_name(skb, KZNL_ATTR_QUERY_REPLY_SERVER_ZONE, server_zone->name) < 0)
		goto nfattr_failure;
	if (service && kznl_dump_name(skb, KZNL_ATTR_SERVICE_NAME, service->name) < 0)
		goto nfattr_failure;

	genlmsg_end(skb, hdr);
	return 0;

nfattr_failure:
	genlmsg_cancel(skb, hdr);
	return -1;
}

#define kznl_query_check_param_existence(PARAM_TYPE, PARAM_NAME) \
if (!info->attrs[PARAM_TYPE]) { \
	pr_err_ratelimited("required attribute missing: attr='%s'\n", #PARAM_NAME); \
	res = -EINVAL; \
	goto error; \
}

static int
kznl_recv_query(struct sk_buff *skb, struct genl_info *info)
{
	int res = 0;
	struct kz_traffic_props traffic_props;
	union nf_inet_addr src_addr;
	union nf_inet_addr dst_addr;
	char ifname[IFNAMSIZ];
	struct kz_reqids reqids;
	struct net_device *dev;
	struct sk_buff *nskb = NULL;
	struct kz_dispatcher *dispatcher;
	struct kz_zone *client_zone;
	struct kz_zone *server_zone;
	struct kz_service *service;

	kznl_query_check_param_existence(KZNL_ATTR_QUERY_PARAMS, params);
	kznl_query_check_param_existence(KZNL_ATTR_QUERY_PARAMS_SRC_IP, src_ip);
	kznl_query_check_param_existence(KZNL_ATTR_QUERY_PARAMS_DST_IP, dst_ip);

	kz_traffic_props_init(&traffic_props);
	traffic_props.src_addr = &src_addr;
	traffic_props.dst_addr = &dst_addr;

	/* fill fields */
	res = kznl_parse_inet_addr(info->attrs[KZNL_ATTR_QUERY_PARAMS_SRC_IP], &src_addr, &traffic_props.l3proto);
	if (res < 0) {
		pr_err_ratelimited("failed to parse src ip nested attribute\n");
		goto error;
	}

	res = kznl_parse_inet_addr(info->attrs[KZNL_ATTR_QUERY_PARAMS_DST_IP], &dst_addr, &traffic_props.l3proto);
	if (res < 0) {
		pr_err_ratelimited("failed to parse src ip nested attribute\n");
		goto error;
	}

	res = kznl_parse_query_params(info->attrs[KZNL_ATTR_QUERY_PARAMS], &traffic_props.proto, ifname);
	if (res < 0) {
		pr_err_ratelimited("failed to parse query parameters\n");
		goto error;
	}

	if (traffic_props.proto == IPPROTO_TCP || traffic_props.proto == IPPROTO_UDP) {
		kznl_query_check_param_existence(KZNL_ATTR_QUERY_PARAMS_SRC_PORT, src_port);
		res = kznl_parse_port(info->attrs[KZNL_ATTR_QUERY_PARAMS_SRC_PORT], &traffic_props.src_port);
		if (res < 0) {
			pr_err_ratelimited("failed to parse query attribute; attr='src_port'\n");
			goto error;
		}

		kznl_query_check_param_existence(KZNL_ATTR_QUERY_PARAMS_DST_PORT, dst_port);
		res = kznl_parse_port(info->attrs[KZNL_ATTR_QUERY_PARAMS_DST_PORT], &traffic_props.dst_port);
		if (res < 0) {
			pr_err_ratelimited("failed to parse query attribute; attr='dst_port'\n");
			goto error;
		}
	}

	if (traffic_props.proto == IPPROTO_ICMP || traffic_props.proto == IPPROTO_ICMPV6) {
		kznl_query_check_param_existence(KZNL_ATTR_QUERY_PARAMS_PROTO_TYPE, proto_type);
		res = kznl_parse_proto_type(info->attrs[KZNL_ATTR_QUERY_PARAMS_PROTO_TYPE], traffic_props.proto, &traffic_props.proto_type);
		if (res < 0) {
			pr_err_ratelimited("failed to parse query attribute; attr='proto_type'\n");
			goto error;
		}

		kznl_query_check_param_existence(KZNL_ATTR_QUERY_PARAMS_PROTO_SUBTYPE, proto_subtype);
		res = kznl_parse_proto_subtype(info->attrs[KZNL_ATTR_QUERY_PARAMS_PROTO_SUBTYPE], traffic_props.proto, &traffic_props.proto_subtype);
		if (res < 0) {
			pr_err_ratelimited("failed to parse query attribute; attr='proto_subtype'\n");
			goto error;
		}
	}

	/* look up interface */
	dev = dev_get_by_name(&init_net, ifname);
	if (dev == NULL) {
		pr_err_ratelimited("failed to look up network device; ifname='%s'\n", ifname);
		res = -ENOENT;
		goto error;
	}
	traffic_props.iface = dev;

	if (info->attrs[KZNL_ATTR_QUERY_PARAMS_REQID]) {
		traffic_props.reqids = &reqids;
		reqids.len = 1;
		res = kznl_parse_reqid(info->attrs[KZNL_ATTR_QUERY_PARAMS_REQID], &reqids.vec[0]);
		if (res < 0) {
			pr_err_ratelimited("failed to parse query attribute\n");
			goto error;
		}
	}

	/* create reply skb */
	nskb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!nskb) {
		pr_err_ratelimited("failed to allocate reply message\n");
		res = -ENOMEM;
		goto error_put_dev;
	}

	/* lookup uses per-cpu data mutating it, we must make sure no interruptions on a CPU */
	rcu_read_lock_bh();
	kz_lookup_session(rcu_dereference(kz_config_rcu),
			  &traffic_props,
			  &client_zone, &server_zone,
			  &service, &dispatcher,
			  0);
	rcu_read_unlock_bh();

	if (kznl_build_query_resp(nskb, info->snd_portid,
				  info->snd_seq, 0,
				  KZNL_MSG_QUERY_REPLY,
				  client_zone, server_zone,
				  service, dispatcher) < 0) {
		res = -ENOMEM;
		goto error_put_dev;
	}

	dev_put(dev);
	return genlmsg_reply(nskb, info);

error_put_dev:
	dev_put(dev);

error:
	nlmsg_free(nskb);

	return res;
}

static int
kznl_build_get_version_resp(struct sk_buff *skb, u_int32_t pid, u_int32_t seq, int flags,
			    enum kznl_msg_types msg)
{
	void *hdr;

	hdr = genlmsg_put(skb, pid, seq, &kznl_family, flags, msg);
	if (!hdr)
		goto nla_put_failure;

	pr_debug("dump version; major='%d', compat='%d'\n", KZ_MAJOR_VERSION, KZ_COMPAT_VERSION);

	if (nla_put_u8(skb, KZNL_ATTR_MAJOR_VERSION, KZ_MAJOR_VERSION))
		goto nla_put_failure;
	if (nla_put_u8(skb, KZNL_ATTR_COMPAT_VERSION, KZ_COMPAT_VERSION))
		goto nla_put_failure;

	genlmsg_end(skb, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -1;
}

static int
kznl_recv_get_version(struct sk_buff *skb, struct genl_info *info)
{
	int res = 0;
	struct sk_buff *nskb = NULL;

	/* create skb and dump */
	nskb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!nskb) {
		pr_err_ratelimited("failed to allocate reply message\n");
		res = -ENOMEM;
		goto error;
	}

	if (kznl_build_get_version_resp(nskb, info->snd_portid, info->snd_seq, 0,
					KZNL_MSG_GET_VERSION_REPLY) < 0) {
		res = -ENOMEM;
		goto error;
	}

	return genlmsg_reply(nskb, info);

error:
	nlmsg_free(nskb);
	return res;
}

static int
kznl_recv_lookup_zone(struct sk_buff *skb, struct genl_info *info)
{
	int res = 0;
	struct sk_buff *nskb = NULL;
	sa_family_t l3proto;
	union nf_inet_addr addr;
	struct kz_zone *zone = NULL;
	const struct kz_head_z * zones;
	const struct kz_config * cfg;

	/* parse attributes */
	if (!info->attrs[KZNL_ATTR_ZONE_IP]) {
		pr_err_ratelimited("required IP attribute missing\n");
		res = -EINVAL;
		goto error;
	}

	/* fill fields */
	res = kznl_parse_inet_addr(info->attrs[KZNL_ATTR_ZONE_IP], &addr, &l3proto);
	if (res < 0) {
		pr_err_ratelimited("failed to parse src ip nested attribute\n");
		goto error;
	}

	rcu_read_lock();
	cfg = rcu_dereference(kz_config_rcu);

	zones = &cfg->zones;

	zone = kz_head_zone_lookup(zones, &addr, l3proto);
	if (zone == NULL) {
		pr_debug("no such zone found\n");
		res = -ENOENT;
		goto error_unlock_zone;
	}

	/* create skb and dump */
	nskb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!nskb) {
		pr_err_ratelimited("failed to allocate reply message\n");
		res = -ENOMEM;
		goto error_unlock_zone;
	}

	if (kznl_build_zone_add(nskb, info->snd_portid, info->snd_seq, 0, KZNL_MSG_ADD_ZONE, zone) < 0) {
		/* data did not fit in a single entry -- for now no support of continuation
		   we could loop and multicast; we chose not to send the partial info */
		pr_err_ratelimited("failed to create zone messages\n");
		res = -ENOMEM;
		goto error_free_skb;
	}

	rcu_read_unlock();

	return genlmsg_reply(nskb, info);

error_free_skb:
	nlmsg_free(nskb);

error_unlock_zone:
	rcu_read_unlock();;

error:
	return res;
}

/***********************************************************
 * Netlink event handler
 ***********************************************************/

static int
kznl_netlink_event(struct notifier_block *n, unsigned long event, void *v)
{
	struct netlink_notify *notify = v;
	struct kz_transaction *tr;
	struct kz_instance *instance;

	if (event == NETLINK_URELEASE &&
	    notify->protocol == NETLINK_GENERIC &&
	    notify->portid != 0) {
		pr_debug("netlink release event received, pid='%d'\n",
			 notify->portid);

		/* remove pending transaction */
		LOCK_TRANSACTIONS();

		tr = transaction_lookup(notify->portid);
		if (tr != NULL) {
			pr_debug("transaction found, removing\n");

			instance = kz_instance_lookup_id(tr->instance_id);
			if (instance != NULL)
				instance->flags &= ~KZF_INSTANCE_TRANS;

			transaction_destroy(tr);
		}

		/* NOTE: removal of any instance-specific data should be here,
		 *       as it is the place where the release of netlink event
		 *       is handled.
		 *
		 * It must also be noted that instances are never freed.
		 */
		list_for_each_entry(instance, &kz_instances, list) {
			if (instance->id == 0) {
				pr_debug("no cleanup for global instance\n");
			} else {
				pr_debug("cleaning up instance; id='%d'\n", instance->id);
			}
			kz_instance_remove_bind(instance, notify->portid, NULL);
		}

		UNLOCK_TRANSACTIONS();
	}

	return NOTIFY_DONE;
}

/***********************************************************
 * Initialization
 ***********************************************************/

#define kznl_recv_NO_RECV_FUNC NULL
#define kznl_dump_NO_DUMP_FUNC NULL

#define KZNL_OP(NL_MSG_NAME, RECV_FUNC, DUMP_FUNC) \
	{ \
		.cmd = KZNL_MSG_##NL_MSG_NAME, \
		.doit = kznl_recv_##RECV_FUNC, \
		.dumpit = kznl_dump_##DUMP_FUNC, \
		.flags = GENL_ADMIN_PERM, \
	},
#define KZNL_NOOP(NL_MSG_NAME, RECV_FUNC, DUMP_FUNC)

static struct genl_ops kznl_ops[] = {
#define SETUP_kznl_ops(NL_MSG_NAME, RECV_FUNC, DUMP_FUNC, KZNL_OP_GEN, ...) \
		KZNL_OP_GEN(NL_MSG_NAME, RECV_FUNC, DUMP_FUNC)

	KZORP_MSG_LIST(SETUP_kznl_ops, )

#undef SETUP_kznl_ops
};

static struct notifier_block kz_rtnl_notifier = {
	.notifier_call	= kznl_netlink_event,
};

int __init kz_netlink_init(void)
{
	int res = -ENOMEM;

	/* initialize data structures */
	transaction_init();

	/* register netlink notifier and genetlink family */
	netlink_register_notifier(&kz_rtnl_notifier);
	res = genl_register_family_with_ops(&kznl_family, kznl_ops);
	if (res < 0) {
		pr_err_ratelimited("failed to register generic netlink family; err='%d'\n", res);
		goto cleanup_notifier;
	}

	return res;

cleanup_notifier:
	netlink_unregister_notifier(&kz_rtnl_notifier);

	return res;
}

void kz_netlink_cleanup(void)
{
	genl_unregister_family(&kznl_family);
	netlink_unregister_notifier(&kz_rtnl_notifier);

	/* FIXME: free all data structures */
}

MODULE_ALIAS("net-pf-" __stringify(PF_NETLINK) "-proto-"
	     __stringify(NETLINK_GENERIC) "-family-kzorp");
