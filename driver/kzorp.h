/*
 * KZorp data structures
 *
 * Copyright (C) 2006-2015 BalaBit IT Security, 2015-2017 BalaSys IT Security.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#ifndef _KZORP_H
#define _KZORP_H

#include <asm/atomic.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/netfilter_ipv4.h>
#include <linux/in.h>
#include <linux/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include "kzorp_netlink.h"
#include <net/xfrm.h>
#include <linux/if.h>
#include <linux/netdevice.h>

#include "kzorp_compat.h"
#include "kzorp_ext.h"
#include "kzorp_internal.h"

#define KZ_MAJOR_VERSION  4
#define KZ_COMPAT_VERSION 6

enum KZ_ALLOC_TYPE
{
	KZALLOC,
	VMALLOC
};

void *kz_big_alloc(size_t size, enum KZ_ALLOC_TYPE *alloc_type);
void kz_big_free(void *ptr, enum KZ_ALLOC_TYPE alloc_type);

/***********************************************************
 * Core data structures
 ***********************************************************/

typedef unsigned int kz_generation_t; /* integral with suitable size */
typedef __be32 netlink_port_t;

enum kzf_instance_flags {
	KZF_INSTANCE_DELETED = 1 << 0,
	KZF_INSTANCE_TRANS   = 1 << 1,
};

struct kz_bind {
	struct list_head list;
	union nf_inet_addr addr;
	netlink_port_t peer_pid;
	sa_family_t family;
	__u16 port;
	__u8 proto;
};

enum kz_bind_l3proto {
	KZ_BIND_L3PROTO_IPV4,
	KZ_BIND_L3PROTO_IPV6,
	KZ_BIND_L3PROTO_COUNT
};

enum kz_bind_l4proto {
	KZ_BIND_L4PROTO_TCP,
	KZ_BIND_L4PROTO_UDP,
	KZ_BIND_L4PROTO_COUNT
};

struct kz_bind_lookup {
	struct rcu_head rcu;
	struct list_head list_bind;

	/* cache of binds by l3 and l4 proto */

	/*
	 * The binds and binds_by_type look something like this:
	 *
	 *	 +-------------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+
	 *	 |  Bind 1     |  Bind 2     |	...	   |  Bind X	 |  Bind X + 1 | ...	     |	Bind Y	   | ...	 |
	 *	 |  (IPv4/TCP) |  (IPv4/TCP) |		   |  (IPv4/UDP) |  (IPv6/TCP) |	     |	(IPv6/UDP) |		 |
	 *	 +-------------+-------------+-------------+------/------+-----/-------+-------------+------/------+-------------+
	 *	       |                                  /-------     /-------		        /-----------
	 *	       |                          /-------      /------		    /-----------
	 *	       |                  /-------	/-------        /-----------
	 *       +-----+-------+-------------+-------------+-------------+
	 *       | IPv4/TCP    | IPv4/UDP    | IPv6/TCP    | IPv6/UDP    |
	 *       +-------------+-------------+-------------+-------------+
	 */

	/* array of pointers to all bind structures, ordered by l3proto and l4proto */
	const struct kz_bind **binds;
	/* array of pointers to the appropriate element of the binds array */
	const struct kz_bind **binds_by_type[KZ_BIND_L3PROTO_COUNT][KZ_BIND_L4PROTO_COUNT];
	unsigned int bind_nums[KZ_BIND_L3PROTO_COUNT][KZ_BIND_L4PROTO_COUNT];
};

struct kz_instance {
	struct list_head list;
	struct kz_bind_lookup __rcu *bind_lookup;
	unsigned int id;
	unsigned int flags;
	netlink_port_t peer_pid;
	char name[0];
};

enum kzf_transaction_flags {
	KZF_TRANSACTION_FLUSH_ZONES		= 1 << 0,
	KZF_TRANSACTION_FLUSH_SERVICES		= 1 << 1,
	KZF_TRANSACTION_FLUSH_DISPATCHERS	= 1 << 2,
	KZF_TRANSACTION_FLUSH_BIND		= 1 << 3,
};

struct kz_transaction {
	unsigned int instance_id;
	netlink_port_t peer_pid;
	unsigned int flags;
	u_int64_t cookie;
	const struct kz_config * cfg;
	struct list_head op;
};

enum kznl_op_data_type {
	KZNL_OP_ADD_ZONE,
	KZNL_OP_ADD_SERVICE,
	KZNL_OP_ADD_DISPATCHER,
	KZNL_OP_ADD_BIND,
	KZNL_OP_DELETE_ZONE,
};

struct kz_operation {
	struct list_head list;
	enum kznl_op_data_type type;
	void *data;
	void (*data_destroy)(void *);
};

struct kz_port_range {
	u_int16_t from;
	u_int16_t to;
};

struct kz_in_subnet {
	struct in_addr addr;
	struct in_addr mask;
};

struct kz_in6_subnet {
	struct in6_addr addr;
	struct in6_addr mask;
};

struct kz_rule_entry_params {
	u_int32_t rule_id;

#define DECLARE_RULE_ENTRY_PARAM(DIM_NAME, _, TYPE, ...) \
	bool has_##DIM_NAME; \
	TYPE DIM_NAME

	KZORP_DIM_LIST(DECLARE_RULE_ENTRY_PARAM, ;);

#undef DECLARE_RULE_ENTRY_PARAM
};

#define DECLARE_PARAM_ENTRY(DIM_NAME, DIM_TYPE) \
	u_int32_t alloc_##DIM_NAME; \
	u_int32_t num_##DIM_NAME; \
	DIM_TYPE *DIM_NAME;

struct kz_rule {
	u_int32_t id;
	atomic64_t count;

	struct kz_service *service;
	struct kz_dispatcher *dispatcher;

#define DECLARE_RULE_ENTRY(DIM_NAME, _, DIM_TYPE, ...) \
	DECLARE_PARAM_ENTRY(DIM_NAME, DIM_TYPE)

	KZORP_DIM_LIST(DECLARE_RULE_ENTRY, ;)

#undef DECLARE_RULE_ENTRY
};

struct kz_reqids {
  u32 vec[XFRM_MAX_DEPTH];
  int len;
};

typedef struct {
	struct work_struct my_work;
	void *p;
} kz_vfree_work_t;

struct kz_dispatcher {
	struct list_head list;
	atomic_t refcnt;
	struct kz_instance *instance;

	unsigned int alloc_rule;
	unsigned int num_rule;
	struct kz_rule *rule;
	enum KZ_ALLOC_TYPE rule_allocator;

	char *name;
};

struct kz_service_nat_entry {
	struct list_head list;
	struct kz_nf_nat_range src;
	struct kz_nf_nat_range dst;
	struct kz_nf_nat_range map;
	uint8_t l3proto;
};

struct kz_service_info_fwd {
	struct list_head snat;
	struct list_head dnat;

	sa_family_t router_dst_addr_family;
	union nf_inet_addr router_dst_addr;
	__be16 router_dst_port;
};

struct kz_service_info_deny {
	enum kz_service_ipv4_deny_method ipv4_reject_method;
	enum kz_service_ipv6_deny_method ipv6_reject_method;
};

#define KZ_SERVICE_CNT_LOCKED_BIT 16

enum kzf_service_internal_flags {
	KZF_SERVICE_CNT_LOCKED = 1 << KZ_SERVICE_CNT_LOCKED_BIT,
};

struct kz_service {
	struct list_head list;
	atomic_t refcnt;
	unsigned int id;
	unsigned int instance_id;
	unsigned int flags;
	atomic64_t count;
	enum kz_service_type type;
	union {
		struct kz_service_info_fwd fwd;
		struct kz_service_info_deny deny;
	} a;
	char *name;
};

enum kzf_zone_internal_flags {
	KZF_ZONE_HAS_RANGE = 1 << 16,
};

struct kz_subnet {
	sa_family_t family;
	union nf_inet_addr addr;
	union nf_inet_addr mask;
};

struct kz_zone {
	struct list_head list;
	struct hlist_node hlist;
	atomic_t refcnt;
	atomic64_t count;
	/* static lookup helper data */
	int depth;
	unsigned int index;

        DECLARE_PARAM_ENTRY(subnet, struct kz_subnet);

	char *name;

	struct kz_zone *admin_parent;
};

/***********************************************************
 * Lookup data structures
 ***********************************************************/

#define DISPATCHER_INET_HASH_SIZE 256

#define KZ_ZONE_HASH_SIZE 32
#define KZ_ZONE_MAX 16384
#define KZ_ZONE_BF_SIZE (KZ_ZONE_MAX / 8)

struct kz_zone_lookup_node;

struct kz_zone_lookup {
	struct kz_zone *ipv4_internet_zone;
	struct kz_zone *ipv6_internet_zone;
	struct kz_zone_lookup_node *ipv4_root_node;
	struct kz_zone_lookup_node *ipv6_root_node;
};

/* config holder for zones */
struct kz_head_z {
	struct list_head head;
	/* lookup data structures */
	struct kz_zone_lookup zone_lookup;
};

/* config holder for dispatchers */
struct kz_head_d {
	struct list_head head;
	/* lookup data structures */
	struct kz_rule_lookup_data *lookup_data;
	enum KZ_ALLOC_TYPE lookup_data_allocator;
};

/* config holder for services */
struct kz_head_s {
	struct list_head head;
	/* no lookup data for now */
};

/* config holder for instances */
struct kz_head_i {
	struct list_head head;
	/* no lookup data for now */
};

/* full config of kzorp
   we have one global instance with rcu protection
   functions may access it vis usual cru API

   CONVENTION: if passed in as function parameter,
   the caller ensures the content is stable!
*/
struct kz_config {
	struct rcu_head rcu;
	struct kz_head_z zones;
	struct kz_head_s services;
	struct kz_head_d dispatchers;
	struct kz_head_i instances;
	u_int64_t cookie;
	kz_generation_t generation;
};

/***********************************************************
 * Shared data
 ***********************************************************/

#define INSTANCE_MAX_NUM 256

extern struct mutex kz_instance_mutex;
extern struct list_head kz_instances;

/* NOTE: shared for nfnetlink transactions in nfnetlink module */
#define LOCK_INSTANCES(...) do {mutex_lock(&kz_instance_mutex);} while (0)
#define UNLOCK_INSTANCES(...) do {mutex_unlock(&kz_instance_mutex);} while (0)
/* we share mutex of instances in core -- no point to use multiples */
#define LOCK_TRANSACTIONS LOCK_INSTANCES
#define UNLOCK_TRANSACTIONS UNLOCK_INSTANCES

#define KZ_KFREE(p) do {if (p) {kfree(p); p = NULL;} } while (0)

/* rcu-protected pointer; can never be NULL
   the generation in the structure is unique in module lifetime
*/
extern struct kz_config *kz_config_rcu;

/* installs the new version, schedules rcu-free on the old one 
   generation is handled internally
*/
void kz_config_swap(struct kz_config * new_cfg);

struct kz_config *kz_config_new(void);
void kz_config_destroy(struct kz_config * cfg);

static inline kz_generation_t
kz_generation_get(const struct kz_config *cfg) {
	return cfg ? cfg->generation : 0;
}

static inline int
kz_generation_valid(const struct kz_config *cfg, kz_generation_t generation) {
	return (generation == kz_generation_get(cfg));
}

/***********************************************************
 * Core functions
 ***********************************************************/

extern char *kz_name_dup(const char * const name);

extern void kz_head_destroy_zone(struct kz_head_z *h);
extern void kz_head_destroy_service(struct kz_head_s *h);
extern void kz_head_destroy_dispatcher(struct kz_head_d *h);

struct kz_bind * kz_bind_new(void);
struct kz_bind * kz_bind_clone(const struct kz_bind *_bind);
void kz_bind_destroy(struct kz_bind *bind);

const struct kz_bind * const
kz_instance_bind_lookup_v4(const struct kz_instance *instance, u8 l4proto,
			   __be32 saddr, __be16 sport,
			   __be32 daddr, __be16 dport);

const struct kz_bind * const
kz_instance_bind_lookup_v6(const struct kz_instance *instance, u8 l4proto,
			   const struct in6_addr *saddr, __be16 sport,
			   const struct in6_addr *daddr, __be16 dport);
void kz_instance_remove_bind(struct kz_instance *instance, const netlink_port_t pid_to_remove, const struct kz_transaction *tr);

extern struct kz_instance *kz_instance_lookup_nocheck(const char *name);
extern struct kz_instance *kz_instance_lookup(const char *name);
extern struct kz_instance *kz_instance_lookup_id(const unsigned int id);
extern struct kz_instance *kz_instance_create(const char *name, const unsigned int len, const netlink_port_t peer_pid);

extern struct kz_zone *kz_zone_new(void);
extern void kz_zone_destroy(struct kz_zone *zone);
extern struct kz_zone *__kz_zone_lookup_name(const struct list_head * const head, const char *name);
extern struct kz_zone *kz_zone_lookup_name(const struct kz_config *cfg, const char *name);

extern struct kz_zone *kz_zone_clone(const struct kz_zone * const zone);

extern struct kz_service *kz_service_new(void);
extern void service_destroy(struct kz_service *service);
extern void kz_service_destroy(struct kz_service *service);
extern struct kz_service *__kz_service_lookup_name(const struct list_head * const head,
						   const char *name);
extern struct kz_service *kz_service_lookup_name(const struct kz_config *cfg, const char *name);
extern int kz_service_add_nat_entry(struct list_head *head,
				    struct kz_nf_nat_range *src,
				    struct kz_nf_nat_range *dst,
				    struct kz_nf_nat_range *map, uint8_t l3proto);
extern struct kz_service *kz_service_clone(const struct kz_service * const o);
extern long kz_service_lock(struct kz_service * const service);
extern void kz_service_unlock(struct kz_service * const service);

extern int kz_rule_copy(struct kz_rule *dst,
			const struct kz_rule * const src);

extern struct kz_dispatcher *kz_dispatcher_new(void);
extern void kz_dispatcher_destroy(struct kz_dispatcher *);
extern struct kz_dispatcher *kz_dispatcher_lookup_name(const struct kz_config *cfg, const char *name);
extern int kz_dispatcher_add_css(struct kz_dispatcher *d, struct kz_zone *client,
				 struct kz_zone *server, struct kz_service *service);
extern int kz_dispatcher_add_rule(struct kz_dispatcher *d, struct kz_service *service,
				  const struct kz_rule * const rule_params);
extern int kz_dispatcher_add_rule_entry(struct kz_rule *rule,
					const struct kz_rule_entry_params * const rule_entry_params);
extern int kz_dispatcher_alloc_rule_array(struct kz_dispatcher *dispatcher, size_t alloc_rules);
extern int kz_dispatcher_copy_rules(struct kz_dispatcher *dst, const struct kz_dispatcher * const src);
extern struct kz_dispatcher *kz_dispatcher_clone(const struct kz_dispatcher * const o);
extern struct kz_dispatcher *kz_dispatcher_clone_pure(const struct kz_dispatcher * const o);
extern int kz_dispatcher_relink(struct kz_dispatcher *d, const struct list_head * zonelist, const struct list_head * servicelist);

int kz_log_ratelimit(void);
bool kz_log_session_verdict_enabled(void);

/*
 * Get/Put functions should handle null pointer as the result of
 * the rule evaluation zone/service may null pointers.
 */
#define kz_object_declare_ref_funcs(object_name) \
static inline struct kz_##object_name *kz_##object_name##_get(struct kz_##object_name *object_name) \
{ \
	if (object_name) \
		atomic_inc(&object_name->refcnt); \
	return object_name; \
} \
static inline void kz_##object_name##_put(struct kz_##object_name *object_name) \
{ \
	if (object_name && atomic_dec_and_test(&object_name->refcnt)) \
		kz_##object_name##_destroy(object_name); \
}

kz_object_declare_ref_funcs(zone)
kz_object_declare_ref_funcs(service)
kz_object_declare_ref_funcs(dispatcher)

/***********************************************************
 * Conntrack structure extension
 ***********************************************************/


/* returns consolidated kzorp lookup info; caches it in ct, and uses 
   the cache if valid;
   returns NULL only if it's not possible to add kzorp extension to ct
   rcu_dereferenced config is stored in p_cfg
  call under rcu_read_lock() even if p_cfg==NULL!

   the returned structure is placed in ct, and destroy will happen
   when ct gets destroyed
*/

extern const struct kz_extension * kz_extension_update(
	struct nf_conn *ct,
	enum ip_conntrack_info ctinfo,
	const struct sk_buff *skb,
	const struct net_device * const in,
	u8 l3proto,
	const struct kz_config **p_cfg);

/* fills kzorp structure with lookup data
   rcu_dereferenced config is stored in p_cfg
   call under rcu_read_lock() even if p_cfg==NULL!
   leaves non-lookup fields untouched!
   pointers in the passed structure must be valid/NULL,
   as they are released while the new ones addrefed

   make sure to call kz_destroy_kzorp on pkzorp eventually
*/
extern void nfct_kzorp_lookup_rcu(struct kz_extension * pkzorp,
	enum ip_conntrack_info ctinfo,
	const struct sk_buff *skb,
	const struct net_device * const in,
	const u8 l3proto,
	const struct kz_config **p_cfg);

/***********************************************************
 * Hook functions
 ***********************************************************/

extern int kz_hooks_init(void);
extern void kz_hooks_cleanup(void);

/***********************************************************
 * Lookup functions
 ***********************************************************/

extern int kz_lookup_init(void);
extern void kz_lookup_cleanup(void);

extern void kz_head_dispatcher_init(struct kz_head_d *h);
extern int kz_head_dispatcher_build(struct kz_head_d *h);
extern void kz_head_dispatcher_destroy(struct kz_head_d *h);

extern void kz_head_zone_init(struct kz_head_z *h);
extern int kz_head_zone_build(struct kz_head_z *h);
extern void kz_head_zone_destroy(struct kz_head_z *h);
extern struct kz_zone * kz_head_zone_lookup(const struct kz_head_z *h, const union nf_inet_addr * addr, u_int8_t proto);
extern bool kz_zone_lookup_from_skb(const struct sk_buff *skb, int l3proto, struct kz_zone **src_zone, struct kz_zone **dst_zone);

extern int kz_add_zone(struct kz_zone *zone);
extern int kz_add_zone_subnet(struct kz_zone *zone, const struct kz_subnet * const zone_subnet);

extern const struct kz_nf_nat_range *kz_service_nat_lookup(const struct list_head
							 *const head,
							 const union nf_inet_addr
							 *saddr,
							 const union nf_inet_addr
							 *daddr,
							 const u_int8_t l3proto);

struct kz_traffic_props {
	sa_family_t l3proto;

	const struct kz_reqids *reqids;

	const struct net_device *iface;

	const union nf_inet_addr * src_addr;
	const union nf_inet_addr * dst_addr;

	struct kz_zone * src_zone;
	struct kz_zone * dst_zone;

	u_int16_t src_port;
	u_int16_t dst_port;

	u_int8_t  proto;
	u_int32_t proto_type;
	u_int32_t proto_subtype;
};

static inline void
kz_traffic_props_init(struct kz_traffic_props *traffic_props)
{
	memset(traffic_props, 0, sizeof(struct kz_traffic_props));
	traffic_props->proto_type = -1;
	traffic_props->proto_subtype = -1;
}

extern u_int32_t kz_lookup_session(const struct kz_config *cfg,
				   struct kz_traffic_props * const traffic_props,
				   struct kz_zone **clientzone, struct kz_zone **serverzone,
				   struct kz_service **service,
				   struct kz_dispatcher **dispatcher,
				   int reply);

/***********************************************************
 * Netlink functions
 ***********************************************************/

extern int kz_nfnetlink_init(void);
extern void kz_nfnetlink_cleanup(void);


/***********************************************************
 * Logging
 ***********************************************************/

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) "kzorp:%s:%d: " fmt, __func__, __LINE__
#endif

#define kz_bind_debug(bind, msg) \
{ \
	switch (bind->family) { \
	case NFPROTO_IPV4: \
		pr_debug("%s; address='%pI4', port='%d', proto='%d' pid='%d'\n", msg, &bind->addr.in, bind->port, bind->proto, bind->peer_pid); \
		break; \
	case NFPROTO_IPV6: \
		pr_debug("%s; address='%pI6c', port='%d', proto='%d' pid='%d'\n", msg, &bind->addr.in6, bind->port, bind->proto, bind->peer_pid); \
		break; \
	default: \
		BUG(); \
	} \
}

#define L4PROTOCOL_STRING_SIZE 20

/**
 * l4proto_as_string() - return name of layer 4 protocol from number
 * @l4proto: layer 4 protocol number
 * @buf: temporary buffer to use if no interned string representation is known
 *
 * Return a string representation of the layer 4 protocol number: either the
 * layer 4 protocol name for well-known protocols or the number itself
 * converted to a string.
 */
static inline const char *
l4proto_as_string(u8 l4proto, char buf[L4PROTOCOL_STRING_SIZE])
{
	const char *proto_name;

	switch (l4proto) {
	case IPPROTO_UDP:
		proto_name = "UDP";
		break;
	case IPPROTO_TCP:
		proto_name = "TCP";
		break;
	case IPPROTO_ICMP:
		proto_name = "ICMP";
		break;
#ifdef CONFIG_IP_VS_IPV6
	case IPPROTO_ICMPV6:
		proto_name = "ICMPv6";
		break;
#endif
	default:
		proto_name = NULL;
		break;
	}

	if (proto_name) {
		strncpy(buf, proto_name, L4PROTOCOL_STRING_SIZE);
		buf[L4PROTOCOL_STRING_SIZE - 1] = '\0';
	} else {
		sprintf(buf, "IP_%d", l4proto);
	}

	return buf;
}

enum kz_verdict {
	KZ_VERDICT_ACCEPTED                  = 0,
	KZ_VERDICT_DENIED_BY_POLICY          = 1,
	KZ_VERDICT_DENIED_BY_LIMIT           = 2,
	KZ_VERDICT_DENIED_BY_CONNECTION_FAIL = 3,
	KZ_VERDICT_DENIED_BY_UNKNOWN_FAIL    = 4
};

void kz_log_session_verdict(enum kz_verdict verdict, const char *info, const struct nf_conn *ct, const struct kz_extension *kzorp);

/* Bitfield */
enum {
	KZL_NONE		= 0,    /* supress log message */
	KZL_NORMAL		= 1,
	KZL_DROPPED_PACKETS	= 2,	/* silently dropped packets */
	KZL_PACKET_INFO		= 4,	/* source and destination */
	KZL_LOOKUP		= 8,	/* Main parts used by lookup_session */
	KZL_POINTERS		= 16,	/*service etc. pointers (debug) */
	KZL_FUNC_DEBUG		= 32,	/* function startup, control path  */
	KZL_FUNC_EXTRA_DEBUG    = 64,   /* basically same as KZL_FUNC_DEBUG, lots of log */
};

#define kz_log_with_dumped_tuple(logger_func, error_msg, tuple, zone_id) \
	char buf[L4PROTOCOL_STRING_SIZE]; \
	switch (tuple->src.l3num) { \
	case AF_INET: \
		logger_func("%s; tuple_address='%p' zone_id='%u' l4proto='%s' %pI4:%hu -> %pI4:%hu\n", \
			    error_msg, tuple, zone_id, l4proto_as_string(tuple->dst.protonum, buf), \
			    &tuple->src.u3.ip, ntohs(tuple->src.u.all), \
			    &tuple->dst.u3.ip, ntohs(tuple->dst.u.all)); \
		break; \
	case AF_INET6: \
		logger_func("%s; tuple_address='%p' zone_id='%u' l4proto='%s' %pI6:%hu -> %pI6:%hu\n", \
			    error_msg, tuple, zone_id, l4proto_as_string(tuple->dst.protonum, buf), \
			    tuple->src.u3.all, ntohs(tuple->src.u.all), \
			    tuple->dst.u3.all, ntohs(tuple->dst.u.all)); \
		break; \
	}

static inline void
kz_log_with_dumped_tuple_err_ratelimited(const char *error_msg, const struct nf_conntrack_tuple *tuple, const u16 zone_id)
{
	kz_log_with_dumped_tuple(pr_err_ratelimited, error_msg, tuple, zone_id)
}

static inline void
kz_log_with_dumped_tuple_warn_ratelimited(const char *error_msg, const struct nf_conntrack_tuple *tuple, const u16 zone_id)
{
	kz_log_with_dumped_tuple(pr_warn_ratelimited, error_msg, tuple, zone_id)
}


/***********************************************************
 * Accounting
 ***********************************************************/

#define kz_object_count_inc(object_name) \
static inline long kz_##object_name##_count_inc(struct kz_##object_name *object_name) \
{ \
	return atomic64_inc_return(&object_name->count); \
}

kz_object_count_inc(zone)
kz_object_count_inc(rule)
kz_object_count_inc(service)
#endif

/***********************************************************
 * getsockopt() interface
 ***********************************************************/

extern int kz_sockopt_init(void);
extern void kz_sockopt_cleanup(void);

/***********************************************************
 * Netlink interface
 ***********************************************************/

extern int kz_netlink_init(void);
extern void kz_netlink_cleanup(void);
