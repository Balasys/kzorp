/*
 * KZorp core
 *
 * Copyright (C) 2006-2010, BalaBit IT Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

/* TODO:
 *   - service NAT list should be stored in an array instead of a linked list
 *   - do we need the _add/_remove functions?
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

#include <net/ip.h>
#include <net/ipv6.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_acct.h>

#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "kzorp.h"
#include "kzorp_netlink.h"

static const char *const kz_log_null = "(NULL)";

#define LOG_RATELIMIT_MSG_COST 50

extern int sysctl_kzorp_log_ratelimit_msg_cost;
extern int sysctl_kzorp_log_ratelimit_burst;
extern int sysctl_kzorp_log_session_verdict;

/***********************************************************
 * Instances
 ***********************************************************/

DEFINE_MUTEX(kz_instance_mutex);
struct list_head kz_instances;


/* instance 0 is the "global" instance, so it must be the first instance created */
static unsigned int instance_id_cnt = 0;

static void __init
instance_init(void)
{
	INIT_LIST_HEAD(&kz_instances);
}

static void __exit
instance_cleanup(void)
{
	struct kz_instance *i, *s;
	list_for_each_entry_safe(i, s, &kz_instances, list) {
		list_del(&i->list);
		kfree(i);
	}
}

/* !!! must be called with the instance mutex held !!! */
struct kz_instance *
kz_instance_lookup_nocheck(const char *name)
{
	struct kz_instance *i;

	pr_debug("name='%s'\n", name);

	list_for_each_entry(i, &kz_instances, list) {
		if (strcmp(i->name, name) == 0)
			return i;
	}

	return NULL;
}

/* !!! must be called with the instance mutex held !!! */
struct kz_instance *
kz_instance_lookup(const char *name)
{
	struct kz_instance *i;

	pr_debug("name='%s'", name);

	list_for_each_entry(i, &kz_instances, list) {
		if (!(i->flags & KZF_INSTANCE_DELETED) &&
		    (strcmp(i->name, name) == 0))
			return i;
	}

	return NULL;
}

/* !!! must be called with the instance mutex held !!! */
struct kz_instance *
kz_instance_lookup_id(const unsigned int id)
{
	struct kz_instance *i;

	pr_debug("id='%u'\n", id);

	list_for_each_entry(i, &kz_instances, list) {
		if (!(i->flags & KZF_INSTANCE_DELETED) &&
		    (i->id == id))
			return i;
	}

	return NULL;
}

/***********************************************************
 * Per-instance bind address lists
 ***********************************************************/

struct kz_bind *
kz_bind_new(void)
{
	struct kz_bind *bind;

	bind = kzalloc(sizeof(struct kz_bind), GFP_KERNEL);
	if (bind == NULL)
		return NULL;

	INIT_LIST_HEAD(&bind->list);

	return bind;
}

struct kz_bind *
kz_bind_clone(const struct kz_bind const *_bind)
{
	struct kz_bind *bind;

	bind = kz_bind_new();
	if (bind == NULL)
		return NULL;

	bind->peer_pid = _bind->peer_pid;
	bind->family = _bind->family;
	bind->proto = _bind->proto;
	bind->addr = _bind->addr;
	bind->port = _bind->port;

	return bind;
}

void
kz_bind_destroy(struct kz_bind *bind)
{
	kfree(bind);
}

/* !!! must be called with the instance mutex held !!! */
struct kz_instance *
kz_instance_create(const char *name, const unsigned int len, const netlink_port_t peer_pid)
{
	struct kz_instance *i;

	pr_debug("name='%s', pid='%d'\n", name, peer_pid);

	/* check if we already have a deleted instance with this name */
	i = kz_instance_lookup_nocheck(name);
	if (i != NULL) {
		/* caller should check for existing instances */
		BUG_ON(!(i->flags & KZF_INSTANCE_DELETED));
		i->flags &= ~KZF_INSTANCE_DELETED;
		return i;
	}

	/* limit check */
	if (instance_id_cnt >= INSTANCE_MAX_NUM)
		return NULL;

	/* allocate memory for the structure + name + terminating 0 */
	i = kzalloc(sizeof(*i) + len + 1, GFP_KERNEL);
	if (i == NULL)
		return NULL;

	i->id = instance_id_cnt++;
	i->peer_pid = peer_pid;
	/* terminating zero comes from kzalloc() */
	memcpy(i->name, name, len);
	i->bind_lookup = kzalloc(sizeof(struct kz_bind_lookup), GFP_KERNEL);
	INIT_LIST_HEAD(&i->bind_lookup->list_bind);
	list_add(&i->list, &kz_instances);

	pr_debug("instance created; name='%s', id='%d'\n", name, i->id);

	return i;
}

/* !!! must be called with the instance mutex held !!! */
void
kz_instance_delete(struct kz_instance * const i)
{
	pr_debug("name='%s'\n", i->name);

	i->flags |= KZF_INSTANCE_DELETED;
}

/***********************************************************
 * Utility functions
 ***********************************************************/

char *
kz_name_dup(const char * const name)
{
	char *n;
	unsigned int len;

	if (name == NULL)
		return NULL;

	len = strlen(name);
	n = kmalloc(len + 1, GFP_KERNEL);
	if (n == NULL)
		return NULL;

	memcpy(n, name, len);
	n[len] = '\0';

	return n;
}

/***********************************************************
 * Config
 ***********************************************************/

/* content shall stay semantically 'empty', properly inited for work,
   only generation may change after module init!  */
static struct kz_config static_config =
{
	.zones = {.head = LIST_HEAD_INIT(static_config.zones.head)},
	.services = {.head = LIST_HEAD_INIT(static_config.services.head)},
	.dispatchers = {.head = LIST_HEAD_INIT(static_config.dispatchers.head)},
	.generation = 1,
	.cookie = 0UL
};

static void
kz_config_init(struct kz_config *cfg)
{
	cfg->cookie = 0;
	cfg->generation = 0;
	INIT_LIST_HEAD(&cfg->zones.head);
	INIT_LIST_HEAD(&cfg->services.head);
	INIT_LIST_HEAD(&cfg->dispatchers.head);
	kz_head_zone_init(&cfg->zones);
	kz_head_dispatcher_init(&cfg->dispatchers);
}

static int __init
static_cfg_init(void)
{
	int res = 0;
	kz_config_init(&static_config);
	static_config.generation = 1;

	res = kz_head_zone_build(&static_config.zones);
	if (res == 0)
		res = kz_head_dispatcher_build(&static_config.dispatchers);
	return res;
}

static void __exit
static_cfg_cleanup(void)
{
	kz_head_dispatcher_destroy(&static_config.dispatchers);
	kz_head_zone_destroy(&static_config.zones);
}

struct kz_config *kz_config_rcu = &static_config;

struct kz_config *kz_config_new(void)
{
	struct kz_config *cfg = kzalloc(sizeof(struct kz_config), GFP_KERNEL);
	if (cfg)
		kz_config_init(cfg);
	return cfg;
}

void kz_config_destroy(struct kz_config * cfg)
{
	if (cfg != NULL) {
		kz_head_destroy_zone(&cfg->zones);
		kz_head_destroy_service(&cfg->services);
		kz_head_destroy_dispatcher(&cfg->dispatchers);
		kfree(cfg);
	}
}

static void
kz_config_list_free_rcu(struct rcu_head *rcu_head)
{
	struct kz_config *cfg = container_of(rcu_head, struct kz_config, rcu);
	if (cfg != &static_config)
		kz_config_destroy(cfg);
}

void
kz_config_swap(struct kz_config * new_cfg)
{
	struct kz_config * old_cfg;
	rcu_read_lock();
	old_cfg = rcu_dereference(kz_config_rcu);
	if (new_cfg != old_cfg) {
		new_cfg->generation = old_cfg->generation + 1;
		rcu_assign_pointer(kz_config_rcu, new_cfg);
		if (old_cfg != &static_config)
			call_rcu(&old_cfg->rcu, kz_config_list_free_rcu);
	}
	rcu_read_unlock();
}

/***********************************************************
 * Lookup
 ***********************************************************/

/* fills kzorp structure with lookup data
   rcu_dereferenced config is stored in p_cfg
   call under rcu_read_lock() even if p_cfg==NULL!
   leaves non-lookup fields untouched!
   pointers in the passed structure must be valid/NULL,
   as they are released while the new ones addrefed
*/
static void kz_extension_fill_with_lookup_data_rcu(struct kz_extension * kzorp,
	enum ip_conntrack_info ctinfo,
	const struct sk_buff *skb,
	const struct net_device * const in,
	const u8 l3proto,
	const struct kz_config **p_cfg)
{
	struct kz_traffic_props traffic_props;
	u_int32_t rule_id = 0;
	struct timespec now;
	struct kz_zone *czone = NULL;
	struct kz_zone *szone = NULL;
	struct kz_dispatcher *dpt = NULL;
	struct kz_service *svc = NULL;
	struct {
		u16 src;
		u16 dst;
	} __attribute__((packed)) *ports, _ports = { .src = 0, .dst = 0 };
	const struct kz_config * loc_cfg;
	u8 l4proto;
	u_int32_t proto_type = 0, proto_subtype = 0;
	union nf_inet_addr *saddr, *daddr;
        struct kz_reqids reqids;
	int sp_idx;

	ports = &_ports;

	if (p_cfg == NULL)
		p_cfg = &loc_cfg;

	*p_cfg = rcu_dereference(kz_config_rcu);

	BUG_ON(*p_cfg == NULL);
	kzorp->generation = (*p_cfg)->generation;

	switch (l3proto) {
	case NFPROTO_IPV4:
	{
		const struct iphdr * const iph = ip_hdr(skb);

		l4proto = iph->protocol;
		saddr = (union nf_inet_addr *) &iph->saddr;
		daddr = (union nf_inet_addr *) &iph->daddr;

		if ((l4proto == IPPROTO_TCP) || (l4proto == IPPROTO_UDP)) {
			ports = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(_ports), &_ports);
			if (unlikely(ports == NULL))
				goto done;
			pr_debug("kzorp lookup for packet: protocol='%u', src='%pI4:%u', dst='%pI4:%u'\n",
				 iph->protocol, &iph->saddr, ntohs(ports->src), &iph->daddr, ntohs(ports->dst));
		}
		else if (l4proto == IPPROTO_ICMP) {
			const struct icmphdr *icmp;
			struct icmphdr _icmp = { .type = 0, .code = 0 };
			icmp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(_icmp), &_icmp);
			if (unlikely(icmp == NULL))
				goto done;

			proto_type = icmp->type;
			proto_subtype = icmp->code;
			pr_debug("kzorp lookup for packet: protocol='%u', src='%pI4', dst='%pI4', type='%d', code='%d'\n", l4proto,
				 &iph->saddr, &iph->daddr, icmp->type, icmp->code);
		}
	}
		break;
	case NFPROTO_IPV6:
	{
		const struct ipv6hdr * const iph = ipv6_hdr(skb);
		int thoff;
		u8 tproto = iph->nexthdr;

		/* find transport header */
		__be16 frag_offp;
		thoff = ipv6_skip_exthdr(skb, sizeof(*iph), &tproto, &frag_offp);
		if (unlikely(thoff < 0))
			goto done;

		l4proto = tproto;
		saddr = (union nf_inet_addr *) &iph->saddr;
		daddr = (union nf_inet_addr *) &iph->daddr;

		if ((l4proto == IPPROTO_TCP) || (l4proto == IPPROTO_UDP)) {
			/* get info from transport header */
			ports = skb_header_pointer(skb, thoff, sizeof(_ports), &_ports);
			if (unlikely(ports == NULL))
				goto done;
			pr_debug("kzorp lookup for packet: protocol='%u', src='%pI6c:%u', dst='%pI6c:%u'\n", l4proto,
				 &iph->saddr, ntohs(ports->src), &iph->daddr, ntohs(ports->dst));
		}
		else if (l4proto == IPPROTO_ICMPV6) {
			const struct icmp6hdr *icmp;
			struct icmp6hdr _icmp = { .icmp6_type = 0, .icmp6_code = 0 };
			icmp = skb_header_pointer(skb, thoff, sizeof(_icmp), &_icmp);
			if (unlikely(icmp == NULL))
				goto done;

			proto_type = icmp->icmp6_type;
			proto_subtype = icmp->icmp6_code;
			pr_debug("kzorp lookup for packet: protocol='%u', src='%pI6c', dst='%pI6c', type='%d', code='%d'\n", l4proto,
				 &iph->saddr, &iph->daddr, icmp->icmp6_type, icmp->icmp6_code);
		}

	}
		break;
	default:
		BUG();
		break;
	}

	/* copy IPSEC reqids from secpath to our own structure */
	if (skb->sp != NULL) {
		reqids.len = skb->sp->len;
		for (sp_idx = 0; sp_idx  < reqids.len; sp_idx++)
			reqids.vec[sp_idx] = skb->sp->xvec[sp_idx]->props.reqid;
	} else {
		reqids.len = 0;
	}

	kz_traffic_props_init(&traffic_props);
	traffic_props.l3proto = l3proto;
	traffic_props.proto = l4proto;
	traffic_props.reqids = &reqids;
	traffic_props.iface = in;
	traffic_props.src_addr = saddr;
	traffic_props.dst_addr = daddr;
	switch (l4proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		traffic_props.src_port = ntohs(ports->src);
		traffic_props.dst_port = ntohs(ports->dst);
		break;

	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		traffic_props.proto_type = proto_type;
		traffic_props.proto_subtype = proto_subtype;
		break;

	default:
		break;
	}
	rule_id = kz_lookup_session(*p_cfg,
				    &traffic_props,
				    &czone, &szone,
				    &svc, &dpt,
				    (ctinfo >= IP_CT_IS_REPLY));

done:
#define REPLACE_PTR(name, type) \
	if (kzorp->name != name) { \
		if (kzorp->name) \
			kz_##type##_put(kzorp->name); \
		kzorp->name = name ? kz_##type##_get(name) : NULL; \
	}

	REPLACE_PTR(czone, zone);
	REPLACE_PTR(szone, zone);
	REPLACE_PTR(dpt, dispatcher);
	REPLACE_PTR(svc, service);

#undef REPLACE_PTR

	if (kzorp->rule_id != rule_id)
		kzorp->rule_id = rule_id;

	getnstimeofday(&now);
	if (kzorp->session_start != now.tv_sec)
		kzorp->session_start = now.tv_sec;

	pr_debug("kzorp lookup result; dpt='%s', client_zone='%s', server_zone='%s', svc='%s'\n",
		 kzorp->dpt ? kzorp->dpt->name : kz_log_null,
		 kzorp->czone ? kzorp->czone->name : kz_log_null,
		 kzorp->szone ? kzorp->szone->name : kz_log_null,
		 kzorp->svc ? kzorp->svc->name : kz_log_null);

	return;
}

static struct kz_extension *
kz_extension_add(struct nf_conn *ct,
		 enum ip_conntrack_info ctinfo,
		 const struct sk_buff *skb,
		 const struct net_device * const in,
		 const u8 l3proto,
		 const struct kz_config **p_cfg)
{
	struct kz_extension *kzorp;

	/* if the conntrack is confirmed extension must not be added */
	if (unlikely(nf_ct_is_confirmed(ct))) {
		switch (l3proto) {
		case NFPROTO_IPV4:
		{
			const struct iphdr * const iph = ip_hdr(skb);
			pr_debug("can't add kzorp to ct for packet: src='%pI4', dst='%pI4'\n",
				 &iph->saddr, &iph->daddr);
		}
			break;
		case NFPROTO_IPV6:
		{
			const struct ipv6hdr * const iph = ipv6_hdr(skb);
			pr_debug("can't add kzorp to ct for packet: src='%pI6c', dst='%pI6c'\n",
				 &iph->saddr, &iph->daddr);
		}
			break;
		default:
			BUG();
		}
		return NULL;
	}

	kzorp = kz_extension_create();
	if (unlikely(!kzorp))
		return NULL;

	/* implicit:  kzorp->sid = 0; */
	kz_extension_fill_with_lookup_data_rcu(kzorp, ctinfo, skb, in, l3proto, p_cfg);
	kz_extension_add_to_cache(kzorp, &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple, kz_nf_ct_zone_id(ct));
	return kzorp;
}

/* returns consolidated kzorp lookup info; caches it in ct, and uses
   the cache if valid;
   returns NULL only if it's not possible to add kzorp extension to ct
   rcu_dereferenced config is stored in p_cfg
  call under rcu_read_lock() even if p_cfg==NULL!
*/
static struct kz_extension *
kz_extension_find_or_add(struct nf_conn *ct,
		    enum ip_conntrack_info ctinfo,
		    const struct sk_buff *skb,
		    const struct net_device * const in,
		    const u8 l3proto,
		    const struct kz_config **p_cfg)
{
	struct kz_extension *kzorp;
	const struct kz_config *kzorp_config;

	kzorp_config = rcu_dereference(kz_config_rcu);
	kzorp = kz_extension_find(ct);
	if (kzorp) {
		if (unlikely(!kz_generation_valid(kzorp_config, kzorp->generation)))
			kz_extension_fill_with_lookup_data_rcu(kzorp, ctinfo, skb, in, l3proto, &kzorp_config);
	} else {
		kzorp = kz_extension_add(ct, ctinfo, skb, in, l3proto, &kzorp_config);
	}

	if (p_cfg)
		*p_cfg = kzorp_config;

	return kzorp;
}

struct kz_extension *
kz_extension_find_or_evaluate(const struct sk_buff *skb,
				   const struct net_device * const in,
				   u8 l3proto,
				   const struct kz_config **cfg)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct kz_extension *kzorp;

	ct = nf_ct_get((struct sk_buff *)skb, &ctinfo);
	if (ct && !nf_ct_is_untracked(ct)) {
		// ctinfo filled by nf_ct_get
		kzorp = kz_extension_find_or_add(ct, ctinfo, skb, in, l3proto, cfg);
	} else {
		ctinfo = IP_CT_NEW;
		kzorp = NULL;
	}

	if (kzorp == NULL) {
		pr_debug("cannot add kzorp extension, doing local lookup\n");

		kzorp = kz_extension_create();
		kz_extension_fill_with_lookup_data_rcu(kzorp, ctinfo, skb, in, l3proto, cfg);
	}

	return kzorp;
}
EXPORT_SYMBOL_GPL(kz_extension_find_or_evaluate);

/***********************************************************
 * Common macros
 ***********************************************************/

#define kz_alloc_entry(entry_name, dst_name, src_name, error_label) \
	if (src_name->alloc_##entry_name) { \
		dst_name->entry_name = kzalloc(sizeof(*dst_name->entry_name) * src_name->alloc_##entry_name, GFP_KERNEL); \
		if (dst_name->entry_name == NULL) { \
			res = -ENOMEM; \
			goto error_label; \
		} \
	} else { \
		dst_name->entry_name = NULL; \
	} \
	dst_name->alloc_##entry_name = src_name->alloc_##entry_name;

#define kz_clone_entry(entry_name, dst_name, src_name) \
	dst_name->num_##entry_name = src_name->num_##entry_name; \
	memcpy(dst_name->entry_name, src_name->entry_name, \
	       dst_name->alloc_##entry_name * sizeof(*dst_name->entry_name));

/***********************************************************
 * Zones
 ***********************************************************/

#define ZONE_SERVICE_ALLOC_THRESHOLD 8
struct kz_zone *
kz_zone_new(void)
{
	struct kz_zone *zone;

	zone = kzalloc(sizeof(struct kz_zone), GFP_KERNEL);
	if (zone == NULL)
		return NULL;

	atomic_set(&zone->refcnt, 1);
	atomic64_set(&zone->count, 0);
	zone->depth = 1;

	return zone;
}

void
kz_zone_destroy(struct kz_zone *zone)
{
       if (zone->admin_parent)
	       kz_zone_put(zone->admin_parent);
       if (zone->name)
	       kfree(zone->name);
       if (zone->subnet)
	       kfree(zone->subnet);

       kfree(zone);
}
EXPORT_SYMBOL_GPL(kz_zone_destroy);

struct kz_zone *
__kz_zone_lookup_name(const struct list_head * const head, const char *name)
{
	struct kz_zone *i;

	BUG_ON(!name);

	list_for_each_entry(i, head, list) {
		if (strcmp(i->name, name) == 0)
			return i;
	}

	return NULL;
}

struct kz_zone *
kz_zone_lookup_name(const struct kz_config *cfg, const char *name)
{
	return __kz_zone_lookup_name(&cfg->zones.head, name);
}

struct kz_zone *
kz_zone_clone(const struct kz_zone * const o)
{
	struct kz_zone *zone;
	int res = 0;

	zone = kz_zone_new();
	if (zone == NULL)
		return NULL;

	zone->depth = o->depth;

	zone->name = kz_name_dup(o->name);
	if (zone->name == NULL)
		goto error_put;

	kz_alloc_entry(subnet, zone, o, error_put);
	kz_clone_entry(subnet, zone, o);

	if (o->admin_parent != NULL)
		zone->admin_parent = kz_zone_get(o->admin_parent);

	atomic64_set(&zone->count, atomic64_read(&o->count));

	return zone;

error_put:
	kz_zone_put(zone);

	return NULL;
}

void
kz_head_destroy_zone(struct kz_head_z *head)
{
	struct kz_zone *i, *p;

	/* destroy lookup data structures */
	kz_head_zone_destroy(head);

	list_for_each_entry_safe(i, p, &head->head, list) {
		list_del(&i->list);
		kz_zone_put(i);
	}
}

/***********************************************************
 * Services
 ***********************************************************/

static atomic_t service_id_cnt;

struct kz_service *
kz_service_new(void)
{
	struct kz_service *service;

	service = kzalloc(sizeof(struct kz_service), GFP_KERNEL);
	if (service == NULL)
		return NULL;

	atomic_set(&service->refcnt, 1);
	atomic64_set(&service->count, 0);

	service->id = atomic_inc_return(&service_id_cnt);

	INIT_LIST_HEAD(&service->a.fwd.snat);
	INIT_LIST_HEAD(&service->a.fwd.dnat);

	return service;
}

void
kz_service_destroy(struct kz_service *service)
{
	struct kz_service_nat_entry *i, *s;

	if (service->name)
		kfree(service->name);

	if (service->type == KZ_SERVICE_FORWARD) {
		/* free NAT entries */
		list_for_each_entry_safe(i, s, &service->a.fwd.snat, list) {
			list_del(&i->list);
			kfree(i);
		}
		list_for_each_entry_safe(i, s, &service->a.fwd.dnat, list) {
			list_del(&i->list);
			kfree(i);
		}
	}

	kfree(service);
}

struct kz_service *
__kz_service_lookup_name(const struct list_head * const head, const char *name)
{
	struct kz_service *i;

	BUG_ON(!name);

	list_for_each_entry(i, head, list) {
		if (strcmp(i->name, name) == 0)
			return i;
	}

	return NULL;
}

struct kz_service *
kz_service_lookup_name(const struct kz_config *cfg, const char *name)
{
	return __kz_service_lookup_name(&cfg->services.head, name);
}
EXPORT_SYMBOL_GPL(kz_service_lookup_name);

int
kz_service_add_nat_entry(struct list_head *head, struct nf_nat_range *src,
			 struct nf_nat_range *dst, struct nf_nat_range *map,
			 uint8_t l3proto)
{
	struct kz_service_nat_entry *entry;

	BUG_ON(!src);
	BUG_ON(!map);

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (entry == NULL)
		return -ENOMEM;

	entry->src = *src;
	entry->dst = *dst;
	entry->map = *map;
	entry->l3proto = l3proto;

	list_add_tail(&entry->list, head);

	return 0;
}

static int
service_clone_nat_list(const struct list_head * const src, struct list_head *dst)
{
	struct kz_service_nat_entry *i;
	int res = 0;

	list_for_each_entry(i, src, list) {
		res = kz_service_add_nat_entry(dst, &i->src, &i->dst, &i->map,
					       i->l3proto);
		if (res < 0)
			break;
	}

	return res;
}

struct kz_service *
kz_service_clone(const struct kz_service * const o)
{
	struct kz_service *svc;

	svc = kz_service_new();
	if (svc == NULL)
		return NULL;

	svc->instance_id = o->instance_id;
	svc->flags = o->flags;
	svc->type = o->type;
	svc->a = o->a;
	svc->name = kz_name_dup(o->name);
	if (svc->name == NULL)
		goto error_put;
	if (svc->type == KZ_SERVICE_FORWARD) {
		INIT_LIST_HEAD(&svc->a.fwd.snat);
		if (service_clone_nat_list(&o->a.fwd.snat, &svc->a.fwd.snat) < 0)
			goto error_put;
		INIT_LIST_HEAD(&svc->a.fwd.dnat);
		if (service_clone_nat_list(&o->a.fwd.dnat, &svc->a.fwd.dnat) < 0)
			goto error_put;
	}

	return svc;

error_put:
	kz_service_put(svc);

	return NULL;
}

long
kz_service_lock(struct kz_service * const service)
{
	/* lock service session counter */
	set_bit(KZ_SERVICE_CNT_LOCKED_BIT, (unsigned long *)&service->flags);
	return atomic64_read(&service->count);
}

void
kz_service_unlock(struct kz_service * const service)
{
	clear_bit(KZ_SERVICE_CNT_LOCKED_BIT, (unsigned long *)&service->flags);
}

void
kz_head_destroy_service(struct kz_head_s *head)
{
	struct kz_service *i, *p;

	list_for_each_entry_safe(i, p, &head->head, list) {
		list_del(&i->list);
		kz_service_put(i);
	}
}

/***********************************************************
 * Dispatchers
 ***********************************************************/

static struct workqueue_struct *vfree_queue;

#define DISPATCHER_CSS_ALLOC_THRESHOLD 8

static int __init
dpt_init(void)
{
	vfree_queue = create_workqueue("kzorp_vfree_queue");
	if (vfree_queue == NULL) {
		return -ENOMEM;
	}
	return 0;
}

static void
dpt_cleanup(void)
{
	flush_workqueue(vfree_queue);
	destroy_workqueue(vfree_queue);
}

void*
kz_big_alloc(size_t size, enum KZ_ALLOC_TYPE *alloc_type)
{
	void * ret = kzalloc(size, GFP_KERNEL | __GFP_NOWARN);
	*alloc_type = KZALLOC;

	if (!ret) {
		ret = __vmalloc(size, GFP_KERNEL | __GFP_ZERO, PAGE_KERNEL);
		*alloc_type = VMALLOC;
	}

	return ret;
}

static void
vfree_wq_function(struct work_struct *work)
{
	const kz_vfree_work_t *w = (kz_vfree_work_t *) work;

	vfree(w->p);
	kfree(w);
}

void
kz_big_free(void *ptr, enum KZ_ALLOC_TYPE alloc_type)
{
	switch (alloc_type) {
	case KZALLOC: {
			kzfree(ptr);
			break;
		}
	case VMALLOC: {
			int res;
			kz_vfree_work_t *w = kzalloc(sizeof(kz_vfree_work_t), GFP_KERNEL);
			INIT_WORK((struct work_struct *) w, vfree_wq_function);
			w->p = ptr;
			res = queue_work(vfree_queue, (struct work_struct *)w);
			BUG_ON(!res);
			break;
		}
	}
}

/**
 * kz_dispatcher_alloc_rule_array - allocate rule array for N-dim rules
 * @dispatcher: the dispatcher to allocate the array for
 * @alloc_rules: the number of rules to allocate memory for
 *
 * This function tries to allocate the rule array using kzalloc(). If
 * that fails (because we're over the maximum memory allocatable by
 * the slab allocator) we retry the allocation using vmalloc().
 *
 * kz_dispatcher_alloc_rule_array() is always called in user
 * context. For freeing the vmalloc()-ed memory block we have to
 * allocate a work_queue structure, too, so that we don't have to
 * allocate memory when we're trying to free the array.
 *
 * Returns: 0 on success,
 *          -ENOMEM if memory allocation fails
 */
int
kz_dispatcher_alloc_rule_array(struct kz_dispatcher *dispatcher, size_t alloc_rules)
{
	const size_t rule_size = sizeof(struct kz_rule) * alloc_rules;

	dispatcher->rule = kz_big_alloc(rule_size, &dispatcher->rule_allocator);

	dispatcher->num_rule = 0;
	dispatcher->alloc_rule = alloc_rules;

	return 0;
}

/**
 * kz_dispatcher_free_rule_array - free rule array in dispatcher structure
 * @dispatcher: dispatcher to clean up
 *
 * Frees the rule array in the dispatcher structure. This is tricky
 * because the array may have been allocated using vmalloc() and in
 * that case we have to defer vfree()-ing the memory to a work queue
 * thread (so that it happens in user context).
 */
static void
kz_dispatcher_free_rule_array(struct kz_dispatcher *dispatcher)
{
	if (dispatcher->rule != NULL) {
		kz_big_free(dispatcher->rule, dispatcher->rule_allocator);
	}

	dispatcher->num_rule = dispatcher->alloc_rule = 0;
	dispatcher->rule = NULL;
}

struct kz_dispatcher *
kz_dispatcher_new(void)
{
	struct kz_dispatcher *dispatcher;

	dispatcher = kzalloc(sizeof(struct kz_dispatcher), GFP_KERNEL);
	if (dispatcher == NULL)
		return NULL;

	atomic_set(&dispatcher->refcnt, 1);

	return dispatcher;
}

static void
kz_rule_destroy(struct kz_rule *rule)
{
	int j;

	if (rule == NULL)
		return;

	for (j = 0; j < rule->num_src_zone; j++)
		kz_zone_put(rule->src_zone[j]);
	for (j = 0; j < rule->num_dst_zone; j++)
		kz_zone_put(rule->dst_zone[j]);

	kz_service_put(rule->service);

	kfree(rule->src_in_subnet);
	kfree(rule->dst_in_subnet);
	kfree(rule->src_in6_subnet);
	kfree(rule->dst_in6_subnet);
	kfree(rule->ifname);
	kfree(rule->ifgroup);
	kfree(rule->src_port);
	kfree(rule->dst_port);
	kfree(rule->src_zone);
	kfree(rule->dst_zone);
	kfree(rule->proto);
	kfree(rule->dst_ifname);
	kfree(rule->dst_ifgroup);
	kfree(rule->reqid);

	memset(rule, 0, sizeof(*rule));
}

void
kz_dispatcher_destroy(struct kz_dispatcher *dispatcher)
{
	int i;

	if (dispatcher->name)
		kfree(dispatcher->name);

	if (dispatcher->rule != NULL) {
		/* drop rule references */
		for (i = 0; i < dispatcher->num_rule; i++)
			kz_rule_destroy(&dispatcher->rule[i]);

		kz_dispatcher_free_rule_array(dispatcher);
	}

	kfree(dispatcher);
}

struct kz_dispatcher *
kz_dispatcher_lookup_name(const struct kz_config *cfg, const char *name)
{
	struct kz_dispatcher *i;

	BUG_ON(!name);

	list_for_each_entry(i, &cfg->dispatchers.head, list) {
		if (strcmp(i->name, name) == 0)
			return i;
	}

	return NULL;
}

int
kz_dispatcher_add_rule(struct kz_dispatcher *d, struct kz_service *service,
		       const struct kz_rule * const rule_params)
{
	int res = 0;
	struct kz_rule *rule = NULL;
	int64_t last_id = -1L;

	if (d->num_rule + 1 > d->alloc_rule) {
		pr_err_ratelimited("each rule has already been added to this dispatcher; num_rule='%d'\n",
		       d->alloc_rule);
		res = -EINVAL;
		goto error;
	}

	/* check that the ID of the rule to be added is larger than
	 * the ID of the last rule */
	if (d->num_rule > 0)
		last_id = d->rule[d->num_rule - 1].id;

	if (rule_params->id <= last_id) {
		pr_err_ratelimited("rule id is not larger than the id of the last rule; id='%u', last_id='%lld'\n", rule_params->id, last_id);
		res = -EINVAL;
		goto error;
	}

	rule = &d->rule[d->num_rule];
	rule->id = rule_params->id;
	rule->service = kz_service_get(service);
	rule->dispatcher = d;
	atomic64_set(&rule->count, 0);

#define CALL_kz_alloc_rule_dimension(DIM_NAME, NL_ATTR_NAME, _, NL_TYPE, ...) \
	kz_alloc_entry(DIM_NAME, rule, rule_params, error_free_dimensions)

	KZORP_DIM_LIST(CALL_kz_alloc_rule_dimension, ;);

#undef CALL_kz_alloc_rule_dimension

	d->num_rule++;

	return 0;

error_free_dimensions:
	kz_rule_destroy(rule);

error:
	return res;
}

#define kz_object_entry_check_alloc(object_name, entry_name)		\
	if (object_name->num_##entry_name + 1 > object_name->alloc_##entry_name) { \
		pr_err_ratelimited("each " #entry_name " has already been added to the " #object_name "; alloc_" #entry_name "='%d'", \
		       object_name->num_##entry_name);			\
		res = -ENOMEM;					\
		goto error;					\
	}							\

#define kz_object_entry_append_value(object_name, entry_name)		\
	if (object_name->has_##entry_name) {			\
		kz_object_entry_check_alloc(rule, entry_name)           \
		rule->entry_name[rule->num_##entry_name] = object_name->entry_name; \
	}

#define kz_object_entry_append_portrange(object_name, entry_name)		\
	if (object_name->has_##entry_name) {			\
		kz_object_entry_check_alloc(rule, entry_name)           \
		rule->entry_name[rule->num_##entry_name].from = object_name->entry_name.from; \
		rule->entry_name[rule->num_##entry_name].to = object_name->entry_name.to; \
	}

#define kz_object_entry_append_subnet(object_name, entry_name)		\
	if (object_name->has_##entry_name) {			\
		kz_object_entry_check_alloc(rule, entry_name)           \
		rule->entry_name[rule->num_##entry_name].addr = object_name->entry_name.addr; \
		rule->entry_name[rule->num_##entry_name].mask = object_name->entry_name.mask; \
	}

#define kz_object_entry_append_in_subnet(object_name, entry_name)		\
	kz_object_entry_append_subnet(object_name, entry_name)
#define kz_object_entry_append_in6_subnet(object_name, entry_name)		\
	kz_object_entry_append_subnet(object_name, entry_name)

#define kz_object_entry_append_ifname(object_name, entry_name) \
	if (object_name->has_##entry_name) { \
		kz_object_entry_check_alloc(rule, entry_name)           \
		memcpy(rule->entry_name[rule->num_##entry_name], object_name->entry_name, IFNAMSIZ); \
	}

#define kz_object_entry_append_string(object_name, entry_name)		\
	kz_object_entry_append_value(object_name, entry_name)

#define kz_object_entry_num_inc(object_name, entry_name) \
		object_name->num_##entry_name++;

#define kz_dispatcher_inc_rule_entry_num(entry_name) \
	if (rule_entry_params->has_##entry_name) { \
		kz_object_entry_num_inc(rule, entry_name) \
	}

int
kz_dispatcher_add_rule_entry(struct kz_rule *rule,
			     const struct kz_rule_entry_params * const rule_entry_params)
{
	int res = 0;
	struct kz_zone *zone;

#define CALL_kz_dispatcher_append_rule_entry(DIM_NAME, NL_ATTR_NAME, _, NL_TYPE, ...) \
	kz_object_entry_append_##NL_TYPE(rule_entry_params, DIM_NAME)

	KZORP_DIM_LIST(CALL_kz_dispatcher_append_rule_entry, ;);

#undef CALL_kz_dispatcher_append_rule_entry

	// no error has occured
	if (rule_entry_params->has_src_zone) {
		zone = rule->src_zone[rule->num_src_zone];
		if (zone != NULL)
			kz_zone_get(zone);
	}

	if (rule_entry_params->has_dst_zone) {
		zone = rule->dst_zone[rule->num_dst_zone];
		if (zone != NULL)
			kz_zone_get(zone);
	}

#define CALL_kz_dispatcher_inc_rule_entry_num(DIM_NAME, NL_ATTR_NAME, _, NL_TYPE, ...) \
	kz_dispatcher_inc_rule_entry_num(DIM_NAME)

	KZORP_DIM_LIST(CALL_kz_dispatcher_inc_rule_entry_num, ;);

#undef CALL_kz_dispatcher_inc_rule_entry_num

error:
	return res;
}

int
kz_add_zone_subnet(struct kz_zone *zone,
		   const struct kz_subnet * const zone_subnet)
{
	int res = 0;

	kz_object_entry_check_alloc(zone, subnet);

	zone->subnet[zone->num_subnet].family = zone_subnet->family;
	zone->subnet[zone->num_subnet].addr = zone_subnet->addr;
	zone->subnet[zone->num_subnet].mask = zone_subnet->mask;

	kz_object_entry_num_inc(zone, subnet)

error:
	return res;
}

int
kz_add_zone(struct kz_zone *zone)
{
	int res = 0;

	kz_alloc_entry(subnet, zone, zone, error);

error:
	return res;
}

static int
kz_rule_arr_relink_zones(u_int32_t * size, struct kz_zone **arr, u_int32_t rule_id, const struct list_head * zonelist)
{
	u_int32_t i, put;

	if (*size == 0)
		return 0;

	for (i = 0, put = 0; i < *size; ++i)
	{
		struct kz_zone * const in = arr[i];
		struct kz_zone * out = __kz_zone_lookup_name(zonelist, in->name);

                /**
		 * After rename/delete of a zone kZorp daemon is reloaded and the new zone
		 * hierarchy is downloaded, but the rules are unaffected while the Zorp is
		 * not reloaded. Therefore after kZorp daemon reloads rules may contain
		 * references to non-existing zones. After Zorp reload configuration will
		 * consistent again.
		 */
		if (out == NULL) {
			pr_err_ratelimited("Zone referred by rule cannot be found, therefore removed; rule_id='%d', zone_name='%s'",
			       rule_id, in->name);
                        kz_zone_put(in);
			continue;
		}
		if (in != out) {
			kz_zone_get(out);
			kz_zone_put(in);
		}
		arr[put++] = out;
	}
        *size = put;
	return 0;
}

static int
kz_rule_relink_zones(struct kz_rule *r, const struct list_head * zonelist)
{
	int error = 0;
	error = kz_rule_arr_relink_zones(&r->num_src_zone, r->src_zone, r->id, zonelist);
	if (error != 0)
		return error;
	return kz_rule_arr_relink_zones(&r->num_dst_zone, r->dst_zone, r->id, zonelist);
}

int
kz_rule_copy(struct kz_rule *dst,
	     const struct kz_rule * const src)
{
	int res = 0;
	int i;

	dst->id = src->id;
	dst->service = kz_service_get(src->service);
	dst->dispatcher = NULL;
	atomic64_set(&dst->count, atomic64_read(&src->count));

#define CALL_kz_alloc_rule_dimension(DIM_NAME, NL_ATTR_NAME, _, NL_TYPE, ...) \
	kz_alloc_entry(DIM_NAME, dst, src, error)

	KZORP_DIM_LIST(CALL_kz_alloc_rule_dimension, ;);

#undef CALL_kz_alloc_rule_dimension

#define CALL_kz_clone_rule_dimension(DIM_NAME, NL_ATTR_NAME, _, NL_TYPE, ...) \
	kz_clone_entry(DIM_NAME, dst, src)

	KZORP_DIM_LIST(CALL_kz_clone_rule_dimension, ;)

#undef CALL_kz_clone_rule_dimension

	for (i = 0; i < dst->num_src_zone; i++)
		dst->src_zone[i] = kz_zone_get(dst->src_zone[i]);
	for (i = 0; i < dst->num_dst_zone; i++)
		dst->dst_zone[i] = kz_zone_get(dst->dst_zone[i]);

	return 0;

error:
	kz_rule_destroy(dst);

	return res;
}

int
kz_dispatcher_copy_rules(struct kz_dispatcher *dst,
			 const struct kz_dispatcher * const src)
{
	unsigned int i = 0, j;
	int res = 0;

	dst->alloc_rule = src->alloc_rule;

	if (dst->alloc_rule == 0) {
		dst->rule = NULL;
		dst->num_rule = 0;
	} else {
		res = kz_dispatcher_alloc_rule_array(dst, src->alloc_rule);
		if (res < 0)
			return -ENOMEM;


		for (i = 0; i < src->num_rule; i++) {
			res = kz_rule_copy(&dst->rule[i], &src->rule[i]);
			if (res < 0)
				goto error;

			dst->rule[i].dispatcher = dst;
			dst->num_rule = i + 1;
		}
	}

	pr_debug("cloned rules; dst_num_rules='%u', dst_alloc_rules='%u', src_num_rules='%u', src_alloc_rules='%u'\n",
		 dst->num_rule, dst->alloc_rule, src->num_rule, src->alloc_rule);

	return 0;

error:
	if (dst->rule) {
		for (j = 0; j < dst->num_rule; j++)
			kz_rule_destroy(&dst->rule[j]);

		kz_dispatcher_free_rule_array(dst);
	}

	return res;
}

struct kz_dispatcher *
kz_dispatcher_clone_pure(const struct kz_dispatcher * const o)
{
	struct kz_dispatcher *dpt;

	dpt = kz_dispatcher_new();
	if (dpt == NULL)
		return NULL;

	dpt->instance = o->instance;
	dpt->name = kz_name_dup(o->name);
	if (dpt->name == NULL)
		goto error_put;

	return dpt;

error_put:
	kz_dispatcher_put(dpt);

	return NULL;
}

struct kz_dispatcher *
kz_dispatcher_clone(const struct kz_dispatcher * const o)
{
	struct kz_dispatcher *dpt;

	dpt = kz_dispatcher_clone_pure(o);
	if (dpt == NULL)
		return NULL;

	if (kz_dispatcher_copy_rules(dpt, o) < 0)
		goto error_put;

	return dpt;

error_put:
	kz_dispatcher_put(dpt);

	return NULL;
}

/* all zone links must point into the passed lists, remove those not found */
static int
kz_dispatcher_relink_n_dim(struct kz_dispatcher *d, const struct list_head * zonelist, const struct list_head * servicelist)
{
	unsigned int i;
	int error;
	for (i = 0; i < d->num_rule; ++i) {
		struct kz_rule *rule = &d->rule[i];
		struct kz_service *service = __kz_service_lookup_name(servicelist, rule->service->name);
		if (service == NULL) {
			pr_err_ratelimited("Service can not be deleted while it is refered; dispatcher='%s', rule_id='%u', service='%s'\n",
			       d->name, rule->id, rule->service->name);
			return -EINVAL;
		}
		if (service != rule->service) {
			kz_service_put(rule->service);
			rule->service = kz_service_get(service);
		}
		error = kz_rule_relink_zones(rule, zonelist);
		if (error != 0)
			return error;
	}

	return 0;
}

int
kz_dispatcher_relink(struct kz_dispatcher *d, const struct list_head * zonelist, const struct list_head * servicelist)
{
	pr_debug("re-linked n-dim dispatcher; name='%s', num_rules='%u'\n", d->name, d->num_rule);
	return kz_dispatcher_relink_n_dim(d, zonelist, servicelist);
}

void
kz_head_destroy_dispatcher(struct kz_head_d *head)
{
	struct kz_dispatcher *i, *p;

	/* destroy lookup data structures */
	kz_head_dispatcher_destroy(head);

	list_for_each_entry_safe(i, p, &head->head, list) {
		list_del(&i->list);
		kz_dispatcher_put(i);
	}
}

/***********************************************************
 * sysctl interface
 ***********************************************************/

#ifdef CONFIG_SYSCTL
static struct ctl_table kzorp_table[] = {
	{
		.procname	= "log_ratelimit_msg_cost",
		.data		= &sysctl_kzorp_log_ratelimit_msg_cost,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_ms_jiffies
	},
	{
		.procname	= "log_ratelimit_burst",
		.data		= &sysctl_kzorp_log_ratelimit_burst,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		.procname	= "log_session_verdict",
		.data		= &sysctl_kzorp_log_session_verdict,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{ }
};

static struct ctl_table_header * kzorp_sysctl_header;
#endif /* CONFIG_SYSCTL */

/***********************************************************
 * Rate limit
 ***********************************************************/

#define LOG_RATELIMIT_MSG_COST 50
#define LOG_RATELIMIT_BURST    50

/*
 * printk rate limiting, lifted from the networking subsystem.
 *
 * This enforces a rate limit: not more than one kernel message
 * every printk_ratelimit_jiffies to make a denial-of-service
 * attack impossible.
 */
static int __log_ratelimit(int ratelimit_msg_cost, int ratelimit_burst)
{
	static DEFINE_SPINLOCK(ratelimit_lock);
	static unsigned long toks = LOG_RATELIMIT_MSG_COST * HZ * LOG_RATELIMIT_BURST / 1000;
	static unsigned long last_msg;
	static int missed;
	unsigned long flags;
	unsigned long now = jiffies;

	spin_lock_irqsave(&ratelimit_lock, flags);
	toks += now - last_msg;
	last_msg = now;

	if (toks > (ratelimit_burst * ratelimit_msg_cost))
		toks = ratelimit_burst * ratelimit_msg_cost;

	if (toks >= ratelimit_msg_cost) {
		int lost = missed;

		missed = 0;
		toks -= ratelimit_msg_cost;
		spin_unlock_irqrestore(&ratelimit_lock, flags);

		if (lost)
			printk(KERN_WARNING "kzorp: %d messages suppressed.\n", lost);

		return 1;
	}

	missed++;
	spin_unlock_irqrestore(&ratelimit_lock, flags);

	return 0;
}

/* minimum time in jiffies between messages */
int sysctl_kzorp_log_ratelimit_msg_cost;

/* number of messages we send before ratelimiting */
int sysctl_kzorp_log_ratelimit_burst = LOG_RATELIMIT_BURST;

int kz_log_ratelimit(void)
{
	return __log_ratelimit(sysctl_kzorp_log_ratelimit_msg_cost,
			       sysctl_kzorp_log_ratelimit_burst);
}
EXPORT_SYMBOL_GPL(kz_log_ratelimit);

int sysctl_kzorp_log_session_verdict = false;

bool kz_log_session_verdict_enabled(void) {
	return !!sysctl_kzorp_log_session_verdict;
}
EXPORT_SYMBOL_GPL(kz_log_session_verdict_enabled);

static inline const char *
verdict_as_string(enum kz_verdict verdict)
{
	switch (verdict) {
	case KZ_VERDICT_ACCEPTED:
		return "ACCEPTED";
	case KZ_VERDICT_DENIED_BY_POLICY:
		return "DENIED_BY_POLICY";
	case KZ_VERDICT_DENIED_BY_LIMIT:
		return "DENIED_BY_LIMIT";
	case KZ_VERDICT_DENIED_BY_CONNECTION_FAIL:
		return "DENIED_BY_CONNECTION_FAIL";
	case KZ_VERDICT_DENIED_BY_UNKNOWN_FAIL:
		return "DENIED_BY_UNKNOWN_FAIL";
	}

	// there is no other case than drop and accept as verdict
	BUG();
	return NULL;
}

// 8 groups of 4 hexa numbers with 7 ':' between them in case of IPv6
#define IP_MAX_LENGTH (8 * 4) + 7

void
kz_log_session_verdict(enum kz_verdict verdict,
		       const char *info,
		       const struct nf_conn *ct,
		       const struct kz_extension *kzorp)
{
	u_int16_t l3proto;
	u_int16_t l4proto;
	bool has_server_side_connection;
	char _buf[L4PROTOCOL_STRING_SIZE];
	char server_str[IP_MAX_LENGTH + 1];
	char server_local_str[IP_MAX_LENGTH + 1];
	const char *verdict_str;
	const char *l4proto_str;
	u_int32_t client_port, server_port, client_local_port, server_local_port;
	const char *client_zone_name = (kzorp->czone && kzorp->czone->name) ? kzorp->czone->name : kz_log_null;
	const char *server_zone_name = (kzorp->szone && kzorp->szone->name) ? kzorp->szone->name : kz_log_null;
	const char *service_name = (kzorp->svc && kzorp->svc->name) ? kzorp->svc->name : kz_log_null;
	const struct nf_conntrack_tuple *ct_orig_tuple = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	const struct nf_conntrack_tuple *ct_reply_tuple = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;
	u_int64_t session_end;
	struct timespec now;

	if (!kz_log_session_verdict_enabled() ||
	    !kz_log_ratelimit())
		return;

	l4proto = nf_ct_protonum(ct);
	if (l4proto == IPPROTO_TCP || l4proto == IPPROTO_UDP) {
		client_port = ntohs(ct_orig_tuple->src.u.all);
		server_port = ntohs(ct_reply_tuple->src.u.all);
		client_local_port = ntohs(ct_orig_tuple->dst.u.all);
		server_local_port = ntohs(ct_reply_tuple->dst.u.all);

	} else {
		client_port = server_port = 0;
		client_local_port = server_local_port = 0;
	}

	l3proto = nf_ct_l3num(ct);
	has_server_side_connection = verdict != KZ_VERDICT_DENIED_BY_POLICY;
	if (has_server_side_connection) {
		const char *format = l3proto == NFPROTO_IPV4 ? "%pI4" : "%pI6c";
		snprintf(server_str, sizeof(server_str), format, &ct_reply_tuple->src.u3.all);
		snprintf(server_local_str, sizeof(server_local_str), format, &ct_reply_tuple->dst.u3.all);
	} else {
		server_port = 0;
		server_local_port = 0;
		snprintf(server_str, sizeof(server_str), "%s", kz_log_null);
		snprintf(server_local_str, sizeof(server_local_str), "%s", kz_log_null);
		server_zone_name = kz_log_null;
	}

	getnstimeofday(&now);
        session_end = now.tv_sec;
	verdict_str = verdict_as_string(verdict);
	l4proto_str = l4proto_as_string(nf_ct_protonum(ct), _buf);
	switch (l3proto) {
	case NFPROTO_IPV4: {
		printk(KERN_INFO "kzorp (svc/%s:%lu): Connection summary; "
				 "rule_id='%u', "
				 "session_start='%llu', session_end='%llu', "
				 "client_proto='%s', "
				 "client_address='%pI4', "
				 "client_port='%u', "
				 "client_zone='%s', "
				 "server_proto='%s', "
				 "server_address='%s', "
				 "server_port='%u', "
				 "server_zone='%s', "
				 "client_local='%pI4', "
				 "client_local_port='%u', "
				 "server_local='%s', "
				 "server_local_port='%u', "
				 "verdict='%s', "
				 "info='%s'\n",
				 service_name, kzorp->sid,
				 kzorp->rule_id,
				 kzorp->session_start, session_end,
				 l4proto_str,
				 &ct_orig_tuple->src.u3.all, client_port,
				 client_zone_name,
				 l4proto_str,
				 server_str, server_port,
				 server_zone_name,
				 &ct_orig_tuple->dst.u3.all, client_local_port,
				 server_local_str, server_local_port,
				 verdict_str,
				 info);
	}
		break;
	case NFPROTO_IPV6: {
		printk(KERN_INFO "kzorp (svc/%s:%lu): Connection summary; "
				 "rule_id='%u', "
				 "session_start='%llu', session_end='%llu', "
				 "client_proto='%s', "
				 "client_address='%pI6c', "
				 "client_port='%u', "
				 "client_zone='%s', "
				 "server_proto='%s', "
				 "server_address='%s', "
				 "server_port='%u', "
				 "server_zone='%s', "
				 "client_local='%pI6c', "
				 "client_local_port='%u', "
				 "server_local='%s', "
				 "server_local_port='%u', "
				 "verdict='%s', "
				 "info='%s'\n",
				 service_name, kzorp->sid,
				 kzorp->rule_id,
				 kzorp->session_start, session_end,
				 l4proto_str,
				 ct_orig_tuple->src.u3.all, client_port,
				 client_zone_name,
				 l4proto_str,
				 server_str, server_port,
				 server_zone_name,
				 ct_orig_tuple->dst.u3.all, client_local_port,
				 server_local_str, server_local_port,
				 verdict_str,
				 info);
	}
		break;
	default:
		BUG();
	}
}
EXPORT_SYMBOL_GPL(kz_log_session_verdict);


/***********************************************************
 * Initialization
 ***********************************************************/

int __init kzorp_core_init(void)
{
	int res = -ENOMEM;
	struct kz_instance *global;

	sysctl_kzorp_log_ratelimit_msg_cost = msecs_to_jiffies(LOG_RATELIMIT_MSG_COST);

	atomic_set(&service_id_cnt, 1);
	instance_init();

	res = static_cfg_init();
	if (res < 0)
		goto cleanup;

	res = dpt_init();
	if (res < 0)
		goto cleanup;

	res = kz_lookup_init();
	if (res < 0)
		goto cleanup_dpt;

	/* create global instance */
	LOCK_INSTANCES();
	global = kz_instance_create(KZ_INSTANCE_GLOBAL, KZ_INSTANCE_GLOBAL_STRLEN, 0);
	if (global == NULL) {
		UNLOCK_INSTANCES();
		printk(KERN_ERR "kzorp: failed to create global instance\n");
		res = -ENOMEM;
		goto cleanup_lookup;
	}
	UNLOCK_INSTANCES();

	res = kz_extension_init();
	if (res < 0) {
		pr_err_ratelimited("unable to init conntrack extension\n");
		goto cleanup_global_instance;
	}
#ifdef CONFIG_SYSCTL
	kzorp_sysctl_header = register_net_sysctl(&init_net, "net/netfilter/kzorp", kzorp_table);
	if (!kzorp_sysctl_header) {
		printk(KERN_ERR "nf_kzorp: can't register to sysctl.\n");
		res = -EINVAL;
		goto cleanup_ctx;
	}
#endif

	res = kz_sockopt_init();
	if (res < 0)
		goto cleanup_sysctl;

	res = kz_netlink_init();
	if (res < 0)
		goto cleanup_sockopt;

	return res;

cleanup_sockopt:
	kz_sockopt_cleanup();

cleanup_sysctl:
#if CONFIG_SYSCTL
	unregister_sysctl_table(kzorp_sysctl_header);
#endif

cleanup_ctx:
	kz_extension_cleanup();

cleanup_global_instance:
	kz_instance_delete(global);

cleanup_lookup:
	kz_lookup_cleanup();

cleanup_dpt:
	dpt_cleanup();

cleanup:
	static_cfg_cleanup();
	return res;
}

static void __exit kzorp_core_fini(void)
{
	struct kz_instance *global;

	kz_netlink_cleanup();

	kz_sockopt_cleanup();

#ifdef CONFIG_KZORP_PROC_FS
	remove_proc_entry("nf_kzorp", init_net.proc_net);
#endif
#ifdef CONFIG_SYSCTL
	unregister_sysctl_table(kzorp_sysctl_header);
#endif
	kz_extension_fini();

	kz_config_swap(&static_config);

	LOCK_INSTANCES();
	global = kz_instance_lookup(KZ_INSTANCE_GLOBAL);
	if (global) {
		kz_instance_delete(global);
	}
	instance_cleanup();
	UNLOCK_INSTANCES();

	kz_lookup_cleanup();

	dpt_cleanup();

	/* last things last! */
	rcu_barrier() ;
	static_cfg_cleanup();
}

MODULE_DESCRIPTION("kzorp core");
MODULE_AUTHOR("Krisztian Kovacs <hidden@balabit.com>");
MODULE_LICENSE("GPL");

module_init(kzorp_core_init);
module_exit(kzorp_core_fini);
