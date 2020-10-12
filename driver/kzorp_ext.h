/*
 * KZorp data structures
 *
 * Copyright (C) 2015, BalaSys IT Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#ifndef _KZORP_EXTENSION_H
#define _KZORP_EXTENSION_H

struct kz_config;

struct kz_extension {
	struct hlist_nulls_node hnnode;
	const struct nf_conn *ct;
	struct nf_conntrack_tuple tuple_orig;
	u16 zone_id;
	atomic_t refcnt;
	unsigned long sid;
	/*  "lookup data" from here to end */
	unsigned int generation; /* config version */
	struct kz_zone *czone;		/* client zone */
	struct kz_zone *szone;		/* server zone */
	struct kz_dispatcher *dpt;	/* dispatcher */
	struct kz_service *svc;		/* service */
	u_int32_t rule_id;
	u_int64_t session_start;
};

extern int kz_extension_init(void);
extern void kz_extension_cleanup(void);
extern void kz_extension_fini(void);
extern struct kz_extension *kz_extension_create(void);
extern void kz_extension_destroy(struct kz_extension *kzorp);

static inline struct kz_extension *kz_extension_get(struct kz_extension *object_name)
{
	if (atomic_inc_not_zero(&object_name->refcnt) == 0)
		return NULL;

	return object_name;
}

static inline void kz_extension_put(struct kz_extension *object_name)
{
	if (atomic_dec_and_test(&object_name->refcnt))
		kz_extension_destroy(object_name);
}

/* handle kzorp extension in conntrack record
   an earlier version had the kzorp structure directly in nf_conn
   we changed that to use the extension API and add only on request
   this makes it possible to use kzorp as a dkms module.

   FIXME: check/test the below sentences
   The downside is that extensions can not be added after certain point
   (basicly, it must happen at the start of a session, not at second
    or a further packet...). 
   If the kzorp extension can't be added, we still can do zone/svc
   lookup on the fly -- only losing the cache. 
   The other thing we lose is the session id assignment.
   
   So a proper ruleset that wants to use those facilities shall make
   sure to have have the first packet meet KZORP related lookup.
   
*/
extern struct kz_extension *kz_extension_find(const struct nf_conn *ct);
extern struct kz_extension *kz_extension_add_to_cache(struct kz_extension *kzorp, const struct nf_conn *ct);
extern void kz_extension_remove_from_cache(struct kz_extension *kzorp);

extern void
kz_extension_config_validate(struct kz_extension *kzorp,
			     enum ip_conntrack_info ctinfo,
			     const struct sk_buff *skb,
			     const struct net_device * const in,
			     const u8 l3proto,
			     const struct kz_config **p_cfg);

extern struct kz_extension *
kz_extension_find_or_evaluate(const struct sk_buff *skb,
			      const struct net_device * const in,
			      u8 l3proto,
			      const struct kz_config **cfg);
#endif
