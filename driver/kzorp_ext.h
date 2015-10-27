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
	struct rcu_head rcu;
	struct nf_conntrack_tuple tuple_orig;
	u16 zone_id;
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

#define NF_CT_EXT_KZ_TYPE struct kz_extension

extern int kz_extension_init(void);
extern void kz_extension_cleanup(void);
extern void kz_extension_fini(void);
extern struct kz_extension *kz_extension_create(struct nf_conn *ct);
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

/* unreferences stuff inside
*/
extern void kz_destroy_kzorp(struct kz_extension *kzorp);

extern void
kz_extension_get_from_ct_or_lookup(const struct sk_buff *skb,
				   const struct net_device * const in,
				   u8 l3proto,
				   struct kz_extension *local_kzorp,
				   const struct kz_extension **kzorp,
				   const struct kz_config **cfg);
#endif
