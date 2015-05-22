/*
 * KZorp "extension" management: the thing which has been a ct ext
 *
 * Copyright (C) 2012, Árpád Magosányi <arpad@magosanyi.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include <linux/hash.h>
#include <linux/bootmem.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include "kzorp.h"

#ifdef CONFIG_LOCKDEP
# define KZ_HASH_LOCK_NUM 8
#else
# define KZ_HASH_LOCK_NUM 1024
#endif

#ifndef KZ_USERSPACE
	#define PRIVATE static
#else
	#define	PRIVATE
#endif

PRIVATE __read_mostly unsigned int kz_hash_shift;
PRIVATE __read_mostly unsigned int kz_hash_size;

PRIVATE struct hlist_nulls_head *kz_hash;
__cacheline_aligned_in_smp spinlock_t kz_hash_locks[KZ_HASH_LOCK_NUM];
PRIVATE struct kmem_cache *kz_cachep;

static void (*nf_ct_destroy_orig)(struct nf_conntrack *) __rcu __read_mostly;

unsigned const int kz_hash_rnd = GOLDEN_RATIO_PRIME_32;

/*
 * the same as in nf_conntrack_core.c
 * do not call directly, use 
 */
static u32
hash_conntrack_raw(const struct nf_conntrack_tuple *tuple, u16 zone)
{
	unsigned int n;

	/* The direction must be ignored, so we hash everything up to the
	 * destination ports (which is a multiple of 4) and treat the last
	 * three bytes manually.
	 */
	n = (sizeof(tuple->src) + sizeof(tuple->dst.u3)) / sizeof(u32);
	return jhash2((u32 *) tuple, n, zone ^ kz_hash_rnd ^
		      (((__force __u16) tuple->dst.u.all << 16) |
		       tuple->dst.protonum));
}

static inline u32
kz_hash_get_lock_index(const u32 hash_index)
{
	return hash_index % KZ_HASH_LOCK_NUM;
}

static inline u32
kz_hash_get_hash_index_from_tuple_and_zone(const struct nf_conntrack_tuple *tuple, u16 zone)
{
	const u32 index = hash_conntrack_raw(tuple, zone) >> (32 - kz_hash_shift);
	return index;
}

static inline u32
kz_hash_get_hash_index_from_ct(const struct nf_conn *ct, enum ip_conntrack_dir dir)
{
	const u32 index = kz_hash_get_hash_index_from_tuple_and_zone(&(ct->tuplehash[dir].tuple), nf_ct_zone(ct));
	return index;
}

struct nf_conntrack_kzorp * kz_get_kzorp_from_node(struct nf_conntrack_tuple_hash *p) {
	struct nf_conntrack_kzorp *kz;
	kz = container_of((struct hlist_nulls_node *)p,
			  struct nf_conntrack_kzorp,
			  tuplehash_orig.hnnode);
	return kz;
}

static inline bool
__kz_extension_key_equal(struct nf_conntrack_tuple_hash *h,
		                            struct nf_conntrack_tuple_hash *th,
		                            unsigned int zone)
{
	struct nf_conntrack_kzorp *kz = kz_get_kzorp_from_node(h);

	return nf_ct_tuple_equal(&th->tuple, &h->tuple) && kz && kz->ct_zone == zone;
}

static struct nf_conntrack_tuple_hash *
__kz_extension_find(struct nf_conn *ct)
{
	struct hlist_nulls_node *n;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple_hash *th = &(ct->tuplehash[0]);
	unsigned int zone = nf_ct_zone(ct);

	const u32 hash_index = kz_hash_get_hash_index_from_ct(ct, IP_CT_DIR_ORIGINAL);

begin:
	hlist_nulls_for_each_entry_rcu(h, n, &kz_hash[hash_index], hnnode) {
		if (__kz_extension_key_equal(h, th, zone)) {
			return h;
		}
	}

	if (get_nulls_value(n) != hash_index) {
	  goto begin;
	}

	return NULL;
}

struct nf_conntrack_kzorp *
kz_extension_find(struct nf_conn *ct)
{
	struct nf_conntrack_kzorp *kz;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple_hash *th = &(ct->tuplehash[0]);
	unsigned int zone = nf_ct_zone(ct);

	rcu_read_lock();

begin:
	h = __kz_extension_find(ct);
	if (h) {
		if (unlikely(!__kz_extension_key_equal(h, th, zone))) {
		  goto begin;
		}
		kz = kz_get_kzorp_from_node(h);
		rcu_read_unlock();
		return kz;
	}

	rcu_read_unlock();

	return NULL;
}

static void kz_extension_dealloc(struct nf_conntrack_kzorp *kz)
{
	const u32 hash_index = kz_hash_get_hash_index_from_tuple_and_zone(&kz->tuplehash_orig.tuple, kz->ct_zone);
	const u32 lock_index = kz_hash_get_lock_index(hash_index);

	spin_lock(&kz_hash_locks[lock_index]);
	hlist_nulls_del_rcu(&(kz->tuplehash_orig.hnnode));
	spin_unlock(&kz_hash_locks[lock_index]);

	if (kz->czone != NULL)
		kz_zone_put(kz->czone);
	if (kz->szone != NULL)
		kz_zone_put(kz->szone);
	if (kz->dpt != NULL)
		kz_dispatcher_put(kz->dpt);
	if (kz->svc != NULL)
		kz_service_put(kz->svc);
	kmem_cache_free(kz_cachep, kz);
}

static void kz_extension_destroy(struct nf_conn *ct)
{
	struct nf_conntrack_kzorp *kzorp = kz_extension_find(ct);

	if (kzorp == NULL)
		return;

	if ((kzorp->svc != NULL) && (kzorp->sid != 0) &&
	    (kzorp->svc->type == KZ_SERVICE_FORWARD)) {
		if (kz_log_ratelimit()) {
			struct nf_conn_counter *acct;

			acct = nf_conn_acct_find(ct);
			if (acct)
				printk(KERN_INFO "kzorp (svc/%s:%lu): Ending forwarded session; "
				       "orig_bytes='%llu', orig_packets='%llu', "
				       "reply_bytes='%llu', reply_packets='%llu'\n",
				       kzorp->svc->name, kzorp->sid,
				       acct[IP_CT_DIR_ORIGINAL].bytes,
				       acct[IP_CT_DIR_ORIGINAL].packets,
				       acct[IP_CT_DIR_REPLY].bytes,
				       acct[IP_CT_DIR_REPLY].packets);
			kz_log_session_verdict(KZ_VERDICT_ACCEPTED, "Ending forwarded session", ct, kzorp);
		}
	}

	kz_extension_dealloc(kzorp);
}

PRIVATE void kz_extension_fill_one(struct nf_conntrack_kzorp *kzorp, struct nf_conn *ct,int direction)
{
	const u32 hash_index = kz_hash_get_hash_index_from_ct(ct, direction);
        const u32 lock_index = kz_hash_get_lock_index(hash_index);

	spin_lock(&kz_hash_locks[lock_index]);
	hlist_nulls_add_head_rcu(&(kzorp->tuplehash_orig.hnnode), &kz_hash[hash_index]);
	spin_unlock(&kz_hash_locks[lock_index]);
}

PRIVATE void kz_extension_copy_tuplehash(struct nf_conntrack_kzorp *kzorp, struct nf_conn *ct)
{
	memcpy(&(kzorp->tuplehash_orig), &(ct->tuplehash[IP_CT_DIR_ORIGINAL]), sizeof(struct nf_conntrack_tuple_hash));
}

static inline void
nf_conntrack_kzorp_init(struct nf_conntrack_kzorp *kzorp)
{
	kzorp->ct_zone = 0;
	kzorp->sid = 0;
	kzorp->generation = 0;
	kzorp->session_start = 0;

	kzorp->rule_id = 0;
	kzorp->czone = NULL;
	kzorp->szone = NULL;
	kzorp->svc = NULL;
	kzorp->dpt = NULL;
}

struct nf_conntrack_kzorp *kz_extension_create(struct nf_conn *ct)
{
	struct nf_conntrack_kzorp *kzorp;

        /*
         * Do not use kmem_cache_zalloc(), as this cache uses
         * SLAB_DESTROY_BY_RCU.
         */
	kzorp = kmem_cache_alloc(kz_cachep, GFP_ATOMIC);
	if (unlikely(!kzorp)) {
		kz_debug("allocation failed creating kzorp extension\n");
		return NULL;
	}

	nf_conntrack_kzorp_init(kzorp);
	kz_extension_copy_tuplehash(kzorp,ct);
	kz_extension_fill_one(kzorp,ct,IP_CT_DIR_ORIGINAL);
	kzorp->ct_zone = nf_ct_zone(ct);
	return kzorp;
}

static void
kz_extension_conntrack_destroy(struct nf_conntrack *nfct)
{
	struct nf_conn *ct = (struct nf_conn *) nfct;
	void (*destroy_orig)(struct nf_conntrack *);

	kz_extension_destroy(ct);

	rcu_read_lock();
	destroy_orig = rcu_dereference(nf_ct_destroy_orig);
	BUG_ON(destroy_orig == NULL);
	destroy_orig(nfct);
	rcu_read_unlock();
}

static int __net_init kz_extension_net_init(struct net *net)
{
	rcu_read_lock();
	nf_ct_destroy_orig = rcu_dereference(nf_ct_destroy);
	BUG_ON(nf_ct_destroy_orig == NULL);
	rcu_read_unlock();

	rcu_assign_pointer(nf_ct_destroy, kz_extension_conntrack_destroy);

	return 0;
}

void kz_extension_net_exit(struct net *net)
{
	void (*destroy_orig)(struct nf_conntrack *);

	rcu_read_lock();
	destroy_orig = rcu_dereference(nf_ct_destroy_orig);
	BUG_ON(destroy_orig == NULL);
	rcu_read_unlock();

	rcu_assign_pointer(nf_ct_destroy, destroy_orig);
}

static void __net_exit kz_extension_net_exit_batch(struct list_head *net_exit_list)
{
	struct net *net;

	list_for_each_entry(net, net_exit_list, exit_list)
		kz_extension_net_exit(net);
}

static struct pernet_operations kz_extension_net_ops = {
	.init           = kz_extension_net_init,
	.exit_batch     = kz_extension_net_exit_batch,
};


static void kz_extension_dealloc_by_tuplehash(struct nf_conntrack_tuple_hash *p)
{
	/*
	 * find the kzorp corresponding to the tuplehash
	 * dereference all tuplehashes
	 * free the kzorp
	 */

	struct nf_conntrack_kzorp *kz;
	kz = kz_get_kzorp_from_node(p);
	kz_extension_dealloc(kz);
}

/* deallocate entries in the hashtable */
static void clean_hash(void)
{
	int i;
	struct nf_conntrack_tuple_hash *p;

	for (i = 0; i < kz_hash_size; i++) {
		while (!hlist_nulls_empty(&kz_hash[i])) {
			p = (struct nf_conntrack_tuple_hash *) kz_hash[i].first;
			kz_extension_dealloc_by_tuplehash(p);
		}
	}
	kzfree(kz_hash);
	kmem_cache_destroy(kz_cachep);
}

int kz_extension_init(void)
{

	int ret, i;

       kz_cachep = kmem_cache_create("kzorp_slab",
                                     sizeof(struct nf_conntrack_kzorp), 0,
                                     SLAB_DESTROY_BY_RCU, NULL);

	kz_hash_size = init_net.ct.htable_size;
	kz_hash_shift = ilog2(kz_hash_size);
	kz_hash =
	    kzalloc(kz_hash_size * sizeof(struct hlist_head *),
		    GFP_KERNEL);
	if (!kz_hash) {
		return -1;
	}

	for (i = 0; i < kz_hash_size; i++) {
		INIT_HLIST_NULLS_HEAD(&kz_hash[i], i);
	}

        ret = register_pernet_subsys(&kz_extension_net_ops);
	if (ret < 0) {
		kz_err("kz_extension_init: cannot register pernet operations\n");
		goto error_cleanup_hash;
	}

	for (i = 0; i < ARRAY_SIZE(kz_hash_locks); i++)
		spin_lock_init(&kz_hash_locks[i]);

	return 0;

error_cleanup_hash:
	clean_hash();

	return -1;
}

void kz_extension_cleanup(void)
{
	clean_hash();
}

void kz_extension_fini(void)
{
	unregister_pernet_subsys(&kz_extension_net_ops);
	clean_hash();
}
