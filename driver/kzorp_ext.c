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
#include <linux/proc_fs.h>
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

struct kzorp_hash_stats {
	unsigned int searched;
	unsigned int found;
	unsigned int search_restart;
	unsigned int key_not_equal;
};

PRIVATE __read_mostly unsigned int kz_hash_shift;
PRIVATE __read_mostly unsigned int kz_hash_size;

PRIVATE struct hlist_nulls_head *kz_hash;
atomic_t *kz_hash_lengths;
struct kzorp_hash_stats __percpu *kz_hash_stats;
static __cacheline_aligned_in_smp spinlock_t kz_hash_locks[KZ_HASH_LOCK_NUM];
PRIVATE struct kmem_cache *kz_cachep;

static struct nf_ct_hook __rcu *nf_ct_hook_orig __read_mostly;

static unsigned int kz_ext_hashrnd __read_mostly;

static inline u32
kz_hash_get_lock_index(const u32 hash_index)
{
	return hash_index % KZ_HASH_LOCK_NUM;
}

static inline u32
kz_extension_get_hash_index(const struct nf_conn *ct)
{
	const u32 length = sizeof(ct) / sizeof(u32);
	const u32 *key = (const u32 *) &ct;
	const u32 hash = jhash2(key, length, kz_ext_hashrnd);
	const u32 index = hash >> (32 - kz_hash_shift);

	return index;
}

static struct kz_extension *
kz_extension_get_from_node(struct hlist_nulls_node *n)
{
	struct kz_extension *kzorp;
	kzorp = hlist_nulls_entry(n, struct kz_extension, hnnode);
	return kzorp;
}

static inline bool
__kz_extension_key_equal(const struct kz_extension *kzorp,
		         const struct nf_conn *ct)
{
	return kzorp->ct == ct;
}

static struct kz_extension *
____kz_extension_find(const struct nf_conn *ct)
{
	struct hlist_nulls_node *n;
	struct kz_extension *kzorp;

	const u32 hash_index = kz_extension_get_hash_index(ct);

begin:
	hlist_nulls_for_each_entry_rcu(kzorp, n, &kz_hash[hash_index], hnnode) {
		if (__kz_extension_key_equal(kzorp, ct)) {
			this_cpu_inc(kz_hash_stats->found);
			return kzorp;
		}
		this_cpu_inc(kz_hash_stats->searched);
	}

	if (get_nulls_value(n) != hash_index) {
		this_cpu_inc(kz_hash_stats->search_restart);
		goto begin;
	}

	return NULL;
}

static inline struct kz_extension *
__kz_extension_find(const struct nf_conn *ct)
{
	struct kz_extension *kzorp;

	rcu_read_lock();

begin:

	kzorp = ____kz_extension_find(ct);
	if (kzorp) {
		kzorp = kz_extension_get(kzorp);
		/*
		 * Geting referenece may fail as kzorp pointer may be freed
		 * by concurrent thread so find should be started again.
		 */
		if (kzorp == NULL)
			goto begin;

		/*
		 * Slab object of kzorp pointer may be freed by slab_destroy_by_rcu
		 * and can be created again concurrently so the key should be checked
		 * again. When the keys are not equal find should be started again.
		 *
		 * http://lxr.free-electrons.com/source/include/linux/slab.h#L31
		 */
		if (unlikely(!__kz_extension_key_equal(kzorp, ct))) {
			this_cpu_inc(kz_hash_stats->key_not_equal);
			kz_extension_put(kzorp);
			goto begin;
		}
	}

	rcu_read_unlock();

	return kzorp;
}

struct kz_extension *
kz_extension_find(const struct nf_conn *ct)
{
	if (ct == NULL)
		return NULL;

	return __kz_extension_find(ct);
}
EXPORT_SYMBOL_GPL(kz_extension_find);

void kz_extension_destroy(struct kz_extension *kzorp)
{
	if (kzorp->czone != NULL)
		kz_zone_put(kzorp->czone);
	if (kzorp->szone != NULL)
		kz_zone_put(kzorp->szone);
	if (kzorp->dpt != NULL)
		kz_dispatcher_put(kzorp->dpt);
	if (kzorp->svc != NULL)
		kz_service_put(kzorp->svc);

	kmem_cache_free(kz_cachep, kzorp);
}
EXPORT_SYMBOL_GPL(kz_extension_destroy);

static void kz_log_accounting(const struct kz_extension *kzorp, struct nf_conn *ct)
{
	if ((kzorp->svc != NULL) && (kzorp->sid != 0) &&
	    (kzorp->svc->type == KZ_SERVICE_FORWARD)) {
		if (kz_log_ratelimit()) {
			struct nf_conn_acct *acct;

			acct = nf_conn_acct_find(ct);
			if (acct) {
				struct nf_conn_counter *counter = acct->counter;

				printk(KERN_INFO "kzorp (svc/%s:%lu): Ending forwarded session; "
				       "orig_bytes='%lld', orig_packets='%llu', "
				       "reply_bytes='%llu', reply_packets='%llu'\n",
				       kzorp->svc->name, kzorp->sid,
				       (unsigned long long)atomic64_read(&counter[IP_CT_DIR_ORIGINAL].bytes),
				       (unsigned long long)atomic64_read(&counter[IP_CT_DIR_ORIGINAL].packets),
				       (unsigned long long)atomic64_read(&counter[IP_CT_DIR_REPLY].bytes),
				       (unsigned long long)atomic64_read(&counter[IP_CT_DIR_REPLY].packets));
			}
			kz_log_session_verdict(KZ_VERDICT_ACCEPTED, "Ending forwarded session", ct, kzorp);
		}
	}
}

static inline void
kz_extension_prepare_to_cache_addition(struct kz_extension *kzorp,
				       const struct nf_conn *ct,
				       const struct nf_conntrack_tuple *tuple,
				       u16 zone_id)
{
	kzorp->ct = ct;
	memcpy(&kzorp->tuple_orig, tuple, sizeof(struct nf_conntrack_tuple));
	kzorp->zone_id = zone_id;
}

struct kz_extension *
kz_extension_add_to_cache(struct kz_extension *kzorp, const struct nf_conn *ct)
{
	u32 hash_index;
	u32 lock_index;
	struct hlist_nulls_node *n;
	struct kz_extension *kzorp_find;
	const struct nf_conntrack_tuple *tuple = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	const u16 zone_id = nf_ct_zone_id(nf_ct_zone(ct), NF_CT_ZONE_DIR_ORIG);

	kz_extension_prepare_to_cache_addition(kzorp, ct, tuple, zone_id);

	local_bh_disable();
	hash_index = kz_extension_get_hash_index(ct);
	lock_index = kz_hash_get_lock_index(hash_index);
	spin_lock(&kz_hash_locks[lock_index]);

	hlist_nulls_for_each_entry_rcu(kzorp_find, n, &kz_hash[hash_index], hnnode) {
		if (__kz_extension_key_equal(kzorp_find, ct)) {
			pr_err("Duplicate kzorp entry found in cache;\n");
			spin_unlock(&kz_hash_locks[lock_index]);
			local_bh_enable();
			return kz_extension_get(kzorp_find);
		}
	}

	smp_wmb();
	hlist_nulls_add_head_rcu(&kzorp->hnnode, &kz_hash[hash_index]);
	atomic_inc(&kz_hash_lengths[hash_index]);
	spin_unlock(&kz_hash_locks[lock_index]);
	local_bh_enable();

	return kz_extension_get(kzorp);
}

struct kz_extension *kz_extension_create(void)
{
	struct kz_extension *kzorp;

        /*
         * Do not use kmem_cache_zalloc(), as this cache uses
         * SLAB_DESTROY_BY_RCU.
         */
	kzorp = kmem_cache_alloc(kz_cachep, GFP_ATOMIC);
	if (unlikely(!kzorp)) {
		pr_debug("allocation failed creating kzorp extension\n");
		return NULL;
	}

	kzorp->sid = 0;
	kzorp->generation = 0;
	kzorp->session_start = 0;

	kzorp->rule_id = 0;
	kzorp->czone = NULL;
	kzorp->szone = NULL;
	kzorp->svc = NULL;
	kzorp->dpt = NULL;

	atomic_set(&kzorp->refcnt, 1);

	memset(&kzorp->tuple_orig, 0, sizeof(struct nf_conntrack_tuple));
	kzorp->hnnode.pprev = NULL;
	kzorp->zone_id = 0;

	return kzorp;
}

void
kz_extension_remove_from_cache(struct kz_extension *kzorp)
{
	u32 hash_index;
	u32 lock_index;

	local_bh_disable();

	hash_index = kz_extension_get_hash_index(kzorp->ct);
	lock_index = kz_hash_get_lock_index(hash_index);

	spin_lock(&kz_hash_locks[lock_index]);
	BUG_ON(hlist_nulls_unhashed(&kzorp->hnnode));
	hlist_nulls_del_rcu(&kzorp->hnnode);
	atomic_dec(&kz_hash_lengths[hash_index]);
	spin_unlock(&kz_hash_locks[lock_index]);

	local_bh_enable();

	kz_extension_put(kzorp);
}

static void
kz_extension_conntrack_destroy(struct nf_conntrack *nfct)
{
	struct nf_conn *ct = (struct nf_conn *) nfct;
	struct nf_ct_hook *ct_hook_orig = NULL;

	struct kz_extension *kzorp = kz_extension_find(ct);
	if (likely(kzorp)) {
		kz_extension_remove_from_cache(kzorp);
		kz_log_accounting(kzorp, ct);
		kz_extension_put(kzorp);
	}

	rcu_read_lock();
	ct_hook_orig = rcu_dereference(nf_ct_hook_orig);
	BUG_ON(ct_hook_orig == NULL);
	ct_hook_orig->destroy(nfct);
	rcu_read_unlock();
}

static int kz_hash_lengths_show(struct seq_file *p, void *v)
{
	int i;

	for (i = 0; i < kz_hash_size; i++)
		seq_printf(p, "%d\n", atomic_read(&kz_hash_lengths[i]));

	return 0;
}

static int kz_hash_lengths_open(struct inode *inode, struct file *file)
{
	return single_open(file, kz_hash_lengths_show, NULL);
}

static const struct file_operations kz_hash_lengths_file_ops = {
	.owner		= THIS_MODULE,
	.open		= kz_hash_lengths_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static void *kz_hash_stats_seq_start(struct seq_file *seq, loff_t *pos)
{
	int cpu;

	if (*pos == 0)
		return SEQ_START_TOKEN;

	for (cpu = *pos - 1; cpu < nr_cpu_ids; ++cpu) {
		if (!cpu_possible(cpu))
			continue;
		*pos = cpu + 1;
		return per_cpu_ptr(kz_hash_stats, cpu);
	}

	return NULL;
}

static void *kz_hash_stats_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	int cpu;

	for (cpu = *pos; cpu < nr_cpu_ids; ++cpu) {
		if (!cpu_possible(cpu))
			continue;
		*pos = cpu + 1;
		return per_cpu_ptr(kz_hash_stats, cpu);
	}

	return NULL;
}

static void kz_hash_stats_seq_stop(struct seq_file *seq, void *v)
{
}

static int kz_hash_stats_seq_show(struct seq_file *seq, void *v)
{
	const struct kzorp_hash_stats *stats = v;

	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "searched found search_restart key_not_equal\n");
		return 0;
	}

	seq_printf(seq, "%d %d %d %d\n",
		   stats->searched,
		   stats->found,
		   stats->search_restart,
		   stats->key_not_equal
		);
	return 0;
}

static const struct seq_operations kz_hash_stats_seq_ops = {
	.start  = kz_hash_stats_seq_start,
	.next   = kz_hash_stats_seq_next,
	.stop   = kz_hash_stats_seq_stop,
	.show   = kz_hash_stats_seq_show,
};

static int kz_hash_stats_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &kz_hash_stats_seq_ops);
}

static const struct file_operations kz_hash_stats_file_ops = {
	.owner   = THIS_MODULE,
	.open    = kz_hash_stats_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

static struct nf_ct_hook kz_nf_ct_hook = {
	.destroy = kz_extension_conntrack_destroy,
};

static int __net_init kz_extension_net_init(struct net *net)
{
	if (!proc_create("kz_hash_lengths", S_IRUGO, NULL, &kz_hash_lengths_file_ops))
		return -1;

	kz_hash_stats = alloc_percpu(struct kzorp_hash_stats);
	if (!kz_hash_stats)
		goto err_proc_entry;

	if (!proc_create("kz_hash_stats", S_IRUGO, NULL, &kz_hash_stats_file_ops))
		goto err_pcpu_lists;

	rcu_read_lock();
	nf_ct_hook_orig = rcu_dereference(nf_ct_hook);
	BUG_ON(nf_ct_hook_orig == NULL);
	rcu_read_unlock();

	rcu_assign_pointer(nf_ct_hook, &kz_nf_ct_hook);

	return 0;

err_pcpu_lists:
	free_percpu(kz_hash_stats);
err_proc_entry:
	remove_proc_entry("kz_hash_lengths", NULL);

	return -1;
}

void kz_extension_net_exit(struct net *net)
{
	struct nf_ct_hook *ct_hook_orig = NULL;

	rcu_read_lock();
	ct_hook_orig = rcu_dereference(nf_ct_hook_orig);
	BUG_ON(ct_hook_orig == NULL);
	rcu_read_unlock();

	rcu_assign_pointer(nf_ct_hook, ct_hook_orig);

	remove_proc_entry("kz_hash_stats", NULL);
	remove_proc_entry("kz_hash_lengths", NULL);
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

static inline void kz_ct_dump_tuple_ip(const struct nf_conntrack_tuple *t, const u16 zone_id)
{
	pr_err_ratelimited("existing item in kzorp hash with the same tuple %p: %u %pI4:%hu -> %pI4:%hu\n",
			   t, t->dst.protonum,
			   &t->src.u3.ip, ntohs(t->src.u.all),
			   &t->dst.u3.ip, ntohs(t->dst.u.all));
}

static inline void kz_ct_dump_tuple_ipv6(const struct nf_conntrack_tuple *t, const u16 zone_id)
{
	pr_err_ratelimited("existing item in kzorp hash with the same tuple %p: %u %pI6 %hu -> %pI6 %hu\n",
			   t, t->dst.protonum,
			   t->src.u3.all, ntohs(t->src.u.all),
			   t->dst.u3.all, ntohs(t->dst.u.all));
}

static inline void kz_ct_dump_tuple(const struct nf_conntrack_tuple *t, const u16 zone_id)
{
	switch (t->src.l3num) {
	case AF_INET:
		kz_ct_dump_tuple_ip(t, zone_id);
		break;
	case AF_INET6:
		kz_ct_dump_tuple_ipv6(t, zone_id);
		break;
	}
}

/* deallocate entries in the hashtable */
static void clean_hash(void)
{
	int i;

	for (i = 0; i < kz_hash_size; i++) {
		while (!hlist_nulls_empty(&kz_hash[i])) {
			struct kz_extension *kzorp = kz_extension_get_from_node(kz_hash[i].first);
			kz_extension_remove_from_cache(kzorp);
			kz_ct_dump_tuple(&kzorp->tuple_orig, kzorp->zone_id);
			kz_extension_put(kzorp);
		}
	}
	kzfree(kz_hash);
	kmem_cache_destroy(kz_cachep);
}

int kz_extension_init(void)
{
	int ret, i;

	kz_cachep = kmem_cache_create("kzorp_slab",
				      sizeof(struct kz_extension), 0,
				      SLAB_TYPESAFE_BY_RCU, NULL);

	get_random_once(&kz_ext_hashrnd, sizeof(kz_ext_hashrnd));
	kz_hash_size = nf_conntrack_htable_size;
	kz_hash_shift = ilog2(kz_hash_size);
	kz_hash =
	    kzalloc(kz_hash_size * sizeof(struct hlist_nulls_head), GFP_KERNEL);
	if (!kz_hash) {
		return -1;
	}

	kz_hash_lengths = kzalloc(kz_hash_size * sizeof(atomic64_t), GFP_KERNEL);
	if (!kz_hash_lengths)
		goto error_free_hash_length;

	for (i = 0; i < kz_hash_size; i++) {
		INIT_HLIST_NULLS_HEAD(&kz_hash[i], i);
		atomic_set(&kz_hash_lengths[i], 0);
	}

	ret = register_pernet_subsys(&kz_extension_net_ops);
	if (ret < 0) {
		pr_err_ratelimited("kz_extension_init: cannot register pernet operations\n");
		goto error_cleanup_hash;
	}

	for (i = 0; i < ARRAY_SIZE(kz_hash_locks); i++)
		spin_lock_init(&kz_hash_locks[i]);

	return 0;

error_cleanup_hash:
	clean_hash();
error_free_hash_length:
	kfree(kz_hash_lengths);

	return -1;
}

void kz_extension_cleanup(void)
{
	clean_hash();
}

void kz_extension_fini(void)
{
	unregister_pernet_subsys(&kz_extension_net_ops);
	free_percpu(kz_hash_stats);
	kfree(kz_hash_lengths);
	clean_hash();
}
