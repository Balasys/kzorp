/*
 * Dynamic expectation support for Linux/iptables
 *
 * Copyright (c) 2005-2015 BalaBit IT Security, 2015-2017 BalaSys IT Security.
 * Author: Krisztian Kovacs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>
#include <net/ip.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_nat.h>
#include "dynexpect.h"
#include "kzorp_compat.h"

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) "dynexpect:%s:%d: " fmt, __func__, __LINE__
#endif

#define CONFIG_NF_DYNEXPECT_MAX_RANGE_SIZE 8

typedef enum {
	MAPPING_EMPTY = 0,
	MAPPING_ALLOCATED,
	MAPPING_HASHED,
	MAPPING_EXPECTED,
	MAPPING_ACTIVE,
	MAPPING_UNHASHED,
	MAPPING_DESTROYED
} dynexpect_mapping_state_t;

enum {
	MAPPING_FLAG_NAT = 1,
};

struct dynexpect_mapping {
	/* list nodes in the hash tables */
	struct hlist_node entry_id, entry_addr;

	/* flags */
	unsigned int flags;

	/* mapping id */
	u32 id;

	/* mapping address: host byte order */
	u32 orig_ip, new_ip;
	u16 orig_port, new_port;

	/* range size */
	unsigned int n_ports;

	/* peer address: host byte order */
	u32 peer_ip;
	u16 peer_port;

	/* protocol */
	u8 proto;

	/* conntrack information */
	u32 ct_mark, ct_mark_mask;

	/* state */
	dynexpect_mapping_state_t state;

	/* timeout */
	struct timer_list timeout;

	/* reference count */
	atomic_t references;

	/* master conntrack */
	struct nf_conn *master_ct;
};

/* module parameters */
static unsigned int mapping_timeout __read_mostly = 300;
static unsigned int hashsize __read_mostly = 512;

/* static state variables initialized at startup */
static u_int32_t hash_rnd_initval __read_mostly = 0;
static u_int32_t dynexpect_mapping_id = 1;

static struct kmem_cache *dynexpect_mapping_cache __read_mostly;

static struct hlist_head *dynexpect_htable_by_id = NULL;
static struct hlist_head *dynexpect_htable_by_addr = NULL;

static spinlock_t dynexpect_lock = __SPIN_LOCK_UNLOCKED(dynexpect_lock);
static spinlock_t dynexpect_rover_lock = __SPIN_LOCK_UNLOCKED(dynexpect_rover_lock);

/****************************************************************/
/* Mapping creation/destruction					*/
/****************************************************************/

static void dynexpect_timeout(kz_timer_arg tl);

static struct nf_conn *get_master_ct_from_tuple(struct net *net,
			const u32 client_master_ip, const u16 client_master_port,
			const u32 server_master_ip, const u16 server_master_port,
			const u8 master_l4proto)
{
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *master_ct = NULL;

	memset(&tuple, 0, sizeof(tuple));
	tuple.src.l3num = AF_INET;
	tuple.src.u3.ip = htonl(client_master_ip);
	tuple.src.u.udp.port = htons(client_master_port);
	tuple.dst.u3.ip = htonl(server_master_ip);
	tuple.dst.protonum = master_l4proto;
	tuple.dst.u.udp.port = htons(server_master_port);

	h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
	if (!h) {
			pr_debug("Cannot find MASTER ct tuple hash;");
			return NULL;
	}
	master_ct = nf_ct_tuplehash_to_ctrack(h);

	if (!master_ct) {
			pr_debug("Cannot find MASTER ct;");
			return NULL;
	}

	pr_debug("MASTER ct found;");

	/* get ref for master ct */
	nf_conntrack_get(&master_ct->ct_general);

	return master_ct;
}

static struct dynexpect_mapping *
dynexpect_mapping_new(void)
{
	struct dynexpect_mapping *m;

	pr_debug("creating mapping\n");

	m = kmem_cache_alloc(dynexpect_mapping_cache, GFP_ATOMIC);
	if (m == NULL) {
		pr_debug("memory allocation failure\n");
		return NULL;
	}

	memset(m, 0, sizeof(*m));
	INIT_HLIST_NODE(&m->entry_id);
	INIT_HLIST_NODE(&m->entry_addr);
	atomic_set(&m->references, 1);

	kz_timer_setup(m->timeout, m, dynexpect_timeout);

	m->state = MAPPING_EMPTY;

	return m;
}

static inline void
dynexpect_mapping_ref(struct dynexpect_mapping *m)
{
	atomic_inc(&m->references);
}

static inline void
dynexpect_mapping_unref(struct dynexpect_mapping *m)
{
	if (atomic_dec_and_test(&m->references))
		kmem_cache_free(dynexpect_mapping_cache, m);
}

/****************************************************************/
/* Hash tables							*/
/****************************************************************/

static inline unsigned int
dynexpect_hashfn_id(u_int32_t id)
{
	return jhash_1word(id, hash_rnd_initval) % hashsize;
}

static inline unsigned int
dynexpect_hashfn_addr(u_int8_t proto, u_int32_t addr, u_int16_t port)
{
	return jhash_2words(addr, port + (proto << 16),
			    hash_rnd_initval) % hashsize;
}

static void
dynexpect_hash_id(struct dynexpect_mapping *m)
{
	unsigned int bucket = dynexpect_hashfn_id(m->id);

	dynexpect_mapping_ref(m);
	hlist_add_head(&m->entry_id, &dynexpect_htable_by_id[bucket]);
}

static void
dynexpect_unhash_id(struct dynexpect_mapping *m)
{
	hlist_del(&m->entry_id);
	dynexpect_mapping_unref(m);
}

static struct dynexpect_mapping *
dynexpect_lookup_id(u_int32_t id)
{
	unsigned int bucket = dynexpect_hashfn_id(id);
	struct dynexpect_mapping *m;

	hlist_for_each_entry(m, &dynexpect_htable_by_id[bucket], entry_id) {
		if (m->id == id) {
			dynexpect_mapping_ref(m);
			return m;
		}
	}

	return NULL;
}

static void
dynexpect_hash_addr(struct dynexpect_mapping *m)
{
	unsigned int bucket = dynexpect_hashfn_addr(m->proto, m->orig_ip, m->orig_port);

	dynexpect_mapping_ref(m);
	hlist_add_head(&m->entry_addr, &dynexpect_htable_by_addr[bucket]);
}

static void
dynexpect_unhash_addr(struct dynexpect_mapping *m)
{
	hlist_del(&m->entry_addr);
	dynexpect_mapping_unref(m);
}

static struct dynexpect_mapping *
dynexpect_lookup_addr(u_int8_t proto, u_int32_t addr, u_int16_t port)
{
	unsigned int bucket = dynexpect_hashfn_addr(proto, addr, port);
	struct dynexpect_mapping *m;

	hlist_for_each_entry(m, &dynexpect_htable_by_addr[bucket], entry_addr) {
		if (m->proto == proto &&
		    m->orig_ip == addr &&
		    m->orig_port == port) {
			dynexpect_mapping_ref(m);
			return m;
		}
	}

	return NULL;
}

/****************************************************************/
/* Mapping iteration						*/
/****************************************************************/

static int
dynexpect_iterate_mappings(int (*check)(const struct dynexpect_mapping *, void *), void *user_data)
{
	unsigned int bucket;
	struct dynexpect_mapping *m;
	int found = 0;

	for (bucket = 0; bucket < hashsize; bucket++)
		hlist_for_each_entry(m, &dynexpect_htable_by_id[bucket], entry_id) {
			if ((found = check(m, user_data)) != 0)
				break;
		}

	return found;
}

/****************************************************************/
/* Helper for removing registered expectations			*/
/****************************************************************/

void
dynexpect_remove_expectation(const struct nf_conntrack_tuple *tuple, const struct dynexpect_mapping *m)
{
	struct nf_conn_help *help;
	struct nf_conntrack_expect *exp;
	struct hlist_node *next;

	help = nfct_help(m->master_ct);

	/* check if we have extensions at all */
	if (unlikely(help == NULL)) {
		pr_debug("no helper data present\n");
		return;
	}

	pr_debug("removing expectations for tuple:\n");
	nf_ct_dump_tuple(tuple);

	hlist_for_each_entry_safe(exp, next, &help->expectations, lnode) {
		pr_debug("comparing with expectation\n");
		nf_ct_dump_tuple(&exp->tuple);

		if (!(exp->flags & NF_CT_EXPECT_INACTIVE) &&
		    nf_ct_tuple_mask_cmp(tuple, &exp->tuple, &exp->mask)) {
			pr_debug("removing expectation; exp='%p'\n", exp);
			nf_ct_unexpect_related(exp);
		}
	}
}

/****************************************************************/
/* Mapping management						*/
/****************************************************************/

static int
dynexpect_check_port_clash(const struct dynexpect_mapping *m, void *u)
{
	const struct nf_ct_dynexpect_map *req = (const struct nf_ct_dynexpect_map *)u;

	if (m->state < MAPPING_ALLOCATED)
		return 0;

	if (m->new_ip == req->new_ip) {
		if (m->new_port == req->new_port)
			return 1;

		if (m->new_port < req->new_port) {
			if (m->new_port + m->n_ports >= req->new_port)
				return 1;
		} else {
			if (req->new_port + req->n_ports >= m->new_port)
				return 1;
		}
	}

	return 0;
}

static int
dynexpect_mapping_alloc(struct dynexpect_mapping *m,
			struct nf_ct_dynexpect_map *req, struct net *net)
{
	struct dynexpect_mapping *n;
	int rover, min, max, left;
	static int dynexpect_alloc_port_rover = 1;
	int succeeded = 0;

	pr_debug("mapping; id='%u', proto='%hhu', nports='%u', orig='%pI4h:%hu', new='%pI4h', client_master='%pI4h:%hu', server_master='%pI4h:%hu', master_l4proto='%hhu'\n",
		  m->id, req->proto, req->n_ports, &req->orig_ip, req->orig_port, &req->new_ip,
		  &req->client_master_ip, req->client_master_port, &req->server_master_ip, req->server_master_port,
		  req->master_l4proto);

	/* About locking: _alloc() is called with an unhashed, empty mapping with only
	 * the calling function holding a reference to it. Thus it's not necessary to
	 * hold the dynexpect_lock when checking member data. However, the
	 * dynexpect_alloc_port_rover counter and the dynexpect_mapping_id counter
	 * must be guarded against modification, we use the dynexpect_rover_lock
	 * spinlock for this. */

	/* make sure the request has no ID specified, the mapping
	 * structure is empty, and the request arguments are there */
	if ((m->state != MAPPING_EMPTY) ||
	    (req->proto == 0) || (req->n_ports == 0) || (req->n_ports > CONFIG_NF_DYNEXPECT_MAX_RANGE_SIZE) ||
	    (req->orig_ip == 0) || (req->orig_port == 0) || (req->new_ip == 0) || (req->client_master_ip == 0) ||
	    (req->client_master_port == 0) || (req->server_master_ip == 0) || (req->server_master_port == 0) ||
	    (req->master_l4proto == 0))
		return -EINVAL;

	/* look up if such mapping already exists */
	n = dynexpect_lookup_addr(req->proto, req->orig_ip, req->orig_port);
	if (n != NULL) {
		dynexpect_mapping_unref(n);
		return -EEXIST;
	}

	/* if orig_ip == new_ip then we don't have to NAT */
	if (req->new_ip == req->orig_ip) {
		/* no NAT, simply use the original IP and port */
		rover = req->orig_port;
	} else {
		spin_lock(&dynexpect_rover_lock);

		/* allocate port to NAT to */
		m->flags |= MAPPING_FLAG_NAT;

		/* get first port to try */
		inet_get_local_port_range(net, &min, &max);
		left = (max - min) + 1;
		rover = dynexpect_alloc_port_rover;

		spin_lock_bh(&dynexpect_lock);

		do {
			rover++;
			if ((rover < min) || (rover > max - req->n_ports - 1))
				rover = min;

			/* try to allocate ports */
			req->new_port = rover;

			if (!dynexpect_iterate_mappings(&dynexpect_check_port_clash, req)) {
				/* if succeeded (no clashing mapping found), break */
				dynexpect_alloc_port_rover = rover + req->n_ports - 1;
				succeeded = 1;
				break;
			}
		} while (--left > 0);

		spin_unlock_bh(&dynexpect_lock);

		spin_unlock(&dynexpect_rover_lock);

		if (!succeeded)
			return -EEXIST;
	}

	/* store results in mapping structure */
	m->state = MAPPING_ALLOCATED;
	m->orig_ip = req->orig_ip;
	m->orig_port = req->orig_port;
	m->new_ip = req->new_ip;
	m->new_port = rover;
	m->proto = req->proto;
	m->n_ports = req->n_ports;
	m->master_ct = get_master_ct_from_tuple(net, req->client_master_ip, req->client_master_port, req->server_master_ip, req->server_master_port, req->master_l4proto);
	if (m->master_ct == NULL) {
		return -EINVAL;
	}

	/* assign next id */
	spin_lock(&dynexpect_rover_lock);
	m->id = dynexpect_mapping_id++;
	spin_unlock(&dynexpect_rover_lock);

	return 0;
}

static int
dynexpect_mapping_hash(struct dynexpect_mapping *m)
{
	int res = -EINVAL;

	pr_debug("mapping; id='%u'\n", m->id);

	spin_lock_bh(&dynexpect_lock);

	if (m->state != MAPPING_ALLOCATED)
		goto exit;

	dynexpect_hash_id(m);
	dynexpect_hash_addr(m);

	/* start timer */
	m->timeout.expires = jiffies + mapping_timeout * HZ;
	add_timer(&m->timeout);

	m->state = MAPPING_HASHED;
	res = 0;

 exit:
	spin_unlock_bh(&dynexpect_lock);

	return res;
}

static int
dynexpect_mapping_refresh(struct dynexpect_mapping *m)
{
	int res = -ENOENT;

	pr_debug("mapping; id='%u'\n", m->id);

	spin_lock_bh(&dynexpect_lock);

	if (m->state < MAPPING_HASHED ||
	    m->state > MAPPING_ACTIVE) {
		pr_debug("invalid state, cannot be refreshed\n");
		res = -EINVAL;
		goto exit;
	}

	/* refresh timer */
	if (del_timer(&m->timeout)) {
		m->timeout.expires = jiffies + mapping_timeout * HZ;
		add_timer(&m->timeout);
		res = 0;
	}

 exit:
	spin_unlock_bh(&dynexpect_lock);

	return res;
}

void dynexpect_nat_expected(struct nf_conn *ct, struct nf_conntrack_expect *exp);

static int
dynexpect_mapping_expect(struct dynexpect_mapping *m,
			 struct nf_ct_dynexpect_expect *req)
{
	int i;
	u_int16_t sport, dport;
	int success = 1;
	int res = -EINVAL;

	pr_debug("called; id='%u', peer_ip='%pI4h', peer_port='%hu'\n",
		  m->id, &req->peer_ip, req->peer_port);

	spin_lock_bh(&dynexpect_lock);

	if (m->state != MAPPING_HASHED) {
		pr_debug("mapping in invalid state; state='%d'\n", m->state);
		goto exit;
	}

	if ((req->mapping_id == 0) || (req->peer_ip == 0) ||
	    (req->peer_port == 0)) {
		pr_debug("invalid arguments\n");
		goto exit;
	}

	sport = m->orig_port;
	dport = req->peer_port;

	for (i = 0; i < m->n_ports; i++) {
		struct nf_conntrack_expect *exp;
		union nf_inet_addr saddr, daddr;
		__be16 nsport, ndport;
		int ret;

		exp = nf_ct_expect_alloc(m->master_ct);
		if (exp == NULL) {
			pr_debug("failed to create expectation\n");
			success = 0;
			break;
		}

		/* set expectation properties */
		saddr.ip = htonl(m->orig_ip);
		daddr.ip = htonl(req->peer_ip);
		nsport = htons(sport + i);
		ndport = htons(dport + i);

		pr_debug("expecting connection; src='%pI4:%hu', dst='%pI4:%hu'\n",
			  &saddr.ip, sport + i, &daddr.ip, dport + i);

		nf_ct_expect_init(exp, NF_CT_EXPECT_CLASS_DEFAULT,
				  AF_INET,
				  &saddr, &daddr, m->proto,
				  &nsport, &ndport);

		/* set expected callback */
		exp->expectfn = dynexpect_nat_expected;

		ret = nf_ct_expect_related(exp);
		if (ret != 0) {
			pr_debug("expect_related() failed: %d\n", ret);
			nf_ct_expect_put(exp);
			success = 0;
			break;
		}

		nf_ct_expect_put(exp);
	}

	if (!success) {
		struct nf_conntrack_tuple tuple;

		/* fill "static" fields */
		memset(&tuple, 0, sizeof(tuple));
		tuple.src.l3num = AF_INET;
		tuple.src.u3.ip = htonl(m->orig_ip);
		tuple.dst.u3.ip = htonl(req->peer_ip);
		tuple.dst.protonum = m->proto;

		pr_debug("cleaning up expectations\n");

		/* clean up registered expectations */
		for (i--, sport--, dport--; i >= 0; i--) {
			/* fill port numbers */
			tuple.src.u.udp.port = htons(sport + i);
			tuple.dst.u.udp.port = htons(dport + i);

			dynexpect_remove_expectation(&tuple, m);
		}

		res = -EEXIST;
		goto exit;
	}

	pr_debug("expectations created\n");

	m->peer_ip = req->peer_ip;
	m->peer_port = req->peer_port;
	m->state = MAPPING_EXPECTED;

	res = 0;

 exit:
	spin_unlock_bh(&dynexpect_lock);

	return res;
}

static int
dynexpect_mapping_unhash(struct dynexpect_mapping *m)
{
	int res = -EINVAL;

	pr_debug("mapping; id='%u'\n", m->id);

	spin_lock_bh(&dynexpect_lock);

	if (m->state < MAPPING_HASHED)
		goto exit;

	if (del_timer(&m->timeout)) {
		dynexpect_unhash_id(m);
		dynexpect_unhash_addr(m);
                res = 0;
	} else
		res = -ENOENT;

 exit:
	spin_unlock_bh(&dynexpect_lock);

	return res;
}

static int
dynexpect_mapping_destroy(struct dynexpect_mapping *m)
{
	int i;
	int res = -EINVAL;

	pr_debug("mapping; id='%u'\n", m->id);

	spin_lock_bh(&dynexpect_lock);

	if ((m->state < MAPPING_ALLOCATED) || (m->state > MAPPING_ACTIVE))
		goto exit;

	/* delete conntracks */
	if (m->state == MAPPING_ACTIVE &&
	    m->peer_ip != 0) {
		struct nf_conntrack_tuple tuple;
		struct nf_conntrack_tuple_hash *h;
		int i;

		/* count number of active connections belonging to this mapping */
		memset(&tuple, 0, sizeof(tuple));
		tuple.src.l3num = AF_INET;
		tuple.src.u3.ip = htonl(m->orig_ip);
		tuple.dst.u3.ip = htonl(m->peer_ip);
		tuple.dst.protonum = m->proto;

		for (i = 0; i < m->n_ports; i++) {
			tuple.src.u.udp.port = htons(m->orig_port + i);
			tuple.dst.u.udp.port = htons(m->peer_port + i);

			h = nf_conntrack_find_get(nf_ct_net(m->master_ct),
						  &nf_ct_zone_dflt,
						  &tuple);

			if (h != NULL) {
				struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);

				nf_ct_kill(ct);
				nf_ct_put(ct);
			}
		}
	}

	/* delete expectations */
	if (m->state >= MAPPING_EXPECTED) {
		struct nf_conntrack_tuple tuple;

		pr_debug("removing expectations\n");

		/* fill "static" fields */
		memset(&tuple, 0, sizeof(tuple));
		tuple.src.l3num = AF_INET;
		tuple.src.u3.ip = htonl(m->orig_ip);
		tuple.dst.u3.ip = htonl(m->peer_ip);
		tuple.dst.protonum = m->proto;

		for (i = 0; i < m->n_ports; i++) {
			tuple.src.u.udp.port = htons(m->orig_port + i);
			tuple.dst.u.udp.port = htons(m->peer_port + i);

			dynexpect_remove_expectation(&tuple, m);
		}
	}

	/* remove ref from master ct */
	nf_ct_put(m->master_ct);

	m->state = MAPPING_DESTROYED;
	res = 0;

 exit:
	spin_unlock_bh(&dynexpect_lock);

	return res;
}

/****************************************************************/
/* Mapping timeout						*/
/****************************************************************/

static void
dynexpect_timeout(kz_timer_arg tl)
{
	struct dynexpect_mapping *m = kz_from_timer(m, tl, timeout);

	pr_debug("mapping; id='%u'\n", m->id);

	dynexpect_mapping_ref(m);

	spin_lock_bh(&dynexpect_lock);

	/* unhash if necessary */
	if (m->state > MAPPING_EMPTY && m->state < MAPPING_DESTROYED) {
		dynexpect_unhash_id(m);
		dynexpect_unhash_addr(m);
	}

	spin_unlock_bh(&dynexpect_lock);

	/* free reservations and delete expectations */
	dynexpect_mapping_destroy(m);

	dynexpect_mapping_unref(m);
}

/****************************************************************/
/* Sockopt interface						*/
/****************************************************************/

static int
dynexpect_setsockopt_map(void *user, int len, struct net *net)
{
	struct nf_ct_dynexpect_map arg;
	struct dynexpect_mapping *m;
	int res;

	if (len != sizeof(struct nf_ct_dynexpect_map)) {
		pr_err("invalid user data length; len='%d', expected='%zu'\n", len, sizeof(struct nf_ct_dynexpect_map));
		return -EINVAL;
	}

	if (copy_from_user(&arg, user, len)) {
		pr_debug("failed to copy request from user-space\n");
		return -EFAULT;
	}

	/* check args */
	if ((arg.proto == 0) || (arg.orig_ip == 0) || (arg.orig_port == 0)) {
		pr_debug("invalid request fields\n");
		return -EINVAL;
	}

	/* check if such a mapping exists */
	spin_lock_bh(&dynexpect_lock);
	m = dynexpect_lookup_addr(arg.proto, arg.orig_ip, arg.orig_port);
	spin_unlock_bh(&dynexpect_lock);

	if (m != NULL) {
		dynexpect_mapping_unref(m);
		pr_debug("mapping clash\n");
		return -EEXIST;
	}

	/* allocate structure */
	m = dynexpect_mapping_new();
	if (m == NULL)
		return -ENOMEM;

	/* allocate mapping */
	res = dynexpect_mapping_alloc(m, &arg, net);
	if (res != 0) {
		dynexpect_mapping_unref(m);
		return res;
	}

	/* insert into hashes */
	res = dynexpect_mapping_hash(m);
	if (res != 0) {
		dynexpect_mapping_destroy(m);
		dynexpect_mapping_unref(m);
		return res;
	}

	/* copy id back to userspace */
	arg.mapping_id = m->id;
	arg.new_port = m->new_port;
	if (copy_to_user(user, &arg, len)) {
		pr_err_ratelimited("failed to copy request to user-space\n");
		dynexpect_mapping_unhash(m);
		dynexpect_mapping_destroy(m);
		dynexpect_mapping_unref(m);
		return -EFAULT;
	}

	dynexpect_mapping_unref(m);

	return 0;
}

static int
dynexpect_setsockopt_expect(void *user, int len)
{
	struct dynexpect_mapping *m;
	struct nf_ct_dynexpect_expect arg;
	int res;

	if (len != sizeof(struct nf_ct_dynexpect_expect)) {
		pr_err("invalid user data length; len='%d', expected='%zu'\n", len, sizeof(struct nf_ct_dynexpect_expect));
		return -EINVAL;
	}

	if (copy_from_user(&arg, user, len)) {
		pr_err_ratelimited("failed to copy request from user-space\n");
		return -EFAULT;
	}

	spin_lock_bh(&dynexpect_lock);
	m = dynexpect_lookup_id(arg.mapping_id);
	spin_unlock_bh(&dynexpect_lock);

	if (m == NULL) {
		pr_debug("no mapping found; id='%u'\n", arg.mapping_id);
		return -ENOENT;
	}

	res = dynexpect_mapping_expect(m, &arg);

	dynexpect_mapping_unref(m);

	return res;
}

static int
dynexpect_setsockopt_destroy(void *user, int len)
{
	struct nf_ct_dynexpect_destroy arg;
	struct dynexpect_mapping *m;
	int res = 0;

	if (len != sizeof(struct nf_ct_dynexpect_destroy))
		return -EINVAL;

	if (copy_from_user(&arg, user, len)) {
		pr_err_ratelimited("failed to copy request from user-space\n");
		return -EFAULT;
	}

	/* check args */
	if (arg.mapping_id == 0)
		return -EINVAL;

	/* look up mapping */
	spin_lock_bh(&dynexpect_lock);
	m = dynexpect_lookup_id(arg.mapping_id);
	spin_unlock_bh(&dynexpect_lock);

	if (m == NULL)
		return -ENOENT;

	if (dynexpect_mapping_unhash(m) != 0) {
		res = -EINVAL;
		goto out;
	}

	if (dynexpect_mapping_destroy(m) != 0) {
		res = -EINVAL;
	}

out:
	dynexpect_mapping_unref(m);

	return 0;
}

static int
dynexpect_setsockopt_mark(void *user, int len)
{
	struct nf_ct_dynexpect_mark arg;
	struct dynexpect_mapping *m;

	if (len != sizeof(struct nf_ct_dynexpect_mark))
		return -EINVAL;

	if (copy_from_user(&arg, user, len)) {
		pr_err_ratelimited("failed to copy request from user-space\n");
		return -EFAULT;
	}

	/* check args */
	if (arg.mapping_id == 0)
		return -EINVAL;

	/* look up mapping */
	spin_lock_bh(&dynexpect_lock);
	m = dynexpect_lookup_id(arg.mapping_id);
	spin_unlock_bh(&dynexpect_lock);

	if (m == NULL)
		return -ENOENT;

	m->ct_mark = arg.mark;

	dynexpect_mapping_unref(m);

	return 0;
}

static int
dynexpect_getsockopt_map(void *user, int *len)
{
	struct nf_ct_dynexpect_map arg;
	struct dynexpect_mapping *m;
	unsigned int n_active;

	if (*len != sizeof(struct nf_ct_dynexpect_map))
		return -EINVAL;

	if (copy_from_user(&arg, user, sizeof(arg))) {
		pr_err_ratelimited("failed to copy request from user-space\n");
		return -EFAULT;
	}

	/* check args */
	if (arg.mapping_id == 0)
		return -EINVAL;

	/* look up mapping */
	spin_lock_bh(&dynexpect_lock);
	m = dynexpect_lookup_id(arg.mapping_id);

	if (m == NULL) {
		spin_unlock_bh(&dynexpect_lock);
		return -ENOENT;
	}

	n_active = 0;
	if ((m->state == MAPPING_ACTIVE) && (m->peer_ip != 0)) {
		struct nf_conntrack_tuple tuple;
		struct nf_conntrack_tuple_hash *h;
		int i;

		/* count number of active connections belonging to this mapping */
		memset(&tuple, 0, sizeof(tuple));
		tuple.src.l3num = AF_INET;
		tuple.src.u3.ip = htonl(m->orig_ip);
		tuple.dst.u3.ip = htonl(m->peer_ip);
		tuple.dst.protonum = m->proto;

		for (i = 0; i < m->n_ports; i++) {
			tuple.src.u.udp.port = htons(m->orig_port + i);
			tuple.dst.u.udp.port = htons(m->peer_port + i);

			pr_debug("checking if conntrack exists for tuple:\n");
			nf_ct_dump_tuple(&tuple);

			h = nf_conntrack_find_get(nf_ct_net(m->master_ct),
						  &nf_ct_zone_dflt,
						  &tuple);

			if (h != NULL) {
				pr_debug("found; ct='%p'\n", nf_ct_tuplehash_to_ctrack(h));
				n_active++;
				nf_ct_put(nf_ct_tuplehash_to_ctrack(h));
			}
		}
	}

        arg.orig_ip = m->orig_ip;
        arg.orig_port = m->orig_port;
        arg.new_ip = m->new_ip;
        arg.new_port = m->new_port;
        arg.proto = m->proto;
        arg.n_ports = m->n_ports;
	arg.n_active = n_active;

	spin_unlock_bh(&dynexpect_lock);

        /* Refresh timeout of the mapping: Zorp periodically calls
         * getsockopt_mapping() to check whether we still have active
         * channels for the RTP streams or only the BYE was lost somehow.
         * We use this polling mechanism to ensure that active mappings don't
         * timeout too early.
         */
	dynexpect_mapping_refresh(m);

        dynexpect_mapping_unref(m);

	if (copy_to_user(user, &arg, sizeof(arg))) {
		pr_err_ratelimited("failed to copy request to user-space\n");
		return -EFAULT;
	}
        *len = sizeof(arg);

	return 0;
}

static int
dynexpect_setsockopt(struct sock *sk, int optval, void *user, unsigned int len)
{
	struct net *net = NULL;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	net = sock_net(sk);

	switch (optval) {
	case SO_DYNEXPECT_MAP:
		return dynexpect_setsockopt_map(user, len, net);
		break;
	case SO_DYNEXPECT_EXPECT:
		return dynexpect_setsockopt_expect(user, len);
		break;
	case SO_DYNEXPECT_DESTROY:
		return dynexpect_setsockopt_destroy(user, len);
		break;
	case SO_DYNEXPECT_MARK:
		return dynexpect_setsockopt_mark(user, len);
		break;
	default:
		return -ENOPROTOOPT;
	}
}

static int
dynexpect_getsockopt(struct sock *sk, int optval, void *user, int *len)
{
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	switch (optval) {
	case SO_DYNEXPECT_MAP:
		return dynexpect_getsockopt_map(user, len);
		break;
	default:
		return -ENOPROTOOPT;
	}
}

static struct nf_sockopt_ops dynexpect_sockopt = {
	.pf		= PF_INET,
	.get_optmin	= SO_DYNEXPECT_MAP,
	.get_optmax	= SO_DYNEXPECT_MARK + 1,
	.get		= &dynexpect_getsockopt,
	.set_optmin	= SO_DYNEXPECT_MAP,
	.set_optmax	= SO_DYNEXPECT_MARK + 1,
	.set		= &dynexpect_setsockopt,
	.owner		= THIS_MODULE,
};

/****************************************************************/
/* Conntrack/NAT helpers					*/
/****************************************************************/

static inline void dynexpect_dump_tuple(const struct nf_conntrack_tuple *t)
{
	pr_debug("tuple %p: %u %pI4:%hu -> %pI4:%hu\n",
	  t, t->dst.protonum,
	  &t->src.u3.ip, ntohs(t->src.u.all),
	  &t->dst.u3.ip, ntohs(t->dst.u.all));
}

u32
dynexpect_find_id_for_tuple(struct nf_conntrack_expect *exp)
{
	unsigned int bucket;
	struct dynexpect_mapping *m;
	struct nf_conntrack_tuple mtuple;
	int i;

	memset(&mtuple, 0, sizeof(mtuple));

	pr_debug("searching for m->id for this tuple:");
	dynexpect_dump_tuple(&exp->tuple);
	for (bucket = 0; bucket < hashsize; bucket++) {
		hlist_for_each_entry(m, &dynexpect_htable_by_id[bucket], entry_id) {
			if (m->state >= MAPPING_EXPECTED) {
				for (i = 0; i < m->n_ports; i++) {
					mtuple.src.l3num = AF_INET;
					mtuple.src.u3.ip = htonl(m->orig_ip);
					mtuple.dst.u3.ip = htonl(m->peer_ip);
					mtuple.dst.protonum = m->proto;
					mtuple.src.u.udp.port = htons(m->orig_port + i);
					mtuple.dst.u.udp.port = htons(m->peer_port + i);
					pr_debug("  m->state=%d, comparing with this tuple:", m->state);
					dynexpect_dump_tuple(&mtuple);
					if (nf_ct_tuple_mask_cmp(&mtuple, &exp->tuple, &exp->mask)) {
						pr_debug("  m->id found; id=%d", m->id);
						return m->id;
					}
				}
			}
		}
	}

	pr_debug("  m->id not found;");
	return 0;
}

void
dynexpect_nat_expected(struct nf_conn *ct,
		       struct nf_conntrack_expect *exp)
{
	struct nf_nat_range2 r;
	struct dynexpect_mapping *m;
	u_int16_t port = ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port);

	/* ************* */
	int mapping_id = 0;
	mapping_id = dynexpect_find_id_for_tuple(exp);
	pr_debug("expected connection arrived; mapping_id='%d', src_port='%hu'\n", mapping_id, port);

	/* FIXME: this is risky, we have to think it over again to make
	 * sure this won't cause deadlocks */
	spin_lock_bh(&dynexpect_lock);

	m = dynexpect_lookup_id(mapping_id);
	if (m == NULL) {
		spin_unlock_bh(&dynexpect_lock);
		pr_debug("no mapping found\n");
		return;
	}

	if ((m->state < MAPPING_EXPECTED) || (m->state > MAPPING_ACTIVE)) {
		pr_debug("invalid state; id='%u', state='%d'\n",
			 m->id, m->state);
		spin_unlock_bh(&dynexpect_lock);
		dynexpect_mapping_unref(m);
		return;
	}

	/* set state to active */
	m->state = MAPPING_ACTIVE;

	spin_unlock_bh(&dynexpect_lock);

	if (m->flags & MAPPING_FLAG_NAT) {
		/* fill range structure */
		r.flags = NF_NAT_RANGE_MAP_IPS |
			NF_NAT_RANGE_PROTO_SPECIFIED;

		/* for SRC manip, set the mapped address */
		r.min_addr.ip = r.max_addr.ip = htonl(m->new_ip);
		r.min_proto.udp.port = r.max_proto.udp.port =
			htons(m->new_port + port - m->orig_port);
		pr_debug("SNATting; to='%pI4:%hu'\n",
			  &r.min_addr.ip, ntohs(r.min_proto.udp.port));
		nf_nat_setup_info(ct, &r, NF_NAT_MANIP_SRC);

		/* for DST manip, set the peer address */
		r.min_addr.ip = r.max_addr.ip = htonl(m->peer_ip);
		r.min_proto.udp.port = r.max_proto.udp.port =
			htons(m->peer_port);
		pr_debug("DNATting; to='%pI4:%hu'\n",
			  &r.min_addr.ip, ntohs(r.min_proto.udp.port));
		nf_nat_setup_info(ct, &r, NF_NAT_MANIP_DST);
	}

#ifdef CONFIG_NF_CONNTRACK_MARK
	/* set up connmark */
	ct->mark = (unsigned long) m->ct_mark;
#endif

	dynexpect_mapping_unref(m);
}

static int dynexpect_help_udp(struct sk_buff *skb, unsigned int protoff,
                              struct nf_conn *ct, enum ip_conntrack_info ctinfo)
{
	return NF_ACCEPT;
}

static const struct nf_conntrack_expect_policy dynexpect_exp_policy = {
	.max_expected		= CONFIG_NF_DYNEXPECT_MAX_EXPECTED,
	.timeout		= CONFIG_NF_DYNEXPECT_HELPER_TIMEOUT,
};

static struct nf_conntrack_helper dynexpect_ct_helper = {
	.name			= "dynexpect",
	.me			= THIS_MODULE,
	.expect_policy		= &dynexpect_exp_policy,
	//.flags   = NF_CT_HELPER_F_CONFIGURED,
	.tuple.src.l3num        = AF_INET,
	.tuple.dst.protonum     = IPPROTO_UDP,
	.tuple.src.u.udp.port = htons(5060),
	.help = dynexpect_help_udp,
};
 
static struct nf_ct_helper_expectfn dynexpect_nat = {
	.name    = "dynexpect",
	.expectfn =  dynexpect_nat_expected
};

/****************************************************************/
/* Init/cleanup							*/
/****************************************************************/

int init_or_cleanup(const int cleanup)
{
	int i;
	int ret = -ENOMEM;
	static unsigned int htable_by_addr_allocated_size;
	static unsigned int htable_by_id_allocated_size;

	if (cleanup)
		goto cleanup;

	/* check hash size */
	if (hashsize > 16384)
		hashsize = 16384;

	/* initialize hash rnd key */
	get_random_bytes(&hash_rnd_initval, sizeof(hash_rnd_initval));

	/* allocate memory */
	dynexpect_mapping_cache = kmem_cache_create("nf_ct_dynexpect",
						    sizeof(struct dynexpect_mapping), 0,
						    0, NULL);
	if (!dynexpect_mapping_cache) {
		pr_err("unable to create ip_conntrack_dynexpect slab cache\n");
		goto err_alloc_cache;
	}

	/* ID hash */
	htable_by_id_allocated_size = sizeof(struct hlist_head) * hashsize;
	dynexpect_htable_by_id = nf_ct_alloc_hashtable(&htable_by_id_allocated_size, 0);
	if (!dynexpect_htable_by_id) {
		pr_err("unable to allocate dynexpect hash table: id\n");
		goto err_alloc_hash;
	}

	/* address hash */
	htable_by_addr_allocated_size = sizeof(struct hlist_head) * hashsize;
	dynexpect_htable_by_addr = nf_ct_alloc_hashtable(&htable_by_addr_allocated_size, 0);
	if (!dynexpect_htable_by_addr) {
		pr_err("unable to allocate dynexpect hash table: address\n");
		goto err_alloc_hash;
	}

	for (i = 0; i < hashsize; i++) {
		INIT_HLIST_HEAD(&dynexpect_htable_by_id[i]);
		INIT_HLIST_HEAD(&dynexpect_htable_by_addr[i]);
	}

	/* register helpers */
	ret = nf_conntrack_helper_register(&dynexpect_ct_helper);
	if (ret != 0) {
		pr_err("unable to register conntrack helper\n");
		goto err_register_ct_helper;
	}
  
	nf_ct_helper_expectfn_register(&dynexpect_nat);

	/* register setsockopt/getsockopt callbacks */
	ret = nf_register_sockopt(&dynexpect_sockopt);
	if (ret != 0) {
		pr_err("unable to register dynexpect socket option interface\n");
		goto err_register_sockopt;
	}

	return 0;

 cleanup:
	nf_unregister_sockopt(&dynexpect_sockopt);

 err_register_sockopt:
	nf_ct_helper_expectfn_unregister(&dynexpect_nat);
	nf_conntrack_helper_unregister(&dynexpect_ct_helper);

 err_register_ct_helper:
 err_alloc_hash:
	if (dynexpect_htable_by_id != NULL)
		nf_ct_free_hashtable(dynexpect_htable_by_id, htable_by_id_allocated_size);
	if (dynexpect_htable_by_addr != NULL)
		nf_ct_free_hashtable(dynexpect_htable_by_addr, htable_by_addr_allocated_size);


	kmem_cache_destroy(dynexpect_mapping_cache);

 err_alloc_cache:
	return ret;
}

int __init dynexpect_init(void)
{
	return init_or_cleanup(0);
}

void __exit dynexpect_cleanup(void)
{
	init_or_cleanup(1);
}

module_init(dynexpect_init);
module_exit(dynexpect_cleanup);

module_param(mapping_timeout, int, 0600);
MODULE_PARM_DESC(mapping_timeout, "timeout for the dynamic mappings");
module_param(hashsize, int, 0400);
MODULE_PARM_DESC(hashsize, "mapping lookup hash size");

MODULE_AUTHOR("BalaSys Development Team <devel@balasys.hu>");
MODULE_DESCRIPTION("Dynamic expectation handler module");
MODULE_LICENSE("GPL");
