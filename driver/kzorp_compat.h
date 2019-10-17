#ifndef _KZORP_COMPAT_H
#define _KZORP_COMPAT_H

#include <compat/compat.h>

/* 
 * Copyright (C) 2006-2015 BalaBit IT Security, 2015-2017 BalaSys IT Security.
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef KZ_COMP_DOES_NOT_HAVE_TIMER_SETUP

typedef unsigned long kz_timer_arg;

#define kz_from_timer(var, callback_timer, timer_fieldname) \
	(void *)callback_timer;

#define kz_timer_setup(timer, userdata, callback) \
	do { \
		init_timer(&timer); \
		timer.data = (unsigned long)userdata; \
		timer.function = callback; \
	} while (0)

#else

typedef struct timer_list * kz_timer_arg;

#define kz_from_timer(var, callback_timer, timer_fieldname) \
	from_timer(var, callback_timer, timer_fieldname)

#define kz_timer_setup(timer, userdata, callback) \
	timer_setup(&timer, callback, 0)

#endif

#ifdef KZ_COMP_INET_LOOKUP_DOES_NOT_HAVE_SKB_DOFF

#define kz_inet_lookup(net, hashinfo, skb, doff, saddr, sport, daddr, dport, dif) \
	inet_lookup(net, hashinfo, saddr, sport, daddr, dport, dif)

#define kz_inet6_lookup(net, hashinfo, skb, doff, saddr, sport, daddr, dport, dif) \
	inet6_lookup(net, hashinfo, saddr, sport, daddr, dport, dif)

#else

#define kz_inet_lookup(net, hashinfo, skb, doff, saddr, sport, daddr, dport, dif) \
	inet_lookup(net, hashinfo, skb, doff, saddr, sport, daddr, dport, dif)

#define kz_inet6_lookup(net, hashinfo, skb, doff, saddr, sport, daddr, dport, dif) \
	inet6_lookup(net, hashinfo, skb, doff, saddr, sport, daddr, dport, dif)

#endif

#if defined KZ_COMP_INET_LOOKUP_DOES_NOT_HAVE_SKB_DOFF && defined KZ_COMP_INET_LOOKUP_DOES_NOT_HAVE_SDIF

#define kz_inet_lookup_listener(net, hashinfo, skb, doff, saddr, sport, daddr, dport, dif, sdif) \
	inet_lookup_listener(net, hashinfo, saddr, sport, daddr, dport, dif)

#define kz_inet6_lookup_listener(net, hashinfo, skb, doff, saddr, sport, daddr, hnum, dif, sdif) \
	inet6_lookup_listener(net, hashinfo, saddr, sport, daddr, hnum, dif)

#define kz___inet6_lookup_established(net, hashinfo, saddr, sport, daddr, hnum, dif, sdif) \
	__inet6_lookup_established(net, hashinfo, saddr, sport, daddr, hnum, dif)

#elif defined KZ_COMP_INET_LOOKUP_DOES_NOT_HAVE_SDIF

#define kz_inet_lookup_listener(net, hashinfo, skb, doff, saddr, sport, daddr, dport, dif, sdif) \
	inet_lookup_listener(net, hashinfo, skb, doff, saddr, sport, daddr, dport, dif)

#define kz_inet6_lookup_listener(net, hashinfo, skb, doff, saddr, sport, daddr, hnum, dif, sdif) \
	inet6_lookup_listener(net, hashinfo, skb, doff, saddr, sport, daddr, hnum, dif)

#define kz___inet6_lookup_established(net, hashinfo, saddr, sport, daddr, hnum, dif, sdif) \
	__inet6_lookup_established(net, hashinfo, saddr, sport, daddr, hnum, dif)

#else

#define kz_inet_lookup_listener(net, hashinfo, skb, doff, saddr, sport, daddr, dport, dif, sdif) \
	inet_lookup_listener(net, hashinfo, skb, doff, saddr, sport, daddr, dport, dif, sdif)

#define kz_inet6_lookup_listener(net, hashinfo, skb, doff, saddr, sport, daddr, hnum, dif, sdif) \
	inet6_lookup_listener(net, hashinfo, skb, doff, saddr, sport, daddr, hnum, dif, sdif)

#define kz___inet6_lookup_established(net, hashinfo, saddr, sport, daddr, hnum, dif, sdif) \
	__inet6_lookup_established(net, hashinfo, saddr, sport, daddr, hnum, dif, sdif)

#endif

#ifdef KZ_COMP_DOES_NOT_HAVE_REFCOUNT_INC_NOT_ZERO
#include <linux/atomic.h>
static inline bool
kz_refcount_inc_not_zero(atomic_t *r)
{
	return atomic_add_unless(r, 1, 0);
}
#else
#include <linux/refcount.h>
static inline bool
kz_refcount_inc_not_zero(refcount_t *r)
{
	return refcount_inc_not_zero(r);
}
#endif

#ifdef KZ_COMP_NLA_PARSE_NESTED_DOES_NOT_HAVE_EXTACK
#define kz_nla_parse_nested(tb, maxtype, nla, policy, extack) \
	nla_parse_nested(tb, maxtype, nla, policy)
#else
#define kz_nla_parse_nested(tb, maxtype, nla, policy, extack) \
	nla_parse_nested(tb, maxtype, nla, policy, extack)
#endif

#ifndef SLAB_TYPESAFE_BY_RCU
#define SLAB_TYPESAFE_BY_RCU SLAB_DESTROY_BY_RCU
#endif

#ifdef KZ_COMP_X_TABLES_DOES_NOT_HAVE_HELPERS
#define xt_in(par) par->in
#define xt_out(par) par->out
#define xt_hooknum(par) par->hooknum
#define xt_family(par) par->family
#define xt_net(par) par->net
#endif

#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
static inline int
kz_nf_defrag_ipv4_enable(struct net *net)
{
#ifdef KZ_COMP_NF_DEFRAG_DOES_NOT_HAVE_NET
	nf_defrag_ipv4_enable();
	return 0;
#else
	return nf_defrag_ipv4_enable(net);
#endif
}

#include <net/netfilter/ipv6/nf_defrag_ipv6.h>
static inline int
kz_nf_defrag_ipv6_enable(struct net *net)
{
#ifdef KZ_COMP_NF_DEFRAG_DOES_NOT_HAVE_NET
	nf_defrag_ipv6_enable();
	return 0;
#else
	return nf_defrag_ipv6_enable(net);
#endif
}

#include <linux/tcp.h>
static inline unsigned int
kz___tcp_hdrlen(const struct tcphdr *th)
{
	return th->doff * 4;
}

#ifdef KZ_COMP_DOES_NOT_HAVE_NLA_PUT_U64_64BIT
#define kz_nla_put_u64_64bit(skb, attrtype, value, padattr) \
	nla_put_u64(skb, attrtype, value)
#else
#define kz_nla_put_u64_64bit(skb, attrtype, value, padattr) \
	nla_put_u64_64bit(skb, attrtype, value, padattr)
#endif

#ifdef KZ_COMP_DOES_NOT_HAVE_NF_NAT_RANGE2
#define kz_nf_nat_range \
	nf_nat_range
#else
#define kz_nf_nat_range \
	nf_nat_range2
#endif

#ifdef KZ_COMP_DOES_NOT_HAVE_NF_CT_HOOK

#define kz_global_kz_nf_ct_hook \
	static void (*nf_ct_destroy_orig)(struct nf_conntrack *) __rcu __read_mostly;

#define kz_nf_ct_hook_call_destroy \
	do { \
		void (*destroy_orig)(struct nf_conntrack *); \
		rcu_read_lock(); \
		destroy_orig = rcu_dereference(nf_ct_destroy_orig); \
		BUG_ON(destroy_orig == NULL); \
		destroy_orig(nfct); \
		rcu_read_unlock(); \
	} while (0)

#define kz_nf_ct_hook_divert \
	do { \
		rcu_read_lock(); \
		nf_ct_destroy_orig = rcu_dereference(nf_ct_destroy); \
		BUG_ON(nf_ct_destroy_orig == NULL); \
		rcu_read_unlock(); \
		rcu_assign_pointer(nf_ct_destroy, kz_extension_conntrack_destroy); \
	} while (0)

#define kz_nf_ct_hook_revert \
	do { \
		void (*destroy_orig)(struct nf_conntrack *); \
		rcu_read_lock(); \
		destroy_orig = rcu_dereference(nf_ct_destroy_orig); \
		BUG_ON(destroy_orig == NULL); \
		rcu_read_unlock(); \
		rcu_assign_pointer(nf_ct_destroy, destroy_orig); \
	} while (0)

#else

#define kz_global_kz_nf_ct_hook \
	static struct nf_ct_hook __rcu *nf_ct_hook_orig __read_mostly; \
	static void kz_extension_conntrack_destroy(struct nf_conntrack *nfct); \
	static struct nf_ct_hook kz_nf_ct_hook = { .destroy = kz_extension_conntrack_destroy, };

#define kz_nf_ct_hook_call_destroy \
	do { \
		struct nf_ct_hook *ct_hook_orig = NULL; \
		rcu_read_lock(); \
		ct_hook_orig = rcu_dereference(nf_ct_hook_orig); \
		BUG_ON(ct_hook_orig == NULL); \
		ct_hook_orig->destroy(nfct); \
		rcu_read_unlock(); \
	} while (0)

#define kz_nf_ct_hook_divert \
	do { \
		rcu_read_lock(); \
		nf_ct_hook_orig = rcu_dereference(nf_ct_hook); \
		BUG_ON(nf_ct_hook_orig == NULL); \
		rcu_read_unlock(); \
		rcu_assign_pointer(nf_ct_hook, &kz_nf_ct_hook); \
	} while (0)

#define kz_nf_ct_hook_revert \
	do { \
		struct nf_ct_hook *ct_hook_orig = NULL; \
		rcu_read_lock(); \
		ct_hook_orig = rcu_dereference(nf_ct_hook_orig); \
		BUG_ON(ct_hook_orig == NULL); \
		rcu_read_unlock(); \
		rcu_assign_pointer(nf_ct_hook, ct_hook_orig); \
	} while (0)

#endif

#ifdef KZ_COMP_DOES_HAVE_NF_CT_FREE_HASHTABLE
#define kz_nf_ct_free_hashtable(hash, size) \
	nf_ct_free_hashtable(hash, size)
#else
#define kz_nf_ct_free_hashtable(hash, size) \
	kvfree(hash)
#endif

#ifdef KZ_COMP_DOES_NOT_HAVE_SKB_EXT_FIND
#define kz_skb_ext_find(skb, id) \
	((skb->sp) ? skb->sp : NULL)
#else
#define kz_skb_ext_find(skb, id) \
	skb_ext_find(skb, id)
#endif

#endif /* _KZORP_COMPAT_H */
