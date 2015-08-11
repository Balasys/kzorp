#ifndef _KZORP_COMPAT_H
#define _KZORP_COMPAT_H

#ifndef KZ_USERSPACE
#include <linux/kernel.h>
#ifdef _UAPI_LINUX_KERNEL_H
#include <generated/uapi/linux/version.h>
#else
#include <linux/version.h>
#endif /* _UAPI_LINUX_KERNEL_H */
#endif /* KZ_USERSPACE */

#include <net/genetlink.h>
#include <linux/netlink.h>
#include <net/netfilter/nf_conntrack_zones.h>

/* 
 * Copyright (C) 2006-2012, BalaBit IT Ltd.
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

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0) )
	static inline int
	genl_register_family_with_ops_and_size(struct genl_family *family,
					       struct genl_ops *ops, size_t n_ops) {
		return genl_register_family_with_ops(family, ops, n_ops);
	}
#else
	static inline int
	genl_register_family_with_ops_and_size(struct genl_family *family,
					       const struct genl_ops *ops, size_t n_ops) {
		return _genl_register_family_with_ops_grps(family, ops, n_ops, NULL, 0);
	}
#endif

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0) )
static inline int nla_put_be16(struct sk_buff *skb, int attrtype, __be16 value)
{
	return nla_put(skb, attrtype, sizeof(__be16), &value);
}
static inline int nla_put_be32(struct sk_buff *skb, int attrtype, __be32 value)
{
	        return nla_put(skb, attrtype, sizeof(__be32), &value);
}
#endif

extern inline __be32
get_genetlink_sender(struct genl_info *info) {
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0) )
	return info->snd_portid;
#else
	return info->snd_pid;
#endif
}

extern inline __u32
get_skb_portid(struct netlink_skb_parms skb) {
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0) )
	return skb.portid;
#else
	return skb.pid;
#endif
}

extern inline int
get_notifier(struct netlink_notify * notifier) {
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0) )
	return notifier->portid;
#else
	return notifier->pid;
#endif
}

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0) )
	#include <linux/netfilter_ipv4/nf_nat.h>
	#define NAT_RANGE_TYPE struct nf_nat_range
#endif
#if ( ( LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0) ) && ( LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0) ) )
	#include <linux/netfilter/nf_nat.h>
	#define NAT_RANGE_TYPE struct nf_nat_ipv4_range
#endif
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0) )
	#include <linux/netfilter/nf_nat.h>
	#define NAT_RANGE_TYPE struct nf_nat_range
#endif
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0) )
        static inline const __be32 *kz_nat_range_get_min_ip(const NAT_RANGE_TYPE *r) { return &r->min_ip; }
        static inline const __be32 *kz_nat_range_get_max_ip(const NAT_RANGE_TYPE *r) { return &r->max_ip; }
        static inline const __be16 *kz_nat_range_get_min_port(const NAT_RANGE_TYPE *r) { return &r->min.udp.port; }
        static inline const __be16 *kz_nat_range_get_max_port(const NAT_RANGE_TYPE *r) { return &r->max.udp.port; }
        static inline void kz_nat_range_set_min_ip(NAT_RANGE_TYPE *r, __be32 min_ip) { r->min_ip = min_ip; }
        static inline void kz_nat_range_set_max_ip(NAT_RANGE_TYPE *r, __be32 max_ip) { r->max_ip = max_ip; }
        static inline void kz_nat_range_set_min_port(NAT_RANGE_TYPE *r, __be16 min_port) { r->min.udp.port = min_port; }
        static inline void kz_nat_range_set_max_port(NAT_RANGE_TYPE *r, __be16 max_port) { r->max.udp.port = max_port; }
#endif
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0) )
        static inline const __be32 *kz_nat_range_get_min_ip(const NAT_RANGE_TYPE *r) { return &r->min_addr.ip; }
        static inline const __be32 *kz_nat_range_get_max_ip(const NAT_RANGE_TYPE *r) { return &r->max_addr.ip; }
        static inline const __be16 *kz_nat_range_get_min_port(const NAT_RANGE_TYPE *r) { return &r->min_proto.udp.port; }
        static inline const __be16 *kz_nat_range_get_max_port(const NAT_RANGE_TYPE *r) { return &r->max_proto.udp.port; }
        static inline void kz_nat_range_set_min_ip(NAT_RANGE_TYPE *r, __be32 min_ip) { r->min_addr.ip = min_ip; }
        static inline void kz_nat_range_set_max_ip(NAT_RANGE_TYPE *r, __be32 max_ip) { r->max_addr.ip = max_ip; }
        static inline void kz_nat_range_set_min_port(NAT_RANGE_TYPE *r, __be16 min_port) { r->min_proto.udp.port = min_port; }
        static inline void kz_nat_range_set_max_port(NAT_RANGE_TYPE *r, __be16 max_port) { r->max_proto.udp.port = max_port; }
#endif

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0) )
	#ifdef CONFIG_NF_CONNTRACK_PROCFS
		#define CONFIG_KZORP_PROC_FS CONFIG_NF_CONNTRACK_PROCFS
	#endif
	#define counter2long(x) ((unsigned long long)x.counter)
	#define ipv6_addr_copy(x,y) ((*x) = (*y))
	#define IP_NAT_RANGE_MAP_IPS NF_NAT_RANGE_MAP_IPS
	#define IP_NAT_RANGE_PROTO_SPECIFIED NF_NAT_RANGE_PROTO_SPECIFIED
	#define IP_NAT_MANIP_SRC NF_NAT_MANIP_SRC
#else
	#define counter2long(x) ((unsigned long long)x)
	#ifdef CONFIG_KZORP_PROC_FS
		#define CONFIG_KZORP_PROC_FS CONFIG_KZORP_PROC_FS
	#endif
#endif

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0) )
#define SHINY_NEW_HLIST_FOR_EACH 1
#endif

#ifndef NLA_PUT
#define NLA_PUT(skb, attrtype, attrlen, data) \
	do { \
		if (unlikely(nla_put(skb, attrtype, attrlen, data) < 0)) \
			goto nla_put_failure; \
	} while(0)
#define NLA_PUT_TYPE(skb, type, attrtype, value) \
	do { \
		type __tmp = value; \
		NLA_PUT(skb, attrtype, sizeof(type), &__tmp); \
	} while(0)

#define NLA_PUT_U8(skb, attrtype, value) \
	NLA_PUT_TYPE(skb, u8, attrtype, value)

#define NLA_PUT_U16(skb, attrtype, value) \
	NLA_PUT_TYPE(skb, u16, attrtype, value)

#define NLA_PUT_U64(skb, attrtype, value) \
	NLA_PUT_TYPE(skb, u64, attrtype, value)

#define NLA_PUT_LE16(skb, attrtype, value) \
	NLA_PUT_TYPE(skb, __le16, attrtype, value)

#define NLA_PUT_BE16(skb, attrtype, value) \
	NLA_PUT_TYPE(skb, __be16, attrtype, value)

#define NLA_PUT_BE32(skb, attrtype, value) \
	NLA_PUT_TYPE(skb, __be32, attrtype, value)

#endif // NLA_PUT

#ifndef sk_daddr
#define sk_daddr             __sk_common.skc_daddr
#endif

#ifndef sk_rcv_saddr
#define sk_rcv_saddr         __sk_common.skc_rcv_saddr
#endif

#ifndef sk_v6_daddr
#define sk_v6_daddr             __sk_common.skc_v6_daddr
#endif

#ifndef sk_v6_rcv_saddr
#define sk_v6_rcv_saddr         __sk_common.skc_v6_rcv_saddr
#endif

#ifdef NF_CT_DEFAULT_ZONE
#define nf_ct_zone_id(ct) nf_ct_zone((ct))
#else
#define NF_CT_DEFAULT_ZONE NF_CT_DEFAULT_ZONE_ID
#define nf_ct_zone_id(ct) nf_ct_zone((ct))->id
#endif

#ifdef inet_twsk_for_each
#define kz_inet_twsk_deschedule(tw) inet_twsk_deschedule((tw), &tcp_death_row)
#else
#define kz_inet_twsk_deschedule inet_twsk_deschedule
#endif

#ifdef WITH_KZ_TPROXY_CORE_H
	#include "kz_tproxy_core.h"
#else
	#include <net/udp.h>
	#include <net/netfilter/nf_tproxy_core.h>
#endif

#endif /* _KZORP_COMPAT_H */
