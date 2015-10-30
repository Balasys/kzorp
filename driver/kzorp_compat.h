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
