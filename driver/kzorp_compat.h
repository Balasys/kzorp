#ifndef _KZORP_COMPAT_H
#define _KZORP_COMPAT_H

#include <compat/compat.h>

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

#include <net/netfilter/nf_conntrack_zones.h>

#ifdef NF_CT_DEFAULT_ZONE
#define kz_nf_ct_zone_id(ct) nf_ct_zone((ct))
#else
#ifdef DIR_ADDED_NF_CT_ZONE
#define NF_CT_DEFAULT_ZONE NF_CT_DEFAULT_ZONE_ID
#define kz_nf_ct_zone_id(ct) nf_ct_zone_id(nf_ct_zone(ct), NF_CT_ZONE_DIR_ORIG)
#else
#define NF_CT_DEFAULT_ZONE NF_CT_DEFAULT_ZONE_ID
#define kz_nf_ct_zone_id(ct) nf_ct_zone((ct))->id
#endif
#endif

/*
static inline struct sock *
kz_inet_lookup_listener(struct net *net,
		struct inet_hashinfo *hashinfo,
		struct sk_buff *skb, int doff,
		__be32 saddr, __be16 sport,
		__be32 daddr, __be16 dport, int dif)
{
	return inet_lookup_listener(net, hashinfo,
#ifdef SKB_DOFF_ADDED_TO_LOOKUP_LISTENER_FUNCTIONS
				    skb, doff,
#endif
				    saddr, sport,
				    daddr, ntohs(dport), dif);
}
*/

#include <net/tcp.h>
static inline void kz_inet_twsk_deschedule_put(struct inet_timewait_sock *tw) {
#ifdef PUT_ADDED_TO_INET_TWSK_DESCHEDULE
	inet_twsk_deschedule_put(tw);
#else
#ifdef inet_twsk_for_each
	inet_twsk_deschedule(tw, &tcp_death_row);
#else
	inet_twsk_deschedule(tw);
#endif
	inet_twsk_put(tw);
#endif
}

#include <net/ip.h>
#include <linux/netfilter_ipv4.h>

static inline int
kz_ip_local_out(struct sk_buff *skb) {
#ifdef NET_PARAM_ADDED_TO_IP_LOCAL_FUNCTIONS
	return ip_local_out(dev_net(skb_dst(skb)->dev), skb->sk, skb);
#else
	return ip_local_out(skb);
#endif
}

static inline int
kz_ip6_local_out(struct sk_buff *skb) {
#ifdef NET_PARAM_ADDED_TO_IP_LOCAL_FUNCTIONS
	return ip6_local_out(dev_net(skb_dst(skb)->dev), skb->sk, skb);
#else
	return ip6_local_out(skb);
#endif
}

static inline int
kz_ip_route_me_harder(struct sk_buff *skb, unsigned addr_type) {
#ifdef NET_PARAM_ADDED_TO_IP_LOCAL_FUNCTIONS
	return ip_route_me_harder(dev_net(skb_dst(skb)->dev), skb, addr_type);
#else
	return ip_route_me_harder(skb, addr_type);
#endif
}

#endif /* _KZORP_COMPAT_H */
