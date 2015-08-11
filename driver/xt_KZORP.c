/*
 * KZorp support for Linux/iptables
 *
 * Copyright (c) 2011-2011 BalaBit IT Ltd.
 * Author: Krisztian Kovacs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/checksum.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/flow.h>
#include <net/dst.h>
#include <net/inet_sock.h>
#include <net/if_inet6.h>
#include <net/addrconf.h>
#include <net/ip6_checksum.h>
#include <net/ip6_fib.h>
#include <net/ip6_route.h>
#include <net/xfrm.h>

#include <linux/inetdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include "xt_KZORP.h"

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_conntrack_acct.h>

#include <net/netfilter/ipv4/nf_defrag_ipv4.h>

#include "kzorp.h"

#ifdef CONFIG_BRIDGE_NETFILTER
#include <linux/netfilter_bridge.h>
#endif

static const char *const kz_log_null = "(NULL)";

static struct kz_zone *
kz_zone_lookup(const struct kz_config *cfg, __be32 _addr)
{
	const union nf_inet_addr addr = { .ip = _addr };
	return kz_head_zone_lookup(&cfg->zones, &addr, NFPROTO_IPV4);
}

/**
 * v4_get_instance_bind_address() - look up the matching listener socket of the instance
 * @dpt: The dispatcher we've found.
 * @skb: The incoming frame.
 * @l4proto: L4 protocol ID.
 * @sport: L4 protocol source port.
 * @dport: L4 protocol destination port.
 *
 * Since more than one bind could be present for an instance, this
 * function looks up the appropriate bind address and looks up the
 * listener socket bound to that address.
 */
static inline struct sock *
v4_lookup_instance_bind_address(const struct kz_dispatcher *dpt,
				const struct sk_buff *skb, u8 l4proto,
				__be16 sport, __be16 dport)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct sock *sk = NULL;
	const struct kz_bind const *bind = kz_instance_bind_lookup_v4(dpt->instance, l4proto,
								      iph->saddr, sport,
								      iph->daddr, dport);
	if (bind) {
		__be16 proxy_port = htons(bind->port);
		__be32 proxy_addr = bind->addr.in.s_addr;

		sk = nf_tproxy_get_sock_v4(&init_net, l4proto,
					   iph->saddr, proxy_addr,
					   sport, proxy_port,
					   skb->dev, NFT_LOOKUP_LISTENER);
		if (sk)
			kz_debug("found instance bind socket; l4proto='%hhu', bind_address='%pI4:%hu'",
				 l4proto, &proxy_addr, proxy_port);
	}

	return sk;
}

static inline struct sock *
v4_get_socket_to_redirect_to(const struct kz_dispatcher *dpt,
			     const struct sk_buff *skb, u8 l4proto,
			     __be16 sport, __be16 dport)
{
	const struct iphdr *iph = ip_hdr(skb);
	const struct net_device *in = skb->dev;
	struct sock *sk;

	/* lookup established first */
	sk = nf_tproxy_get_sock_v4(&init_net, iph->protocol, iph->saddr, iph->daddr,
				   sport, dport, in, NFT_LOOKUP_ESTABLISHED);

	if (sk == NULL || sk->sk_state == TCP_TIME_WAIT)
	{
		struct sock *listener_sk = NULL;
		struct tcphdr _tcp_header;
		const struct tcphdr *tcp_header = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(_tcp_header), &_tcp_header);

		/* N-dimension dispatchers use the bind addresses registered for the instance */
		listener_sk = v4_lookup_instance_bind_address(dpt, skb, l4proto, sport, dport);
		if (listener_sk) {
			if (sk) {
				if (sk->sk_state == TCP_TIME_WAIT &&
				    tcp_header->syn && !tcp_header->rst && !tcp_header->ack && !tcp_header->fin)
					kz_inet_twsk_deschedule(inet_twsk(sk));

				if (sk->sk_state == TCP_TIME_WAIT)
					inet_twsk_put(inet_twsk(sk));
				else
					sock_put(sk);
			}

			sk = listener_sk;
		}
	} else {
		/* non-TW established socket */
		kz_debug("found established socket");
	}

	return sk;
}

static inline bool
redirect_v4(struct sk_buff *skb, u8 l4proto,
	    __be16 sport, __be16 dport,
	    const struct kz_dispatcher *dpt,
	    const struct xt_kzorp_target_info * tgi)
{
	struct sock *sk = NULL;
	const struct iphdr * const iph = ip_hdr(skb);

	kz_debug("transparent dispatcher, trying to redirect; dpt='%s'\n", dpt->name);

	sk = v4_get_socket_to_redirect_to(dpt, skb, l4proto, sport, dport);
	if (sk == NULL) {
		/* FIXME: we've found no socket to divert to,
		   so we simply drop the packet.  We should
		   really implement the possibility of
		   REJECT-ing the packet instead of silently
		   dropping it.
		*/
		kz_debug("socket not found, trasparent proxy not redirected; src='%pI4:%u', dst='%pI4:%u'\n",
			 &iph->saddr, ntohs(sport), &iph->daddr, ntohs(dport));
		return false;
	}

	nf_tproxy_assign_sock(skb, sk);
	skb->mark = (skb->mark & ~tgi->mark_mask) ^ tgi->mark_value;

	kz_debug("transparent proxy session redirected; socket='%p'\n", sk);

	return true;
}

static inline const struct in6_addr *
tproxy_laddr6(struct sk_buff *skb, const struct in6_addr *daddr)
{
	struct inet6_dev *indev;
	struct inet6_ifaddr *ifa;
	struct in6_addr *laddr;

	laddr = NULL;

	rcu_read_lock();
	indev = __in6_dev_get(skb->dev);
	if (indev)
		list_for_each_entry(ifa, &indev->addr_list, if_list) {
			if (ifa->flags & (IFA_F_TENTATIVE | IFA_F_DEPRECATED))
				continue;

			laddr = &ifa->addr;
			break;
		}
	rcu_read_unlock();

	return laddr ? laddr : daddr;
}

/**
 * relookup_time_wait6() - handle IPv6 TCP TIME_WAIT reopen redirections
 * @skb:	The skb being processed.
 * @tproto:	Transport protocol.
 * @thoff:	Transport protocol header offset.
 * @par:	Iptables target parameters.
 * @sk:		The TIME_WAIT TCP socket found by the lookup.
 *
 * We have to handle SYN packets arriving to TIME_WAIT sockets
 * differently: instead of reopening the connection we should rather
 * redirect the new connection to the proxy if there's a listener
 * socket present.
 *
 * relookup_time_wait6() consumes the socket reference passed in.
 *
 * Returns the listener socket if there's one, the TIME_WAIT socket if
 * no such listener is found, or NULL if the TCP header is incomplete.
 */
static struct sock *
relookup_time_wait6(struct sk_buff *skb, int l4proto, int thoff,
			 const struct in6_addr *proxy_addr, __be16 proxy_port,
			 struct sock *sk)
{
	const struct ipv6hdr *iph = ipv6_hdr(skb);
	struct tcphdr _hdr, *hp;

	hp = skb_header_pointer(skb, thoff, sizeof(_hdr), &_hdr);
	if (hp == NULL) {
		inet_twsk_put(inet_twsk(sk));
		return NULL;
	}

	if (hp->syn && !hp->rst && !hp->ack && !hp->fin) {
		/* SYN to a TIME_WAIT socket, we'd rather redirect it
		 * to a listener socket if there's one */
		struct sock *sk2;

		sk2 = nf_tproxy_get_sock_v6(dev_net(skb->dev), l4proto,
					    &iph->saddr,
					    tproxy_laddr6(skb, proxy_addr),
					    hp->source,
					    proxy_port,
					    skb->dev, NFT_LOOKUP_LISTENER);
		if (sk2) {
			kz_inet_twsk_deschedule(inet_twsk(sk));
			inet_twsk_put(inet_twsk(sk));
			sk = sk2;
		}
	}

	return sk;
}

static inline bool
redirect_v6(struct sk_buff *skb, u8 l4proto,
	    __be16 sport, __be16 dport,
	    const struct kz_dispatcher *dpt,
	    const struct xt_kzorp_target_info * tgi)
{
	const struct ipv6hdr * const iph = ipv6_hdr(skb);
	int thoff;
	u8 tproto = iph->nexthdr;
	struct udphdr _hdr, *hp;
	__be16 proxy_port = 0;
	const struct in6_addr *proxy_addr = NULL;
	struct sock *sk = NULL;

	/* find transport header */
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0) )
	__be16 frag_offp;
	thoff = ipv6_skip_exthdr(skb, sizeof(*iph), &tproto, &frag_offp);
#else
	thoff = ipv6_skip_exthdr(skb, sizeof(*iph), &tproto);
#endif
	if (unlikely(thoff < 0)) {
		kz_debug("unable to find transport header in IPv6 packet, dropped; src='%pI6c', dst='%pI6c'\n",
			 &iph->saddr, &iph->daddr);
		return false;
	}

	hp = skb_header_pointer(skb, thoff, sizeof(_hdr), &_hdr);
	if (hp == NULL) {
		kz_debug("unable to grab transport header contents in IPv6 packet, dropping\n");
		return false;
	}

	/* check if there's an ongoing connection on the packet
	 * addresses, this happens if the redirect already happened
	 * and the current packet belongs to an already established
	 * connection */
	sk = nf_tproxy_get_sock_v6(dev_net(skb->dev), tproto,
				   &iph->saddr, &iph->daddr,
				   hp->source, hp->dest,
				   skb->dev, NFT_LOOKUP_ESTABLISHED);
	if (sk == NULL || sk->sk_state == TCP_TIME_WAIT) {

		const struct kz_bind const *bind = kz_instance_bind_lookup_v6(dpt->instance, l4proto,
									      &iph->saddr, sport,
									      &iph->daddr, dport);
		if (bind) {
			proxy_port = htons(bind->port);
			proxy_addr = &bind->addr.in6;
			/* UDP has no TCP_TIME_WAIT state, so we never enter here */
			if (sk == NULL)
				/* no there's no established connection, check if
				 * there's a listener on the redirected addr/port */
				sk = nf_tproxy_get_sock_v6(dev_net(skb->dev), tproto,
							   &iph->saddr, proxy_addr,
							   hp->source, proxy_port,
							   skb->dev, NFT_LOOKUP_LISTENER);
			else /* sk->sk_state == TIME_WAIT */
				/* reopening a TIME_WAIT connection needs special handling */
				sk = relookup_time_wait6(skb, tproto, thoff, proxy_addr, proxy_port, sk);
		} else {
			sk = NULL;
		}
	}

	/* NOTE: assign_sock consumes our sk reference */
	if (sk) {
		/* This should be in a separate target, but we don't do multiple
		   targets on the same rule yet */
		skb->mark = (skb->mark & ~tgi->mark_mask) ^ tgi->mark_value;

		if (proxy_addr) {
			pr_debug("redirecting: proto %hhu %pI6c:%hu -> %pI6c:%hu, mark: %x\n",
				 tproto, &iph->daddr, ntohs(hp->dest),
				 proxy_addr, ntohs(proxy_port), skb->mark);
		} else {
			pr_debug("redirecting: proto %hhu %pI6c:%hu -> %pI6c:%hu, mark: %x\n",
				 tproto, &iph->daddr, ntohs(hp->dest),
				 &inet6_sk(sk)->saddr, inet_sk(sk)->inet_num, skb->mark);
		}

		nf_tproxy_assign_sock(skb, sk);
		return true;
	}

	return false;
}

static inline bool
is_protocol_hanlded_by_proxy(u8 l3proto, u8 l4proto)
{
	if (unlikely((l4proto != IPPROTO_TCP) && (l4proto != IPPROTO_UDP))) {
		/* this is a config problem: a proxy service configured for
		 * non TCP/UDP traffic -> we cannot do much but drop the packet */
		char _buf[L4PROTOCOL_STRING_SIZE];

		kz_debug("non TCP or UDP frame, dropping; protocol='%s'\n", l4proto_as_string(l4proto, _buf));
		return false;
	}

	return true;
}

static inline bool
redirect_to_proxy(struct sk_buff *skb,
		  u8 l3proto, u8 l4proto, __be16 sport, __be16 dport,
		  const struct kz_dispatcher *dpt,
		  const struct xt_kzorp_target_info * tgi)
{
	bool res = false;

	switch (l3proto) {
	case NFPROTO_IPV4:
		res = redirect_v4(skb, l4proto, sport, dport, dpt, tgi);
		break;
	case NFPROTO_IPV6:
		res = redirect_v6(skb, l4proto, sport, dport, dpt, tgi);
		break;
	default:
		BUG();
	}

	return res;
}

static inline unsigned int
process_forwarded_session(unsigned int hooknum, struct sk_buff *skb,
			  const struct net_device *in, const struct net_device *out,
			  const struct kz_config *cfg,
			  u8 l3proto, u8 l4proto,
			  __be16  sport, __be16 dport, 
			  struct nf_conn * const ct,
			  const enum ip_conntrack_info ctinfo,
			  struct kz_zone ** const szone,
			  struct kz_service *svc)
{
	unsigned int verdict = NF_ACCEPT;
	const NAT_RANGE_TYPE *map;
	NAT_RANGE_TYPE fakemap;
	__be32 raddr;
	__be16 rport;
	const struct list_head *head = NULL;

	/* new IPv4 connections only */
	if (l3proto == NFPROTO_IPV4 && ct && (ctinfo == IP_CT_NEW) &&
	    !nf_nat_initialized(ct, HOOK2MANIP(hooknum))) {

		const struct iphdr * const iph = ip_hdr(skb);

		/* destination address:
		 *   - original destination if the service is transparent
		 *   - specified destination otherwise */
		if (svc->flags & KZF_SERVICE_TRANSPARENT) {
			raddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
			rport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.udp.port;
		} else {
			raddr = svc->a.fwd.router_dst_addr.ip;
			rport = htons(svc->a.fwd.router_dst_port);
		}

		kz_debug("processing forwarded session; remote_address='%pI4:%u'\n", &raddr, ntohs(rport));

		switch (hooknum) {
		case NF_INET_PRE_ROUTING:
			/* we apply DNAT rules on PREROUTING */
			head = &svc->a.fwd.dnat;
			break;
		case NF_INET_POST_ROUTING:
			/* and SNAT rules on POSTROUTING */
			head = &svc->a.fwd.snat;
			break;
		default:
			verdict = NF_DROP;
			BUG();
		}

		map = kz_service_nat_lookup(head, iph->saddr, raddr,
					sport, rport, l4proto);
		kz_debug("NAT rule lookup done; map='%p'\n", map);

		if (hooknum == NF_INET_PRE_ROUTING) {
			if (map == NULL) {
				if (!(svc->flags & KZF_SERVICE_TRANSPARENT)) {
					/* PFService with DirectedRouter, we have to DNAT to
					 * the specified address */
					fakemap.flags = IP_NAT_RANGE_MAP_IPS | IP_NAT_RANGE_PROTO_SPECIFIED;
					kz_nat_range_set_min_ip(&fakemap, raddr);
					kz_nat_range_set_max_ip(&fakemap, raddr);
					kz_nat_range_set_min_port(&fakemap, rport);
					kz_nat_range_set_max_port(&fakemap, rport);
					map = &fakemap;
					kz_debug("setting up destination NAT for DirectedRouter; new_dst='%pI4:%u'\n",
						 &raddr, ntohs(rport));
				}
			} else {
				/* DNAT entry with no specified destination port */
				if (!(map->flags & IP_NAT_RANGE_PROTO_SPECIFIED)) {
					fakemap.flags = IP_NAT_RANGE_MAP_IPS | IP_NAT_RANGE_PROTO_SPECIFIED;
					kz_nat_range_set_min_ip(&fakemap, *kz_nat_range_get_min_ip(map));
					kz_nat_range_set_max_ip(&fakemap, *kz_nat_range_get_max_ip(map));
					kz_nat_range_set_min_port(&fakemap, rport);
					kz_nat_range_set_max_port(&fakemap, rport);
					map = &fakemap;
				}
			}
		}

		if (map != NULL) {
			struct kz_zone *fzone = NULL;

			/* mapping found */
			kz_debug("NAT rule found; hooknum='%d', min_ip='%pI4', max_ip='%pI4', min_port='%u', max_port='%u'\n",
				 hooknum,
				 kz_nat_range_get_min_ip(map),
				 kz_nat_range_get_max_ip(map),
				 ntohs(*kz_nat_range_get_min_port(map)),
				 ntohs(*kz_nat_range_get_max_port(map)));

			if (hooknum == NF_INET_PRE_ROUTING) {
				/* XXX: Assumed: map->min_ip == map->max_ip */
				fzone = kz_zone_lookup(cfg, *kz_nat_range_get_min_ip(map));

				kz_debug("re-lookup zone after NAT; old_zone='%s', new_zone='%s'\n",
					 *szone ? (*szone)->name : kz_log_null,
					 fzone ? fzone->name : kz_log_null);

				if (fzone != *szone) {
					*szone = fzone;
					if (*szone)
						*szone = kz_zone_get(*szone);
				}
			}

			verdict = nf_nat_setup_info(ct, map, HOOK2MANIP(hooknum));
		} else {
			kz_debug("no NAT rule found; hooknum='%d'\n", hooknum);

			/* we have to SNAT the session if the service
			 * has no FORGE flag */
			if ((hooknum == NF_INET_POST_ROUTING) &&
			    !(svc->flags & KZF_SERVICE_FORGE_ADDR)) {
				struct rtable *rt;
				NAT_RANGE_TYPE range;
				__be32 laddr;

				rt = skb_rtable(skb);
				laddr = inet_select_addr(out, rt->rt_gateway, RT_SCOPE_UNIVERSE);
				if (!laddr) {
					kz_debug("failed to select source address; out_iface='%s'\n",
						 out ? out->name : kz_log_null);
					goto done;
				}

				range.flags = IP_NAT_RANGE_MAP_IPS;
				kz_nat_range_set_min_ip(&range, laddr);
				kz_nat_range_set_max_ip(&range, laddr);

				kz_debug("setting up implicit SNAT as FORGE_ADDR is off; new_src='%pI4'\n", &laddr);
				verdict = nf_nat_setup_info(ct, &range, HOOK2MANIP(hooknum));
			}
		}
	}

done:
	kz_debug("verdict='%d'\n", verdict);
	return verdict;
}

static inline void
kz_session_log(const char *msg,
	       const struct kz_service *svc,
	       const u8 l3proto, const u8 l4proto,
	       const struct kz_zone *client_zone, const struct kz_zone *server_zone,
	       const struct sk_buff *skb,
	       const __be16 src_port, const __be16 dst_port)
{
	char _buf[L4PROTOCOL_STRING_SIZE];
	const char *client_zone_name = (client_zone && client_zone->name) ? client_zone->name : kz_log_null;
	const char *server_zone_name = (server_zone && server_zone->name) ? server_zone->name : kz_log_null;
	const char *service_name = (svc && svc->name) ? svc->name : kz_log_null;

	if (!kz_log_ratelimit())
		return;

	if (svc && (svc->flags & KZF_SERVICE_LOGGING) == 0)
		return;

	switch (l3proto) {
	case NFPROTO_IPV4: {
		const struct iphdr * const iph = ip_hdr(skb);
		printk(KERN_INFO "kzorp (svc/%s): %s; service='%s', "
				 "client_zone='%s', server_zone='%s', "
				 "client_address='%pI4:%u', "
				 "server_address='%pI4:%u', protocol='%s'\n",
				 service_name, msg, service_name,
				 client_zone_name,
				 server_zone_name,
				 &iph->saddr, ntohs(src_port),
				 &iph->daddr, ntohs(dst_port),
				 l4proto_as_string(l4proto, _buf));
	}
		break;
	case NFPROTO_IPV6: {
		const struct ipv6hdr *iph = ipv6_hdr(skb);
		printk(KERN_INFO "kzorp (svc/%s): %s; service='%s', "
				 "client_zone='%s', server_zone='%s', "
				 "client_address='%pI6c:%u', "
				 "server_address='%pI6c:%u', protocol='%s'\n",
				 service_name, msg, service_name,
				 client_zone_name,
				 server_zone_name,
				 &iph->saddr, ntohs(src_port),
				 &iph->daddr, ntohs(dst_port),
				 l4proto_as_string(l4proto, _buf));
	}
		break;
	default:
		BUG();
	}
}

/* Send RST reply: copied from net/ipv4/netfilter/ipt_REJECT.c
 * change: if (ip_route_me_harder(nskb, RTN_UNICAST))
 * RTN_UNICAST is used instead of RTN_UNSPEC, this is needed
 * for ip_route_me_harder to set the FLOWI_FLAG_ANYSRC flag.
 */
static void
send_reset_v4(struct sk_buff *oldskb, int hook)
{
	struct sk_buff *nskb;
	const struct iphdr *oiph;
	struct iphdr *niph;
	const struct tcphdr *oth;
	struct tcphdr _otcph, *tcph;

	/* IP header checks: fragment. */
	if (ip_hdr(oldskb)->frag_off & htons(IP_OFFSET))
		return;

	oth = skb_header_pointer(oldskb, ip_hdrlen(oldskb),
				 sizeof(_otcph), &_otcph);
	if (oth == NULL)
		return;

	/* No RST for RST. */
	if (oth->rst)
		return;

	if (skb_rtable(oldskb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
		return;

	/* Check checksum */
	if (nf_ip_checksum(oldskb, hook, ip_hdrlen(oldskb), IPPROTO_TCP))
		return;
	oiph = ip_hdr(oldskb);

	nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) +
			 LL_MAX_HEADER, GFP_ATOMIC);
	if (!nskb)
		return;

	skb_reserve(nskb, LL_MAX_HEADER);

	skb_reset_network_header(nskb);
	niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
	niph->version	= 4;
	niph->ihl	= sizeof(struct iphdr) / 4;
	niph->tos	= 0;
	niph->id	= 0;
	niph->frag_off	= htons(IP_DF);
	niph->protocol	= IPPROTO_TCP;
	niph->check	= 0;
	niph->saddr	= oiph->daddr;
	niph->daddr	= oiph->saddr;

	tcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
	memset(tcph, 0, sizeof(*tcph));
	tcph->source	= oth->dest;
	tcph->dest	= oth->source;
	tcph->doff	= sizeof(struct tcphdr) / 4;

	if (oth->ack)
		tcph->seq = oth->ack_seq;
	else {
		tcph->ack_seq = htonl(ntohl(oth->seq) + oth->syn + oth->fin +
				      oldskb->len - ip_hdrlen(oldskb) -
				      (oth->doff << 2));
		tcph->ack = 1;
	}

	tcph->rst	= 1;
	tcph->check = ~tcp_v4_check(sizeof(struct tcphdr), niph->saddr,
				    niph->daddr, 0);
	nskb->ip_summed = CHECKSUM_PARTIAL;
	nskb->csum_start = (unsigned char *)tcph - nskb->head;
	nskb->csum_offset = offsetof(struct tcphdr, check);

	/* ip_route_me_harder expects skb->dst to be set */
	skb_dst_set_noref(nskb, skb_dst(oldskb));

	nskb->protocol = htons(ETH_P_IP);
	if (ip_route_me_harder(nskb, RTN_UNICAST))
		goto free_nskb;

	niph->ttl	= ip4_dst_hoplimit(skb_dst(nskb));

	/* "Never happens" */
	if (nskb->len > dst_mtu(skb_dst(nskb)))
		goto free_nskb;

	nf_ct_attach(nskb, oldskb);

	ip_local_out(nskb);
	return;

 free_nskb:
	kfree_skb(nskb);
}

static void
send_unreach_v4(struct sk_buff *skb_in, unsigned char code)
{
	kz_debug("sending ICMP destination unreachable; code='%hhu'\n", code);
	icmp_send(skb_in, ICMP_DEST_UNREACH, code, 0);
}

static void
send_reset_v6(struct net *net, struct sk_buff *oldskb)
{
	struct sk_buff *nskb;
	struct tcphdr otcph, *tcph;
	unsigned int otcplen, hh_len;
	int tcphoff, needs_ack;
	const struct ipv6hdr *oip6h = ipv6_hdr(oldskb);
	struct ipv6hdr *ip6h;
#define DEFAULT_TOS_VALUE	0x0U
	const __u8 tclass = DEFAULT_TOS_VALUE;
	struct dst_entry *dst = NULL;
	u8 proto;
	struct flowi6 fl6;

	if ((!(ipv6_addr_type(&oip6h->saddr) & IPV6_ADDR_UNICAST)) ||
	    (!(ipv6_addr_type(&oip6h->daddr) & IPV6_ADDR_UNICAST))) {
		pr_debug("addr is not unicast.\n");
		return;
	}

	proto = oip6h->nexthdr;
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0) )
	{
		__be16 frag_offp;
		tcphoff = ipv6_skip_exthdr(oldskb, ((u8*)(oip6h+1) - oldskb->data), &proto, &frag_offp);
	}
#else
	tcphoff = ipv6_skip_exthdr(oldskb, ((u8*)(oip6h+1) - oldskb->data), &proto);
#endif

	if ((tcphoff < 0) || (tcphoff > oldskb->len)) {
		pr_debug("Cannot get TCP header.\n");
		return;
	}

	otcplen = oldskb->len - tcphoff;

	/* IP header checks: fragment, too short. */
	if (proto != IPPROTO_TCP || otcplen < sizeof(struct tcphdr)) {
		pr_debug("proto(%d) != IPPROTO_TCP, "
			 "or too short. otcplen = %d\n",
			 proto, otcplen);
		return;
	}

	if (skb_copy_bits(oldskb, tcphoff, &otcph, sizeof(struct tcphdr)))
		BUG();

	/* No RST for RST. */
	if (otcph.rst) {
		pr_debug("RST is set\n");
		return;
	}

	/* Check checksum. */
	if (csum_ipv6_magic(&oip6h->saddr, &oip6h->daddr, otcplen, IPPROTO_TCP,
			    skb_checksum(oldskb, tcphoff, otcplen, 0))) {
		pr_debug("TCP checksum is invalid\n");
		return;
	}

	memset(&fl6, 0, sizeof(fl6));
	fl6.flowi6_proto = IPPROTO_TCP;
	ipv6_addr_copy(&fl6.saddr, &oip6h->daddr);
	ipv6_addr_copy(&fl6.daddr, &oip6h->saddr);
	fl6.fl6_sport = otcph.dest;
	fl6.fl6_dport = otcph.source;
	security_skb_classify_flow(oldskb, flowi6_to_flowi(&fl6));
	dst = ip6_route_output(net, NULL, &fl6);
	if (dst == NULL || dst->error) {
		dst_release(dst);
		return;
	}
	dst = xfrm_lookup(net, dst, flowi6_to_flowi(&fl6), NULL, 0);
	if (IS_ERR(dst))
		return;

	hh_len = (dst->dev->hard_header_len + 15)&~15;
	nskb = alloc_skb(hh_len + 15 + dst->header_len + sizeof(struct ipv6hdr)
			 + sizeof(struct tcphdr) + dst->trailer_len,
			 GFP_ATOMIC);

	if (!nskb) {
		if (net_ratelimit())
			pr_debug("cannot alloc skb\n");
		dst_release(dst);
		return;
	}

	skb_dst_set(nskb, dst);

	skb_reserve(nskb, hh_len + dst->header_len);

	skb_put(nskb, sizeof(struct ipv6hdr));
	skb_reset_network_header(nskb);
	ip6h = ipv6_hdr(nskb);
	*(__be32 *)ip6h =  htonl(0x60000000 | (tclass << 20));
	ip6h->hop_limit = ip6_dst_hoplimit(dst);
	ip6h->nexthdr = IPPROTO_TCP;
	ipv6_addr_copy(&ip6h->saddr, &oip6h->daddr);
	ipv6_addr_copy(&ip6h->daddr, &oip6h->saddr);

	tcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
	/* Truncate to length (no data) */
	tcph->doff = sizeof(struct tcphdr)/4;
	tcph->source = otcph.dest;
	tcph->dest = otcph.source;

	if (otcph.ack) {
		needs_ack = 0;
		tcph->seq = otcph.ack_seq;
		tcph->ack_seq = 0;
	} else {
		needs_ack = 1;
		tcph->ack_seq = htonl(ntohl(otcph.seq) + otcph.syn + otcph.fin
				      + otcplen - (otcph.doff<<2));
		tcph->seq = 0;
	}

	/* Reset flags */
	((u_int8_t *)tcph)[13] = 0;
	tcph->rst = 1;
	tcph->ack = needs_ack;
	tcph->window = 0;
	tcph->urg_ptr = 0;
	tcph->check = 0;

	/* Adjust TCP checksum */
	tcph->check = csum_ipv6_magic(&ipv6_hdr(nskb)->saddr,
				      &ipv6_hdr(nskb)->daddr,
				      sizeof(struct tcphdr), IPPROTO_TCP,
				      csum_partial(tcph,
						   sizeof(struct tcphdr), 0));

	nf_ct_attach(nskb, oldskb);

	ip6_local_out(nskb);
}

static void
send_unreach_v6(struct net *net, struct sk_buff *skb_in, unsigned char code,
		unsigned int hooknum)
{
	kz_debug("sending ICMPv6 destination unreachable; code='%hhu'\n", code);

	if (hooknum == NF_INET_LOCAL_OUT && skb_in->dev == NULL)
		skb_in->dev = net->loopback_dev;

	icmpv6_send(skb_in, ICMPV6_DEST_UNREACH, code, 0);
}

static unsigned int
process_denied_session(unsigned int hooknum, struct sk_buff *skb,
		       const struct net_device *in,
		       u8 l3proto, u8 l4proto,
		       u16 sport, u16 dport,
		       const struct nf_conn *ct,
		       const struct nf_conntrack_kzorp *kzorp)
{
	struct kz_service *svc = kzorp->svc;
	struct net *net = dev_net(in);

	kz_session_log("Session denied",
			kzorp->svc, l3proto, l4proto,
			kzorp->czone, kzorp->szone, skb,
			sport, dport);

	kz_log_session_verdict(KZ_VERDICT_DENIED_BY_POLICY, "Rejecting session", ct, kzorp);

	switch (l3proto) {
	case NFPROTO_IPV4:
		switch (svc->a.deny.ipv4_reject_method) {
		case KZ_SERVICE_DENY_METHOD_V4_DROP:
			/* do nothing, just drop the packet */
			break;

		case KZ_SERVICE_DENY_METHOD_V4_TCP_RESET:
			if (l4proto == IPPROTO_TCP)
				send_reset_v4(skb, hooknum);
			break;

		case KZ_SERVICE_DENY_METHOD_ICMP_NET_UNREACHABLE:
			send_unreach_v4(skb, ICMP_NET_UNREACH);
			break;

		case KZ_SERVICE_DENY_METHOD_ICMP_HOST_UNREACHABLE:
			send_unreach_v4(skb, ICMP_HOST_UNREACH);
			break;

		case KZ_SERVICE_DENY_METHOD_ICMP_PROTO_UNREACHABLE:
			send_unreach_v4(skb, ICMP_PROT_UNREACH);
			break;

		case KZ_SERVICE_DENY_METHOD_ICMP_PORT_UNREACHABLE:
			send_unreach_v4(skb, ICMP_PORT_UNREACH);
			break;

		case KZ_SERVICE_DENY_METHOD_ICMP_NET_PROHIBITED:
			send_unreach_v4(skb, ICMP_NET_ANO);
			break;

		case KZ_SERVICE_DENY_METHOD_ICMP_HOST_PROHIBITED:
			send_unreach_v4(skb, ICMP_HOST_ANO);
			break;

		case KZ_SERVICE_DENY_METHOD_ICMP_ADMIN_PROHIBITED:
			send_unreach_v4(skb, ICMP_PKT_FILTERED);
			break;

		case KZ_SERVICE_DENY_METHOD_V4_COUNT:
			BUG();
			break;
		}
		break;

	case NFPROTO_IPV6:
		switch (svc->a.deny.ipv6_reject_method) {
		case KZ_SERVICE_DENY_METHOD_V6_DROP:
			break;

		case KZ_SERVICE_DENY_METHOD_V6_TCP_RESET:
			if (l4proto == IPPROTO_TCP)
				send_reset_v6(net, skb);
			break;

		case KZ_SERVICE_DENY_METHOD_ICMPV6_NO_ROUTE:
			send_unreach_v6(net, skb, ICMPV6_NOROUTE, hooknum);
			break;

		case KZ_SERVICE_DENY_METHOD_ICMPV6_ADMIN_PROHIBITED:
			send_unreach_v6(net, skb, ICMPV6_ADM_PROHIBITED, hooknum);
			break;

		case KZ_SERVICE_DENY_METHOD_ICMPV6_ADDR_UNREACHABLE:
			send_unreach_v6(net, skb, ICMPV6_ADDR_UNREACH, hooknum);
			break;

		case KZ_SERVICE_DENY_METHOD_ICMPV6_PORT_UNREACHABLE:
			send_unreach_v6(net, skb, ICMPV6_PORT_UNREACH, hooknum);
			break;

		case KZ_SERVICE_DENY_METHOD_V6_COUNT:
			BUG();
			break;
		}
		break;
	}

	return NF_DROP;
}

/* cast away constness */
static inline struct nf_conntrack_kzorp *
patch_kzorp(const struct nf_conntrack_kzorp *kzorp)
{
	return (struct nf_conntrack_kzorp *) kzorp;
}

static inline struct kz_rule *
find_rule_by_id(struct kz_dispatcher *dispatcher, u_int64_t rule_id)
{
	unsigned int i;
	struct kz_rule *rule = NULL;

	for (i = 0; i < dispatcher->num_rule; ++i)
		if (dispatcher->rule[i].id == rule_id) {
			rule = &dispatcher->rule[i];
			break;
		}

	return rule;
}

static bool
service_assign_session_id(const struct nf_conn *ct,
			  const struct nf_conntrack_kzorp *kzorp)
{
	struct kz_service *svc = kzorp->svc;

	if  (svc->flags & KZF_SERVICE_CNT_LOCKED) {
		kz_log_session_verdict(KZ_VERDICT_DENIED_BY_POLICY, "Service is locked during reload",
				       ct, kzorp);
		return false;
	} else {
		struct nf_conntrack_kzorp *patchable_kzorp = patch_kzorp(kzorp);
		struct kz_dispatcher *dispatcher = patchable_kzorp->dpt;
		struct kz_rule *rule = NULL;

		patchable_kzorp->sid = kz_service_count_inc(svc);
		rule = find_rule_by_id(dispatcher, kzorp->rule_id);
		BUG_ON(rule == NULL);

		kz_rule_count_inc(rule);
		if (rule->num_src_zone > 0 && kzorp->czone)
			kz_zone_count_inc(kzorp->czone);
		if (rule->num_dst_zone > 0 && kzorp->szone)
			kz_zone_count_inc(kzorp->szone);
	}

	return true;
}

static unsigned int
kz_prerouting_verdict(struct sk_buff *skb,
		      const struct net_device *in,
		      const struct net_device *out,
		      const struct kz_config *cfg,
		      const u8 l3proto,
		      const u8 l4proto,
		      __be16 sport, __be16 dport,
		      enum ip_conntrack_info ctinfo,
		      struct nf_conn *ct,
		      const struct nf_conntrack_kzorp *kzorp,
		      const struct xt_kzorp_target_info *tgi)
{
	struct kz_dispatcher *dpt = kzorp->dpt; 
	struct kz_service *svc = kzorp->svc;
	struct kz_zone *czone = kzorp->czone;
	struct kz_zone *szone = kzorp->szone;

	unsigned int verdict = NF_ACCEPT;
	/* do session id assignment for new connections */
	if (ctinfo == IP_CT_NEW) {
		/* proxy sessions have their session id assigned on prerouting */
		if ((svc != NULL) && (svc->type == KZ_SERVICE_PROXY) && (kzorp->sid == 0))
			if (!service_assign_session_id(ct, kzorp))
				return NF_DROP;
	}

	if (dpt != NULL) {
		if (svc != NULL) {
			/* process actions:
			 *   - for forwarded sessions:
			 *     - DNAT + ACCEPT
			 *   - for proxied sessions:
			 *     - transparent: redirect + ACCEPT
			 *     - non-transparent: ACCEPT
			 */

			switch (svc->type) {
			case KZ_SERVICE_PROXY:
				if (!is_protocol_hanlded_by_proxy(l3proto, l4proto)) {
					verdict = NF_DROP;
					kz_log_session_verdict(KZ_VERDICT_DENIED_BY_POLICY, "Unacceptable protocol for proxy",
							       ct, kzorp);
				} else if (!redirect_to_proxy(skb, l3proto, l4proto, sport, dport, dpt, tgi)) {
					verdict = NF_DROP;
					kz_log_session_verdict(KZ_VERDICT_DENIED_BY_UNKNOWN_FAIL, "Redirection to proxy has failed",
							       ct, kzorp);
				}
				break;

			case KZ_SERVICE_FORWARD:
				verdict = process_forwarded_session(NF_INET_PRE_ROUTING, skb, in, out, cfg,
								    l3proto, l4proto, sport, dport,
								    ct, ctinfo, &szone, svc);
				if ( szone != kzorp->szone) {
					kz_zone_put(kzorp->szone);
					patch_kzorp(kzorp)->szone = szone;
				}
				break;

			case KZ_SERVICE_DENY:
				/* do nothing: deny services are processed either on INPUT or FORWARD */
				break;

			case KZ_SERVICE_INVALID:
			case KZ_SERVICE_TYPE_COUNT:
				BUG();
			}
		} else {
			/* no service was found, log and drop packet */
			if (!czone || !szone) {
				kz_log_session_verdict(KZ_VERDICT_DENIED_BY_POLICY, "Dispatcher found without valid (client zone, server zone, service) triplet; dropping packet",
						       ct, kzorp);
			} else  {
				kz_log_session_verdict(KZ_VERDICT_DENIED_BY_POLICY, "No applicable service found for this client & server zone, dropping packet",
						       ct, kzorp);
			}

			verdict = NF_DROP;
		}
	}

	return verdict;
}

static unsigned int
kz_input_newconn_verdict(struct sk_buff *skb,
			 const struct net_device *in,
			 u8 l3proto, u8 l4proto,
			 u16 sport, u16 dport,
			 const struct nf_conn *ct,
			 const struct nf_conntrack_kzorp *kzorp)
{
	unsigned int verdict = NF_ACCEPT;
	struct kz_service *svc = kzorp->svc;

	if (svc != NULL && svc->type == KZ_SERVICE_DENY) {
		if (kzorp->sid == 0) {
			if (!service_assign_session_id(ct, kzorp))
				return NF_DROP;
		}

		/* Only deny services are processed on INPUT */
		verdict = process_denied_session(NF_INET_PRE_ROUTING, skb, in, l3proto, l4proto, sport, dport, ct, kzorp);
	}

	return verdict;
}

static unsigned int
kz_forward_newconn_verdict(struct sk_buff *skb,
			   const struct net_device *in,
			   u8 l3proto, u8 l4proto,
			   u16 sport, u16 dport,
			   const struct nf_conn *ct,
			   const struct nf_conntrack_kzorp *kzorp)
{
	unsigned int verdict = NF_ACCEPT;
	struct kz_service *svc = kzorp->svc;

	bool new_session = false;

	if (svc != NULL) {

		/* forwarded and denied session have their session id assigned on forward */
		if (kzorp->sid == 0) {
			if (!service_assign_session_id(ct, kzorp))
				return NF_DROP;

			new_session = true;
		}

		switch (svc->type) {
		case KZ_SERVICE_FORWARD:
			/* log new sessions */
			if (new_session) {
				kz_session_log("Starting forwarded session",
						kzorp->svc, l3proto, l4proto,
						kzorp->czone, kzorp->szone, skb,
						sport, dport);
			}
			break;

		case KZ_SERVICE_DENY:
			verdict = process_denied_session(NF_INET_FORWARD, skb, in, l3proto, l4proto,
							 sport, dport, ct, kzorp);
			break;

		default:
			/* do nothing */
			break;
		}
	}

	return verdict;
}


static unsigned int
kz_postrouting_newconn_verdict(struct sk_buff *skb,
			       const struct net_device *in,
			       const struct net_device *out,
			       const struct kz_config *cfg,
			       u8 l3proto,
			       u8 l4proto,
			       u16 sport, u16 dport,
			       struct nf_conn *ct,
			       const struct nf_conntrack_kzorp *kzorp,
			       const struct xt_kzorp_target_info *tgi)
{
	struct kz_dispatcher *dpt = kzorp->dpt; 
	struct kz_service *svc = kzorp->svc;
	struct kz_zone *szone = kzorp->szone;

	if (dpt != NULL && svc != NULL) {
		if (svc->type == KZ_SERVICE_FORWARD)
			return process_forwarded_session(NF_INET_POST_ROUTING, skb, in, out, cfg,
							 l3proto, l4proto, sport, dport,
							 ct, IP_CT_NEW,
							 &szone, svc);
	}

	return NF_ACCEPT;
}

static unsigned int
kzorp_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_kzorp_target_info * const tgi = par->targinfo;
	const struct net_device * const in = par->in;
	const struct net_device * const out = par->out;

	unsigned int verdict = NF_ACCEPT;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	const struct nf_conntrack_kzorp *kzorp;
	struct nf_conntrack_kzorp local_kzorp;
	const struct kz_config *cfg = NULL;
	u_int8_t l4proto = 0;
	struct {
		u16 src;
		u16 dst;
	} __attribute__((packed)) *ports, _ports = { .src = 0, .dst = 0, };

	ports = &_ports;

	ct = nf_ct_get(skb, &ctinfo);
	/* no conntrack or this is a reply packet: we simply accept it
	   we don't want to mark the reply packages with tproxy mark
	   in iptables there could be a condition so reply does not get here
	   at all -- for that here a warning could be emitted, preferably
	   only once.  but that means slightly worse performance, so
	   the former bahavior is kept.*/
	if (ct == NULL || nf_ct_is_untracked(ct) || ctinfo >= IP_CT_IS_REPLY)
		return NF_ACCEPT;

	switch (par->family) {
	case NFPROTO_IPV4:
	{
		const struct iphdr * const iph = ip_hdr(skb);

		l4proto = iph->protocol;

		if ((l4proto == IPPROTO_TCP) || (l4proto == IPPROTO_UDP)) {
			ports = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(_ports), &_ports);
			if (unlikely(ports == NULL)) {
				/* unexpected ill case */
				kz_debug("failed to get ports, dropped packet; src='%pI4', dst='%pI4'\n",
					 &iph->saddr, &iph->daddr);
				return NF_DROP;
			}
		}

		kz_debug("kzorp hook processing packet: hook='%u', protocol='%u', src='%pI4:%u', dst='%pI4:%u'\n",
			 par->hooknum, l4proto, &iph->saddr, ntohs(ports->src), &iph->daddr, ntohs(ports->dst));
	}
		break;
	case NFPROTO_IPV6:
	{
		const struct ipv6hdr * const iph = ipv6_hdr(skb);
		int thoff;
		u8 tproto = iph->nexthdr;

		/* find transport header */
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0) )
		__be16 frag_offp;
		thoff = ipv6_skip_exthdr(skb, sizeof(*iph), &tproto, &frag_offp);
#else
		thoff = ipv6_skip_exthdr(skb, sizeof(*iph), &tproto);
#endif
		if (unlikely(thoff < 0)) {
			kz_debug("unable to find transport header in IPv6 packet, dropped; src='%pI6c', dst='%pI6c'\n",
			         &iph->saddr, &iph->daddr);
			return NF_DROP;
		}

		l4proto = tproto;

		if ((l4proto == IPPROTO_TCP) || (l4proto == IPPROTO_UDP)) {
			/* get info from transport header */
			ports = skb_header_pointer(skb, thoff, sizeof(_ports), &_ports);
			if (unlikely(ports == NULL)) {
				kz_debug("failed to get ports, dropped packet; src='%pI6c', dst='%pI6c'\n",
					 &iph->saddr, &iph->daddr);
				return NF_DROP;
			}
		}

		kz_debug("kzorp hook processing packet: hook='%u', protocol='%u', src='%pI6c:%u', dst='%pI6c:%u'\n",
			 par->hooknum, l4proto, &iph->saddr, ntohs(ports->src), &iph->daddr, ntohs(ports->dst));
	}
		break;
	default:
		BUG();
	}

	rcu_read_lock();
	kz_extension_get_from_ct_or_lookup(skb, in, par->family, &local_kzorp, &kzorp, &cfg);

	kz_debug("lookup data for kzorp hook; dpt='%s', client_zone='%s', server_zone='%s', svc='%s'\n",
		 kzorp->dpt ? kzorp->dpt->name : kz_log_null,
		 kzorp->czone ? kzorp->czone->name : kz_log_null,
		 kzorp->szone ? kzorp->szone->name : kz_log_null,
		 kzorp->svc ? kzorp->svc->name : kz_log_null);

	switch (par->hooknum)
	{
	case NF_INET_PRE_ROUTING:
		verdict = kz_prerouting_verdict(skb, in, out, cfg,
						par->family, l4proto,
						ports->src, ports->dst, 
						ctinfo, ct, kzorp, tgi);
		break;
	case NF_INET_LOCAL_IN:
		if (ctinfo == IP_CT_NEW)
			verdict = kz_input_newconn_verdict(skb, in, par->family, l4proto,
							   ports->src, ports->dst,
							   ct, kzorp);
		break;
	case NF_INET_FORWARD:
		if (ctinfo == IP_CT_NEW)
			verdict = kz_forward_newconn_verdict(skb, in, par->family, l4proto,
							     ports->src, ports->dst,
							     ct, kzorp);
		break;
	case NF_INET_POST_ROUTING:
		if (ctinfo == IP_CT_NEW)
			verdict = kz_postrouting_newconn_verdict(skb, in, out, cfg,
								 par->family, l4proto,
								 ports->src, ports->dst,
								 ct, kzorp, tgi);
		break;
	default:
		BUG();
		break;
	}

	if (kzorp == &local_kzorp)
		kz_destroy_kzorp(&local_kzorp);
	rcu_read_unlock();

	return verdict;
}


static int kzorp_tg_check(const struct xt_tgchk_param *par)
{
	const struct xt_kzorp_target_info * const tgi = par->targinfo;

	/* flags can be used in the future to support extension vithout versioning */
	if (tgi->flags != 0)
		return -EINVAL;

/* it would be better to check for -p (TCP | UDP)
   but that switch only supports a single protocol

   we accept everything here until a more suitable check emerges
*/
	return 0;
}

static struct xt_target kzorp_tg_reg[] __read_mostly = {
	{
		.name		= "KZORP",
		.family		= AF_INET,
		.table		= "mangle",
		.target		= kzorp_tg,
		.targetsize	= sizeof(struct xt_kzorp_target_info),
		.checkentry	= kzorp_tg_check,
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_IN) |
				  (1 << NF_INET_FORWARD) |
				  (1 << NF_INET_POST_ROUTING),
		.me		= THIS_MODULE,
	},
	{
		.name		= "KZORP",
		.family		= AF_INET6,
		.table		= "mangle",
		.target		= kzorp_tg,
		.targetsize	= sizeof(struct xt_kzorp_target_info),
		.checkentry	= kzorp_tg_check,
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_IN) |
				  (1 << NF_INET_FORWARD) |
				  (1 << NF_INET_POST_ROUTING),
		.me		= THIS_MODULE,
	},
};

static int __init kzorp_tg_init(void)
{
	nf_defrag_ipv4_enable();
	return xt_register_targets(kzorp_tg_reg, ARRAY_SIZE(kzorp_tg_reg));
}

static void __exit kzorp_tg_exit(void)
{
	xt_unregister_targets(kzorp_tg_reg, ARRAY_SIZE(kzorp_tg_reg));
}

module_init(kzorp_tg_init);
module_exit(kzorp_tg_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Krisztian Kovacs <hidden@balabit.com>");
MODULE_DESCRIPTION("Netfilter KZorp target module.");
MODULE_ALIAS("ipt_KZORP");
MODULE_ALIAS("ip6t_KZORP");
