#ifndef _NF_TPROXY_CORE_H
#define _NF_TPROXY_CORE_H

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/checksum.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <net/inet_sock.h>
#include <net/inet_hashtables.h>
#include <linux/inetdevice.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include <net/netfilter/ipv4/nf_defrag_ipv4.h>

#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
#define XT_TPROXY_HAVE_IPV6 1
#include <net/if_inet6.h>
#include <net/addrconf.h>
#include <net/inet6_hashtables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <net/netfilter/ipv6/nf_defrag_ipv6.h>
#endif

#include "kzorp_compat.h"
#include <linux/netfilter/xt_TPROXY.h>

enum nf_tproxy_lookup_t {
	NFT_LOOKUP_LISTENER,
	NFT_LOOKUP_ESTABLISHED,
};

static bool tproxy_sk_is_transparent(struct sock *sk)
{
	switch (sk->sk_state) {
	case TCP_TIME_WAIT:
		if (inet_twsk(sk)->tw_transparent)
			return true;
		break;
	case TCP_NEW_SYN_RECV:
		if (inet_rsk(inet_reqsk(sk))->no_srccheck)
			return true;
		break;
	default:
		if (inet_sk(sk)->transparent)
			return true;
	}

	sock_gen_put(sk);
	return false;
}

static inline __be32
tproxy_laddr4(struct sk_buff *skb, __be32 user_laddr, __be32 daddr)
{
	struct in_device *indev;
	__be32 laddr;

	if (user_laddr)
		return user_laddr;

	laddr = 0;
	indev = __in_dev_get_rcu(skb->dev);
	for_primary_ifa(indev) {
		laddr = ifa->ifa_local;
		break;
	} endfor_ifa(indev);

	return laddr ? laddr : daddr;
}

/*
 * This is used when the user wants to intercept a connection matching
 * an explicit iptables rule. In this case the sockets are assumed
 * matching in preference order:
 *
 *   - match: if there's a fully established connection matching the
 *     _packet_ tuple, it is returned, assuming the redirection
 *     already took place and we process a packet belonging to an
 *     established connection
 *
 *   - match: if there's a listening socket matching the redirection
 *     (e.g. on-port & on-ip of the connection), it is returned,
 *     regardless if it was bound to 0.0.0.0 or an explicit
 *     address. The reasoning is that if there's an explicit rule, it
 *     does not really matter if the listener is bound to an interface
 *     or to 0. The user already stated that he wants redirection
 *     (since he added the rule).
 *
 * Please note that there's an overlap between what a TPROXY target
 * and a socket match will match. Normally if you have both rules the
 * "socket" match will be the first one, effectively all packets
 * belonging to established connections going through that one.
 */
static inline struct sock *
nf_tproxy_get_sock_v4(struct net *net, struct sk_buff *skb, void *hp,
		      const u8 protocol,
		      const __be32 saddr, const __be32 daddr,
		      const __be16 sport, const __be16 dport,
		      const struct net_device *in,
		      const enum nf_tproxy_lookup_t lookup_type)
{
	struct sock *sk;
	struct tcphdr *tcph;

	switch (protocol) {
	case IPPROTO_TCP:
		switch (lookup_type) {
		case NFT_LOOKUP_LISTENER:
			tcph = hp;
			sk = kz_inet_lookup_listener(net, &tcp_hashinfo, skb,
						     ip_hdrlen(skb) +
						     kz___tcp_hdrlen(tcph),
						     saddr, sport,
						     daddr, dport,
						     in->ifindex, 0);

			if (sk && !kz_refcount_inc_not_zero(&sk->sk_refcnt))
				sk = NULL;
			/* NOTE: we return listeners even if bound to
			 * 0.0.0.0, those are filtered out in
			 * xt_socket, since xt_TPROXY needs 0 bound
			 * listeners too
			 */
			break;
		case NFT_LOOKUP_ESTABLISHED:
			sk = inet_lookup_established(net, &tcp_hashinfo,
						    saddr, sport, daddr, dport,
						    in->ifindex);
			break;
		default:
			BUG();
		}
		break;
	case IPPROTO_UDP:
		sk = udp4_lib_lookup(net, saddr, sport, daddr, dport,
				     in->ifindex);
		if (sk) {
			int connected = (sk->sk_state == TCP_ESTABLISHED);
			int wildcard = (inet_sk(sk)->inet_rcv_saddr == 0);

			/* NOTE: we return listeners even if bound to
			 * 0.0.0.0, those are filtered out in
			 * xt_socket, since xt_TPROXY needs 0 bound
			 * listeners too
			 */
			if ((lookup_type == NFT_LOOKUP_ESTABLISHED && (!connected || wildcard)) ||
			    (lookup_type == NFT_LOOKUP_LISTENER && connected)) {
				sock_put(sk);
				sk = NULL;
			}
		}
		break;
	default:
		WARN_ON(1);
		sk = NULL;
	}

	pr_debug("tproxy socket lookup: proto %u %08x:%u -> %08x:%u, lookup type: %d, sock %p\n",
		 protocol, ntohl(saddr), ntohs(sport), ntohl(daddr), ntohs(dport), lookup_type, sk);

	return sk;
}

#ifdef XT_TPROXY_HAVE_IPV6
static inline struct sock *
nf_tproxy_get_sock_v6(struct net *net, struct sk_buff *skb, int thoff, void *hp,
		      const u8 protocol,
		      const struct in6_addr *saddr, const struct in6_addr *daddr,
		      const __be16 sport, const __be16 dport,
		      const struct net_device *in,
		      const enum nf_tproxy_lookup_t lookup_type)
{
	struct sock *sk;
	struct tcphdr *tcph;

	switch (protocol) {
	case IPPROTO_TCP:
		switch (lookup_type) {
		case NFT_LOOKUP_LISTENER:
			tcph = hp;
			sk = kz_inet6_lookup_listener(net, &tcp_hashinfo, skb,
						      thoff + kz___tcp_hdrlen(tcph),
						      saddr, sport,
						      daddr, ntohs(dport),
						      in->ifindex, 0);

			if (sk && !kz_refcount_inc_not_zero(&sk->sk_refcnt))
				sk = NULL;
			/* NOTE: we return listeners even if bound to
			 * 0.0.0.0, those are filtered out in
			 * xt_socket, since xt_TPROXY needs 0 bound
			 * listeners too
			 */
			break;
		case NFT_LOOKUP_ESTABLISHED:
			sk = kz___inet6_lookup_established(net, &tcp_hashinfo,
							   saddr, sport, daddr, ntohs(dport),
							   in->ifindex, 0);
			break;
		default:
			BUG();
		}
		break;
	case IPPROTO_UDP:
		sk = udp6_lib_lookup(net, saddr, sport, daddr, dport,
				     in->ifindex);
		if (sk) {
			int connected = (sk->sk_state == TCP_ESTABLISHED);
			int wildcard = ipv6_addr_any(&sk->sk_v6_rcv_saddr);

			/* NOTE: we return listeners even if bound to
			 * 0.0.0.0, those are filtered out in
			 * xt_socket, since xt_TPROXY needs 0 bound
			 * listeners too
			 */
			if ((lookup_type == NFT_LOOKUP_ESTABLISHED && (!connected || wildcard)) ||
			    (lookup_type == NFT_LOOKUP_LISTENER && connected)) {
				sock_put(sk);
				sk = NULL;
			}
		}
		break;
	default:
		WARN_ON(1);
		sk = NULL;
	}

	pr_debug("tproxy socket lookup: proto %u %pI6c:%u -> %pI6c:%u, lookup type: %d, sock %p\n",
		 protocol, saddr, ntohs(sport), daddr, ntohs(dport), lookup_type, sk);

	return sk;
}
#endif

/**
 * tproxy_handle_time_wait4 - handle IPv4 TCP TIME_WAIT reopen redirections
 * @skb:	The skb being processed.
 * @laddr:	IPv4 address to redirect to or zero.
 * @lport:	TCP port to redirect to or zero.
 * @sk:		The TIME_WAIT TCP socket found by the lookup.
 *
 * We have to handle SYN packets arriving to TIME_WAIT sockets
 * differently: instead of reopening the connection we should rather
 * redirect the new connection to the proxy if there's a listener
 * socket present.
 *
 * tproxy_handle_time_wait4() consumes the socket reference passed in.
 *
 * Returns the listener socket if there's one, the TIME_WAIT socket if
 * no such listener is found, or NULL if the TCP header is incomplete.
 */
static struct sock *
tproxy_handle_time_wait4(struct net *net, struct sk_buff *skb,
			 __be32 laddr, __be16 lport, struct sock *sk)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct tcphdr _hdr, *hp;

	hp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(_hdr), &_hdr);
	if (hp == NULL) {
		inet_twsk_put(inet_twsk(sk));
		return NULL;
	}

	if (hp->syn && !hp->rst && !hp->ack && !hp->fin) {
		/* SYN to a TIME_WAIT socket, we'd rather redirect it
		 * to a listener socket if there's one */
		struct sock *sk2;

		sk2 = nf_tproxy_get_sock_v4(net, skb, hp, iph->protocol,
					    iph->saddr, laddr ? laddr : iph->daddr,
					    hp->source, lport ? lport : hp->dest,
					    skb->dev, NFT_LOOKUP_LISTENER);
		if (sk2) {
			inet_twsk_deschedule_put(inet_twsk(sk));
			sk = sk2;
		}
	}

	return sk;
}

/* assign a socket to the skb -- consumes sk */
static void
nf_tproxy_assign_sock(struct sk_buff *skb, struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = sock_edemux;
}

static unsigned int
tproxy_tg4(struct net *net, struct sk_buff *skb, __be32 laddr, __be16 lport,
	   u_int32_t mark_mask, u_int32_t mark_value)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct udphdr _hdr, *hp;
	struct sock *sk;

	hp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(_hdr), &_hdr);
	if (hp == NULL)
		return NF_DROP;

	/* check if there's an ongoing connection on the packet
	 * addresses, this happens if the redirect already happened
	 * and the current packet belongs to an already established
	 * connection */
	sk = nf_tproxy_get_sock_v4(net, skb, hp, iph->protocol,
				   iph->saddr, iph->daddr,
				   hp->source, hp->dest,
				   skb->dev, NFT_LOOKUP_ESTABLISHED);

	laddr = tproxy_laddr4(skb, laddr, iph->daddr);
	if (!lport)
		lport = hp->dest;

	/* UDP has no TCP_TIME_WAIT state, so we never enter here */
	if (sk && sk->sk_state == TCP_TIME_WAIT)
		/* reopening a TIME_WAIT connection needs special handling */
		sk = tproxy_handle_time_wait4(net, skb, laddr, lport, sk);
	else if (!sk)
		/* no, there's no established connection, check if
		 * there's a listener on the redirected addr/port */
		sk = nf_tproxy_get_sock_v4(net, skb, hp, iph->protocol,
					   iph->saddr, laddr,
					   hp->source, lport,
					   skb->dev, NFT_LOOKUP_LISTENER);

	/* NOTE: assign_sock consumes our sk reference */
	if (sk && tproxy_sk_is_transparent(sk)) {
		/* This should be in a separate target, but we don't do multiple
		   targets on the same rule yet */
		skb->mark = (skb->mark & ~mark_mask) ^ mark_value;

		pr_debug("redirecting: proto %hhu %pI4:%hu -> %pI4:%hu, mark: %x\n",
			 iph->protocol, &iph->daddr, ntohs(hp->dest),
			 &laddr, ntohs(lport), skb->mark);

		nf_tproxy_assign_sock(skb, sk);
		return NF_ACCEPT;
	}

	pr_debug("no socket, dropping: proto %hhu %pI4:%hu -> %pI4:%hu, mark: %x\n",
		 iph->protocol, &iph->saddr, ntohs(hp->source),
		 &iph->daddr, ntohs(hp->dest), skb->mark);
	return NF_DROP;
}

static inline unsigned int
tproxy_tg4_v0(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_tproxy_target_info *tgi = par->targinfo;

	return tproxy_tg4(xt_net(par), skb, tgi->laddr, tgi->lport,
			  tgi->mark_mask, tgi->mark_value);
}

static inline unsigned int
tproxy_tg4_v1(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_tproxy_target_info_v1 *tgi = par->targinfo;

	return tproxy_tg4(xt_net(par), skb, tgi->laddr.ip, tgi->lport,
			  tgi->mark_mask, tgi->mark_value);
}

static inline int
tproxy_tg4_check(const struct xt_tgchk_param *par)
{
	const struct ipt_ip *i = par->entryinfo;
	int err;

	err = kz_nf_defrag_ipv4_enable(par->net);
	if (err)
		return err;

	if ((i->proto == IPPROTO_TCP || i->proto == IPPROTO_UDP)
	    && !(i->invflags & IPT_INV_PROTO))
		return 0;

	pr_info_ratelimited("Can be used only with -p tcp or -p udp\n");
	return -EINVAL;
}

/* assign a socket to the skb -- consumes sk */
void
nf_tproxy_assign_sock(struct sk_buff *skb, struct sock *sk);

#endif
