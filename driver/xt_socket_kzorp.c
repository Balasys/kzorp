/*
 * Transparent proxy support for Linux/iptables
 *
 * Copyright (C) 2007-2015 BalaBit IT Security, 2015-2017 BalaSys IT Security.
 * Author: Krisztian Kovacs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>

#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <net/inet6_hashtables.h>
#include <net/netfilter/ipv6/nf_defrag_ipv6.h>
#endif

#include <net/netfilter/nf_socket.h>
#include <linux/netfilter/xt_socket_kzorp.h>

/* "socket" match based redirection (no specific rule)
 * ===================================================
 *
 * There are connections with dynamic endpoints (e.g. FTP data
 * connection) that the user is unable to add explicit rules
 * for. These are taken care of by a generic "socket" rule. It is
 * assumed that the proxy application is trusted to open such
 * connections without explicit iptables rule (except of course the
 * generic 'socket' rule). In this case the following sockets are
 * matched in preference order:
 *
 *   - match: if there's a fully established connection matching the
 *     _packet_ tuple
 *
 *   - match: if there's a non-zero bound listener (possibly with a
 *     non-local address) We don't accept zero-bound listeners, since
 *     then local services could intercept traffic going through the
 *     box.
 */
static bool
socket_match(const struct sk_buff *skb, struct xt_action_param *par,
	     const struct xt_socket_mtinfo1 *info)
{
	struct sock *sk = skb->sk;
	const struct net_device *dev =
		(xt_hooknum(par) == NF_INET_LOCAL_OUT) ? xt_out(par) : xt_in(par);

	if (!sk)
		sk = nf_sk_lookup_slow_v4(xt_net(par), skb, dev);
	if (sk) {
		bool wildcard;
		bool transparent = true;
		bool is_mark_matches = true;

		/* Ignore sockets listening on INADDR_ANY,
		 * unless XT_SOCKET_NOWILDCARD is set
		 */
		wildcard = (!(info->flags & XT_SOCKET_NOWILDCARD) &&
			    sk_fullsock(sk) &&
			    inet_sk(sk)->inet_rcv_saddr == 0);

		/* Ignore non-transparent sockets,
		 * if XT_SOCKET_TRANSPARENT is used
		 */
		if (info->flags & XT_SOCKET_TRANSPARENT)
			transparent = nf_sk_is_transparent(sk);

		if (info->flags & XT_SOCKET_MARK) {
			const struct xt_socket_mtinfo3 *mark_info = (struct xt_socket_mtinfo3 *) info;

			if (unlikely(sk->sk_state == TCP_TIME_WAIT))
				is_mark_matches = mark_info->invert;
			else
				is_mark_matches = ((sk->sk_mark & mark_info->mask) == mark_info->mark) ^ mark_info->invert;
		}

		if (sk != skb->sk)
			sock_gen_put(sk);

		if (wildcard || !transparent || !is_mark_matches)
			sk = NULL;
	}

	return sk != NULL;
}

static bool
socket_mt4_v0(const struct sk_buff *skb, struct xt_action_param *par)
{
	static struct xt_socket_mtinfo1 xt_info_v0 = {
		.flags = 0,
	};

	return socket_match(skb, par, &xt_info_v0);
}

static bool
socket_mt4_v1_v2_v3(const struct sk_buff *skb, struct xt_action_param *par)
{
	return socket_match(skb, par, par->matchinfo);
}

#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
static bool
socket_mt6_v1_v2_v3(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_socket_mtinfo1 *info = (struct xt_socket_mtinfo1 *) par->matchinfo;
	struct sock *sk = skb->sk;
	const struct net_device *dev =
		(xt_hooknum(par) == NF_INET_LOCAL_OUT) ? xt_out(par) : xt_in(par);

	if (!sk)
		sk = nf_sk_lookup_slow_v6(xt_net(par), skb, dev);
	if (sk) {
		bool wildcard;
		bool transparent = true;
		bool is_mark_matches = true;

		/* Ignore sockets listening on INADDR_ANY
		 * unless XT_SOCKET_NOWILDCARD is set
		 */
		wildcard = (!(info->flags & XT_SOCKET_NOWILDCARD) &&
			    sk_fullsock(sk) &&
			    ipv6_addr_any(&sk->sk_v6_rcv_saddr)
			   );

		/* Ignore non-transparent sockets,
		 * if XT_SOCKET_TRANSPARENT is used
		 */
		if (info->flags & XT_SOCKET_TRANSPARENT)
			transparent = nf_sk_is_transparent(sk);

		if (info->flags & XT_SOCKET_MARK) {
			const struct xt_socket_mtinfo3 *mark_info = (struct xt_socket_mtinfo3 *) info;

			if (unlikely(sk->sk_state == TCP_TIME_WAIT))
				is_mark_matches = mark_info->invert;
			else
				is_mark_matches = ((sk->sk_mark & mark_info->mask) == mark_info->mark) ^ mark_info->invert;
		}

		if (sk != skb->sk)
			sock_gen_put(sk);

		if (wildcard || !transparent || !is_mark_matches)
			sk = NULL;
	}

	return sk != NULL;
}
#endif

static int socket_mt_enable_defrag(struct net *net, int family)
{
	switch (family) {
	case NFPROTO_IPV4:
		return nf_defrag_ipv4_enable(net);
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	case NFPROTO_IPV6:
		return nf_defrag_ipv6_enable(net);
#endif
	}
	WARN_ONCE(1, "Unknown family %d\n", family);
	return 0;
}

static int socket_mt_v1_check(const struct xt_mtchk_param *par)
{
	const struct xt_socket_mtinfo1 *info = (struct xt_socket_mtinfo1 *) par->matchinfo;
	int err;

	err = socket_mt_enable_defrag(par->net, par->family);
	if (err)
		return err;

	if (info->flags & ~XT_SOCKET_FLAGS_V1) {
		pr_info_ratelimited("unknown flags 0x%x\n",
				    info->flags & ~XT_SOCKET_FLAGS_V1);
		return -EINVAL;
	}
	return 0;
}

static int socket_mt_v2_check(const struct xt_mtchk_param *par)
{
	const struct xt_socket_mtinfo2 *info = (struct xt_socket_mtinfo2 *) par->matchinfo;
	int err;

	err = socket_mt_enable_defrag(par->net, par->family);
	if (err)
		return err;

	if (info->flags & ~XT_SOCKET_FLAGS_V2) {
		pr_info_ratelimited("unknown flags 0x%x\n",
				    info->flags & ~XT_SOCKET_FLAGS_V2);
		return -EINVAL;
	}
	return 0;
}

static inline int socket_mt_check_flags(__u8 flags, __u8 valid_flags) {
	const __u8 invalid_flags = flags & ~valid_flags;

	if (invalid_flags) {
		pr_info_ratelimited("unknown flags 0x%x\n", invalid_flags);
		return -EINVAL;
	}
	return 0;
}

static int socket_mt_v3_check(const struct xt_mtchk_param *par) {
	const struct xt_socket_mtinfo3 *info = (struct xt_socket_mtinfo3 *) par->matchinfo;

	return socket_mt_check_flags(info->flags, XT_SOCKET_FLAGS_V3);
}

static struct xt_match socket_mt_reg[] __read_mostly = {
	{
		.name		= "socket_kzorp",
		.revision	= 0,
		.family		= NFPROTO_IPV4,
		.match		= socket_mt4_v0,
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_IN),
		.me		= THIS_MODULE,
	},
	{
		.name		= "socket_kzorp",
		.revision	= 1,
		.family		= NFPROTO_IPV4,
		.match		= socket_mt4_v1_v2_v3,
		.checkentry	= socket_mt_v1_check,
		.matchsize	= sizeof(struct xt_socket_mtinfo1),
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_IN),
		.me		= THIS_MODULE,
	},
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	{
		.name		= "socket_kzorp",
		.revision	= 1,
		.family		= NFPROTO_IPV6,
		.match		= socket_mt6_v1_v2_v3,
		.checkentry	= socket_mt_v1_check,
		.matchsize	= sizeof(struct xt_socket_mtinfo1),
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_IN),
		.me		= THIS_MODULE,
	},
#endif
	{
		.name		= "socket_kzorp",
		.revision	= 2,
		.family		= NFPROTO_IPV4,
		.match		= socket_mt4_v1_v2_v3,
		.checkentry	= socket_mt_v2_check,
		.matchsize	= sizeof(struct xt_socket_mtinfo1),
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_IN),
		.me		= THIS_MODULE,
	},
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	{
		.name		= "socket_kzorp",
		.revision	= 2,
		.family		= NFPROTO_IPV6,
		.match		= socket_mt6_v1_v2_v3,
		.checkentry	= socket_mt_v2_check,
		.matchsize	= sizeof(struct xt_socket_mtinfo1),
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_IN),
		.me		= THIS_MODULE,
	},
#endif
	{
		.name		= "socket_kzorp",
		.revision	= 3,
		.family		= NFPROTO_IPV4,
		.match		= socket_mt4_v1_v2_v3,
		.checkentry	= socket_mt_v3_check,
		.matchsize	= sizeof(struct xt_socket_mtinfo3),
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_IN) |
				  (1 << NF_INET_LOCAL_OUT),
		.me		= THIS_MODULE,
	},
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	{
		.name		= "socket_kzorp",
		.revision	= 3,
		.family		= NFPROTO_IPV6,
		.match		= socket_mt6_v1_v2_v3,
		.checkentry	= socket_mt_v3_check,
		.matchsize	= sizeof(struct xt_socket_mtinfo3),
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_IN) |
				  (1 << NF_INET_LOCAL_OUT),
		.me		= THIS_MODULE,
	},
#endif

};

static int __init socket_mt_init(void)
{
	return xt_register_matches(socket_mt_reg, ARRAY_SIZE(socket_mt_reg));
}

static void __exit socket_mt_exit(void)
{
	xt_unregister_matches(socket_mt_reg, ARRAY_SIZE(socket_mt_reg));
}

module_init(socket_mt_init);
module_exit(socket_mt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BalaSys Development Team <devel@balasys.hu>");
MODULE_DESCRIPTION("x_tables socket_kzorp match module");
MODULE_ALIAS("ipt_socket_kzorp");
MODULE_ALIAS("ip6t_socket_kzorp");
