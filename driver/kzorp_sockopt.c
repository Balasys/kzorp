/*
 * KZorp getsockopt() interface
 *
 * Copyright (C) 2010-2015 BalaBit IT Security, 2015-2017 BalaSys IT Security.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include <net/inet_sock.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>
#include "kzorp.h"
#include "kzorp_sockopt.h"
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <linux/export.h>
#include <net/netfilter/nf_conntrack_zones.h>

static const char *const kz_log_null = "(NULL)";

#define COPY_NAME_TO_USER(dst, field, string)				\
	if (string != NULL) {						\
		size_t len = strlen(string) + 1;			\
		if (copy_to_user(dst + offsetof(struct kz_lookup_result, field), string, len) != 0) { \
			res = -EFAULT;					\
			goto error_put_ct;				\
		}							\
	}

#define COPY_NUM_TO_USER(dst, dst_field_name, num)				\
	if (copy_to_user(dst + offsetof(struct kz_lookup_result, dst_field_name), &(num), sizeof(num)) != 0) { \
		res = -EFAULT;					\
		goto error_put_ct;				\
	}

static int
kzorp_getsockopt_results(u8 family, struct sock *sk, int optval, void __user *user, int *len)
{
	const struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;

	if (sk->sk_protocol != IPPROTO_TCP && sk->sk_protocol != IPPROTO_UDP) {
		pr_debug("not a TCP or UDP socket; proto='%u'\n", sk->sk_protocol);
		return -ENOPROTOOPT;
	}

	switch (family) {
	case PF_INET:
		pr_debug("getting results; proto='%u', src='%pI4:%hu', dst='%pI4:%hu'\n", sk->sk_protocol,
			 &inet_sk(sk)->inet_rcv_saddr, ntohs(inet_sk(sk)->inet_sport), &inet_sk(sk)->inet_daddr, ntohs(inet_sk(sk)->inet_dport));
		break;
	case PF_INET6:
		pr_debug("getting results; proto='%u', src='%pI6c:%hu', dst='%pI6c:%hu'\n", sk->sk_protocol,
			 &inet6_sk(sk)->saddr, ntohs(inet_sk(sk)->inet_sport), inet6_sk(sk)->daddr_cache, ntohs(inet_sk(sk)->inet_dport));
		break;
	default:
		BUG();
	}

	if ((unsigned int) *len < sizeof(struct kz_lookup_result)) {
		pr_debug("buffer size is too small for the result; len='%d', required='%zu'\n", *len, sizeof(struct kz_lookup_result));
		return -EINVAL;
	}

	memset(&tuple, 0, sizeof(tuple));
	tuple.dst.protonum = sk->sk_protocol;
	tuple.src.u.tcp.port = inet_sk(sk)->inet_sport;
	tuple.dst.u.tcp.port = inet_sk(sk)->inet_dport;
	switch (family) {
	case PF_INET:
		tuple.src.l3num = AF_INET;
		tuple.src.u3.ip = sk->sk_rcv_saddr;
		tuple.dst.u3.ip = sk->sk_daddr;
		break;
	case PF_INET6:
		tuple.src.l3num = AF_INET6;
		tuple.src.u3.in6 = sk->sk_v6_rcv_saddr;
		tuple.dst.u3.in6 = sk->sk_v6_daddr;
		break;
	default:
		BUG();
	}

	h = nf_conntrack_find_get(sock_net(sk), &nf_ct_zone_dflt, &tuple);
	if (h) {
		struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);
		struct kz_extension *kzorp;
		u_int64_t cookie;
		int res = 0;

		rcu_read_lock_bh();
		kzorp = kz_extension_find(ct);
		if (kzorp == NULL) {
			pr_err("no kzorp extension structure found\n");
			res = -ENOENT;
			goto error_put_ct;
		}

		{
			/* we could waste space to store the coolie in kzorp but user is really interested
			   whether it is the current one, 0 indicates obsolete  */
			const struct kz_config *cfg = rcu_dereference(kz_config_rcu);
			cookie = kz_generation_valid(cfg, kzorp->generation) ? cfg->cookie : 0;
		}

		pr_debug("found kzorp results; client_zone='%s', server_zone='%s', dispatcher='%s', service='%s'\n",
			 kzorp->czone ? kzorp->czone->name : kz_log_null,
			 kzorp->szone ? kzorp->szone->name : kz_log_null,
			 kzorp->dpt ? kzorp->dpt->name : kz_log_null,
			 kzorp->svc ? kzorp->svc->name : kz_log_null);

		if (copy_to_user(user, &cookie, sizeof(cookie)) != 0) {
			res = -EFAULT;
			goto error_put_ct;
		}

		if (kzorp->czone)
			COPY_NAME_TO_USER(user, czone_name, kzorp->czone->name);
		if (kzorp->szone)
			COPY_NAME_TO_USER(user, szone_name, kzorp->szone->name);
		if (kzorp->dpt)
			COPY_NAME_TO_USER(user, dispatcher_name, kzorp->dpt->name);
		if (kzorp->svc)
			COPY_NAME_TO_USER(user, service_name, kzorp->svc->name);

		COPY_NUM_TO_USER(user, rule_id, kzorp->rule_id);

		kz_extension_put(kzorp);
error_put_ct:
		rcu_read_unlock_bh();
		nf_ct_put(ct);

		return res;
	}

	pr_err("conntrack entry not found\n");

	return -ENOENT;
}

static int
kzorp_getsockopt_results_v4(struct sock *sk, int optval, void __user *user, int *len)
{
	return kzorp_getsockopt_results(PF_INET, sk, optval, user, len);
}

static int
kzorp_getsockopt_results_v6(struct sock *sk, int optval, void __user *user, int *len)
{
	return kzorp_getsockopt_results(PF_INET6, sk, optval, user, len);
}

static struct nf_sockopt_ops so_kzorpresult[] = {
	{
		.pf		= PF_INET,
		.get_optmin	= SO_KZORP_RESULT,
		.get_optmax	= SO_KZORP_RESULT + 1,
		.get		= &kzorp_getsockopt_results_v4,
		.owner		= THIS_MODULE,
	},
	{
		.pf		= PF_INET6,
		.get_optmin	= SO_KZORP_RESULT,
		.get_optmax	= SO_KZORP_RESULT + 1,
		.get		= &kzorp_getsockopt_results_v6,
		.owner		= THIS_MODULE,
	},
};

int __init
kz_sockopt_init(void)
{
	int res;

	res = nf_register_sockopt(&so_kzorpresult[0]);
	if (res < 0)
		return res;

	res = nf_register_sockopt(&so_kzorpresult[1]);
	if (res < 0)
		nf_unregister_sockopt(&so_kzorpresult[0]);

	return res;
}

void
kz_sockopt_cleanup(void)
{
	nf_unregister_sockopt(&so_kzorpresult[1]);
	nf_unregister_sockopt(&so_kzorpresult[0]);
}
