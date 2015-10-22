/*
 * KZorp `zone' match
 *
 * Copyright (C) 2006-2011, BalaBit IT Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

#include <linux/netfilter/x_tables.h>
#include "xt_zone.h"
#include "kzorp.h"

static bool
zone_mt_v1_eval(const struct sk_buff *skb, const struct xt_zone_info_v1 *info, const struct xt_action_param *par)
{
	struct kz_zone *zone;
	const struct nf_conntrack_kzorp *kzorp;
	struct nf_conntrack_kzorp local_kzorp;
	int reply;
	bool res;

	rcu_read_lock();
	kz_extension_get_from_ct_or_lookup(skb, par->in, par->family, &local_kzorp, &kzorp, NULL);

	reply = skb->nfctinfo >= IP_CT_IS_REPLY;
	if (info->flags & IPT_ZONE_SRC)
		zone = reply ? kzorp->szone : kzorp->czone;
	else
		zone = reply ? kzorp->czone : kzorp->szone;

	while (zone != NULL) {
		int i;

		for (i = 0; i != info->count; ++i)
			if (strcmp(zone->name, info->names[i]) == 0)
				goto ret_true;

		if (info->flags & IPT_ZONE_CHILDREN)
			zone = zone->admin_parent;
		else
			zone = NULL;
	}

/* ret_false: */
	res = false;
	goto done;
ret_true:
	res = true;
	if ((info->flags & IPT_ZONE_NOCOUNT) == 0)
		kz_zone_count_inc(zone);
done:
	if (kzorp == &local_kzorp)
		kz_destroy_kzorp(&local_kzorp);
	rcu_read_unlock();
	return res;
}

static bool
zone_mt_v2(const struct sk_buff *skb, struct xt_action_param *par)
{
	return zone_mt_v1_eval(skb, (const struct xt_zone_info_v1 *) par->matchinfo, par);
}

static bool
zone_mt_v1(const struct sk_buff *skb, struct xt_action_param *par)
{
	return zone_mt_v1_eval(skb, (const struct xt_zone_info_v1 *) par->matchinfo, par);
}

static bool
zone_mt_v0(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_zone_info *oldinfo = (const struct xt_zone_info *) par->matchinfo;
	/* would be xt_zone_info_v1 directly, but that may exceed stack limit; we only need 1 entry*/
	unsigned char buf[16 + offsetof(struct xt_zone_info_v1, names) + sizeof(oldinfo->name)];
	struct xt_zone_info_v1 *info = (struct xt_zone_info_v1 *) &buf[0];

	info->flags = oldinfo->flags;
	info->count = 1;
	memcpy(info->names[0], oldinfo->name, sizeof(info->names[0]));

	return zone_mt_v1_eval(skb, info, par);
}

static struct xt_match xt_zone_match[] __read_mostly = {
	{
		.name		= "zone",
		.family		= NFPROTO_IPV4,
		.match		= zone_mt_v0,
		.matchsize	= sizeof(struct xt_zone_info),
		.me		= THIS_MODULE,
	},
	{
		.name		= "zone",
		.revision	= 1,
		.family		= NFPROTO_IPV4,
		.match		= zone_mt_v1,
		.matchsize	= sizeof(struct xt_zone_info_v1),
		.me		= THIS_MODULE,
	},
	{
		.name		= "zone",
		.revision	= 1,
		.family		= NFPROTO_IPV6,
		.match		= zone_mt_v1,
		.matchsize	= sizeof(struct xt_zone_info_v1),
		.me		= THIS_MODULE,
	},
	{
		.name		= "zone",
		.revision	= 2,
		.family		= NFPROTO_IPV4,
		.match		= zone_mt_v2,
		.matchsize	= sizeof(struct xt_zone_info_v1),
		.me		= THIS_MODULE,
	},
	{
		.name		= "zone",
		.revision	= 2,
		.family		= NFPROTO_IPV6,
		.match		= zone_mt_v2,
		.matchsize	= sizeof(struct xt_zone_info_v1),
		.me		= THIS_MODULE,
	},

};

static int __init zone_mt_init(void)
{
	return xt_register_matches(xt_zone_match, ARRAY_SIZE(xt_zone_match));
}

static void __exit zone_mt_exit(void)
{
	xt_unregister_matches(xt_zone_match, ARRAY_SIZE(xt_zone_match));
}

MODULE_AUTHOR("Krisztian Kovacs <hidden@balabit.hu>");
MODULE_DESCRIPTION("kzorp zone match");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_zone");
MODULE_ALIAS("ip6t_zone");

module_init(zone_mt_init);
module_exit(zone_mt_exit);
