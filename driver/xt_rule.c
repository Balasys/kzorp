/*
 * kZorp `rule' match
 *
 * Copyright (C) 2014, BalaBit IT Ltd.
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
#include "xt_rule.h"
#include "kzorp.h"

static bool
rule_mt_v0_eval(const struct sk_buff *skb, const struct ipt_rule_info_v0 *info, const struct xt_action_param *par)
{
	const struct nf_conntrack_kzorp *kzorp;
	struct nf_conntrack_kzorp local_kzorp;
	bool res = true;

	rcu_read_lock();
	kz_extension_get_from_ct_or_lookup(skb, par->in, par->family, &local_kzorp, &kzorp, NULL);
	rcu_read_unlock();

	if (info->flags & IPT_RULE_ID) {
		res &= (kzorp->rule_id == info->id);
	}
	kz_debug("match calculation has finished; flags='%x', rule_id='%d', result='%d'", info->flags, info->id, res);

	if (kzorp == &local_kzorp)
		kz_destroy_kzorp(&local_kzorp);

	return res;
}

static bool
rule_mt_v0(const struct sk_buff *skb, struct xt_action_param *par)
{
	return rule_mt_v0_eval(skb, (const struct ipt_rule_info_v0 *) par->matchinfo, par);
}

static struct xt_match xt_rule_match[] __read_mostly = {
	{
		.name		= "rule",
		.revision	= 0,
		.family		= NFPROTO_IPV4,
		.match		= rule_mt_v0,
		.matchsize	= sizeof(struct ipt_rule_info_v0),
		.me		= THIS_MODULE,
	},
	{
		.name		= "rule",
		.revision	= 0,
		.family		= NFPROTO_IPV6,
		.match		= rule_mt_v0,
		.matchsize	= sizeof(struct ipt_rule_info_v0),
		.me		= THIS_MODULE,
	},
};

static int __init rule_mt_init(void)
{
	return xt_register_matches(xt_rule_match, ARRAY_SIZE(xt_rule_match));
}

static void __exit rule_mt_exit(void)
{
	xt_unregister_matches(xt_rule_match, ARRAY_SIZE(xt_rule_match));
}

MODULE_AUTHOR("Szilárd Pfeiffer coroner@balabit.hu>");
MODULE_DESCRIPTION("kzorp rule match");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_rule");
MODULE_ALIAS("ip6t_rule");

module_init(rule_mt_init);
module_exit(rule_mt_exit);
