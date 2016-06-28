/*
 * KZorp `service' match
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

#include <linux/netfilter/x_tables.h>
#include "xt_service.h"
#include "kzorp.h"

static bool
service_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	struct xt_service_info *info = (struct xt_service_info *) par->matchinfo;
	const struct kz_service *s_svc, *p_svc;
	const struct kz_config *cfg = NULL;
	struct kz_extension *kzorp;
	bool res = true;

	/* NOTE: unlike previous version, we provide match even for invalid and --notrack packets */

	rcu_read_lock();

	kzorp = kz_extension_find_or_evaluate(skb, par->in, par->family, &cfg);

	if ((p_svc = kzorp->svc) == NULL) {
		/* no service for this packet => no match */
		goto ret_false;
	}

	if (info->name_match == XT_SERVICE_NAME_MATCH) {
		/* check cached service id validity */
		if (unlikely(!kz_generation_valid(cfg, info->generation))) {
			pr_debug("looking up service id; name='%s'\n", info->name);
			/* id invalid, try to look up again */
			info->generation = kz_generation_get(cfg);
			s_svc = kz_service_lookup_name(cfg, info->name);
			if (s_svc != NULL)
				info->service_id = s_svc->id;
			else
				info->service_id = 0;

			pr_debug("lookup done; id='%u'\n", info->service_id);
		}
	}

	pr_debug("service lookup done; type='%d', id='%u'\n", p_svc->type, p_svc->id);

	if (info->type != XT_SERVICE_TYPE_ANY && p_svc->type != info->type)
		goto ret_false;

	if (info->name_match == XT_SERVICE_NAME_MATCH &&
	    p_svc->id != info->service_id)
		goto ret_false;

	if ((info->flags & XT_SERVICE_NOCOUNT) == 0)
		kz_service_count_inc(kzorp->svc);
	goto done;
ret_false:
	res = false;
done:
	rcu_read_unlock();
	kz_extension_put(kzorp);
	return res;
}

static bool
service_mt_v2(const struct sk_buff *skb, struct xt_action_param *par)
{
	return service_mt(skb, par);
}

static int
service_mt_checkentry(const struct xt_mtchk_param *par)
{
	struct xt_service_info *info = (struct xt_service_info *) par->matchinfo;

	info->name[XT_SERVICE_NAME_LENGTH] = 0;

	if ((info->name_match == XT_SERVICE_NAME_MATCH) &&
	    (info->name[0] == '\0'))
		return -EINVAL;

	if ((info->type == XT_SERVICE_TYPE_ANY) &&
	    (info->name_match == XT_SERVICE_NAME_ANY))
		return -EINVAL;

	if (info->type > XT_SERVICE_TYPE_DENY)
		return -EINVAL;

	if (info->name_match > XT_SERVICE_NAME_MATCH)
		return -EINVAL;

	info->generation = -1;
	info->service_id = 0;

	return 0;
}

static struct xt_match service_match[] = {
	{
		.family		= NFPROTO_IPV4,
		.name		= "service",
		.match		= service_mt,
		.matchsize	= sizeof(struct xt_service_info),
		.checkentry	= service_mt_checkentry,
		.me		= THIS_MODULE,
	},
	{
		.family		= NFPROTO_IPV6,
		.name		= "service",
		.match		= service_mt,
		.matchsize	= sizeof(struct xt_service_info),
		.checkentry	= service_mt_checkentry,
		.me		= THIS_MODULE,
	},
	{
		.family		= NFPROTO_IPV4,
		.name		= "service",
		.revision	= 2,
		.match		= service_mt_v2,
		.matchsize	= sizeof(struct xt_service_info_v2),
		.checkentry	= service_mt_checkentry,
		.me		= THIS_MODULE,
	},
	{
		.family		= NFPROTO_IPV6,
		.name		= "service",
		.revision	= 2,
		.match		= service_mt_v2,
		.matchsize	= sizeof(struct xt_service_info_v2),
		.checkentry	= service_mt_checkentry,
		.me		= THIS_MODULE,
	},

};

static int __init service_mt_init(void)
{
	return xt_register_matches(service_match, ARRAY_SIZE(service_match));
}

static void __exit service_mt_exit(void)
{
	xt_unregister_matches(service_match, ARRAY_SIZE(service_match));
}

MODULE_AUTHOR("Krisztian Kovacs <hidden@balabit.hu>");
MODULE_DESCRIPTION("kzorp service match");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_service");
MODULE_ALIAS("ip6t_service");

module_init(service_mt_init);
module_exit(service_mt_exit);
