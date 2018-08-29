#include <linux/module.h>
#include <linux/kernel.h>

#include <net/netlink.h>

int init_module(void)
{
	nla_parse_nested(NULL, 0, NULL, NULL, NULL);

	return 0;
}

void cleanup_module(void)
{
}
