#include <linux/module.h>
#include <linux/kernel.h>

#include <net/netlink.h>

int init_module(void)
{
	nla_put_u64_64bit(NULL, 0, 0, 0);

	return 0;
}

void cleanup_module(void)
{
}
