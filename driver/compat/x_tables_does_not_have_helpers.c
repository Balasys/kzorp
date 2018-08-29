#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/netfilter/x_tables.h>

int init_module(void)
{
	xt_in(NULL);
	xt_out(NULL);
	xt_hooknum(NULL);
	xt_family(NULL);
	xt_net(NULL);

	return 0;
}

void cleanup_module(void)
{
}
