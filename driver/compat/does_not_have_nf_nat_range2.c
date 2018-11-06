#include <linux/module.h>
#include <linux/kernel.h>

#include <net/netfilter/nf_nat.h>

int init_module(void)
{
	struct nf_nat_range2 test;

	return 0;
}

void cleanup_module(void)
{
}
