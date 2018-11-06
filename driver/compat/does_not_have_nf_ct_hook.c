#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/netfilter.h>

int init_module(void)
{
	struct nf_ct_hook test;

	return 0;
}

void cleanup_module(void)
{
}
