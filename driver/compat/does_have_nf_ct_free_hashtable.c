#include <linux/module.h>
#include <linux/kernel.h>

#include <net/netfilter/nf_conntrack.h>

int init_module(void)
{
	nf_ct_free_hashtable(NULL, 0);

	return 0;
}

void cleanup_module(void)
{
}
