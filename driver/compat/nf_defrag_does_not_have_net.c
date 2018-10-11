#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/netfilter.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#include <net/netfilter/ipv6/nf_defrag_ipv6.h>

int init_module(void)
{
	nf_defrag_ipv4_enable(NULL);
	nf_defrag_ipv6_enable(NULL);

	return 0;
}

void cleanup_module(void)
{
}
