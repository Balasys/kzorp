#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/skbuff.h>

int init_module(void)
{
	skb_ext_find(NULL, 0);

	return 0;
}

void cleanup_module(void)
{
}
