#include <linux/module.h>
#include <linux/kernel.h>

#include <net/inet_hashtables.h>
#include <net/inet6_hashtables.h>

int init_module(void)
{
	inet_lookup(NULL, NULL, NULL, 0, 0, 0, 0, 0, 0);
	inet6_lookup(NULL, NULL, NULL, 0, NULL, 0, NULL, 0, 0);

	return 0;
}

void cleanup_module(void)
{
}
