#include <linux/module.h>
#include <linux/kernel.h>

#include <net/sock.h>
#include <linux/refcount.h>

static void check_type_refcount(refcount_t *r)
{
	r = NULL;
}

int init_module(void)
{
	struct sock *sk = NULL;

	check_type_refcount(&sk->sk_refcnt);

	return 0;
}

void cleanup_module(void)
{
}
