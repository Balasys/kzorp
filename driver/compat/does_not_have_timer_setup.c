#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/timer.h>

int init_module(void)
{
	timer_setup(NULL, NULL, 0);

	return 0;
}

void cleanup_module(void)
{
}
