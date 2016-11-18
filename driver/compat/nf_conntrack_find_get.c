#include <net/netfilter/nf_conntrack_core.h>

void test_nf_conntrack_find_get() {
	nf_conntrack_find_get(NULL, 1, NULL);
}
