#include <linux/types.h>
#include <net/netfilter/nf_conntrack_zones.h>

void test_nf_ct_zone_id() {
	nf_ct_zone_id(NULL, 0);
}
