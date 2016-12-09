#include <net/addrconf.h>

void test_ipv4_rcv_saddr_equal() {
	ipv4_rcv_saddr_equal(NULL, NULL, false);
}
