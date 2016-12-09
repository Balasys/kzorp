#include <net/inet_timewait_sock.h>

void test_inet_twsk_deschedule_put() {
#ifdef inet_twsk_for_each
	inet_twsk_deschedule(NULL, NULL);
#else
	inet_twsk_deschedule(NULL);
#endif
}
