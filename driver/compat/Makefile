$(eval HDR_ARCH ?= \
	$(shell uname -m | sed -e s/i.86/x86/ -e s/x86_64/x86/\
		-e s/sun4u/sparc64/ \
		-e s/arm.*/arm/ -e s/sa110/arm/ \
		-e s/s390x/s390/ -e s/parisc64/parisc/ \
		-e s/ppc.*/powerpc/ -e s/mips.*/mips/ \
		-e s/sh[234].*/sh/ -e s/aarch64.*/arm64/ \
	))
$(eval COMPAT_CPPFLAGS ?= \
	-DKBUILD_MODNAME \
	-isystem $(KBUILD)/include \
	-isystem $(KBUILD)/arch/${HDR_ARCH}/include/ \
	-isystem $(KBUILD)/arch/${HDR_ARCH}/include/generated/ \
	-isystem $(KBUILD)/include/uapi/ \
	-include $(KBUILD)/include/linux/kconfig.h \
)
$(eval COMPAT_CFLAGS ?= \
	-D__KERNEL__ \
)

all: compat_h

clean:
	rm -f *.h *.o

net_param_added_to_ip_local_functions.h: net_param_added_to_ip_local_functions.c
	truncate -s 0 net_param_added_to_ip_local_functions.h
	$(CC) $(COMPAT_CPPFLAGS) $(COMPAT_CFLAGS) -c net_param_added_to_ip_local_functions.c 2>/dev/null || \
	echo "#define NET_PARAM_ADDED_TO_IP_LOCAL_FUNCTIONS 1" > net_param_added_to_ip_local_functions.h

put_added_to_inet_twsk_deschedule.h: put_added_to_inet_twsk_deschedule.c
	truncate -s 0 put_added_to_inet_twsk_deschedule.h
	$(CC) $(COMPAT_CPPFLAGS) $(COMPAT_CFLAGS) -c -Werror=implicit-function-declaration put_added_to_inet_twsk_deschedule.c 2>/dev/null || \
	echo "#define PUT_ADDED_TO_INET_TWSK_DESCHEDULE 1" > put_added_to_inet_twsk_deschedule.h

skb_doff_added_to_lookup_listener_function.h: skb_doff_added_to_lookup_listener_function.c
	truncate -s 0 skb_doff_added_to_lookup_listener_function.h
	$(CC) $(COMPAT_CPPFLAGS) $(COMPAT_CFLAGS) -c skb_doff_added_to_lookup_listener_function.c 2>/dev/null || \
	echo "#define SKB_DOFF_ADDED_TO_LOOKUP_LISTENER_FUNCTIONS 1" > skb_doff_added_to_lookup_listener_function.h

nf_ct_zone_id.h: nf_ct_zone_id.c
	truncate -s 0 nf_ct_zone_id.h
	$(CC) $(COMPAT_CPPFLAGS) $(COMPAT_CFLAGS) -c nf_ct_zone_id.c 2>/dev/null || \
	echo "#define DIR_ADDED_NF_CT_ZONE 1" > nf_ct_zone_id.h

nf_conntrack_find_get.h: nf_conntrack_find_get.c
	truncate -s 0 nf_conntrack_find_get.h
	$(CC) $(COMPAT_CPPFLAGS) $(COMPAT_CFLAGS) -c -Werror nf_conntrack_find_get.c 2>/dev/null || \
	echo "#define ZONE_STRUCT_ADDED_NF_CONNTRACK_FIND_GET 1" > nf_conntrack_find_get.h


compat.h: \
		net_param_added_to_ip_local_functions.h \
		put_added_to_inet_twsk_deschedule.h \
		skb_doff_added_to_lookup_listener_function.h \
		nf_ct_zone_id.h \
		nf_conntrack_find_get.h

	cat \
	net_param_added_to_ip_local_functions.h \
	put_added_to_inet_twsk_deschedule.h \
	skb_doff_added_to_lookup_listener_function.h \
	nf_ct_zone_id.h \
	nf_conntrack_find_get.h \
	> compat.h

compat_h: compat.h
