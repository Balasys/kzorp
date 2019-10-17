PWD=$(shell pwd)

all: compat_h

clean:
	rm -Rf *.mod.c
	find . ! -name '*.c' ! -name Makefile -delete

does_not_have_timer_setup.h: does_not_have_timer_setup.c
	truncate -s 0 does_not_have_timer_setup.h
	make -C $(KBUILD) M=$(PWD) obj-m=does_not_have_timer_setup.o modules 2>/dev/null || \
	echo "#define KZ_COMP_DOES_NOT_HAVE_TIMER_SETUP 1" > does_not_have_timer_setup.h

inet_lookup_does_not_have_sdif.h: inet_lookup_does_not_have_sdif.c
	truncate -s 0 inet_lookup_does_not_have_sdif.h
	make -C $(KBUILD) M=$(PWD) obj-m=inet_lookup_does_not_have_sdif.o modules 2>/dev/null || \
	echo "#define KZ_COMP_INET_LOOKUP_DOES_NOT_HAVE_SDIF 1" > inet_lookup_does_not_have_sdif.h

does_not_have_refcount_inc_not_zero.h: does_not_have_refcount_inc_not_zero.c
	truncate -s 0 does_not_have_refcount_inc_not_zero.h
	make -C $(KBUILD) M=$(PWD) obj-m=does_not_have_refcount_inc_not_zero.o modules 2>/dev/null || \
	echo "#define KZ_COMP_DOES_NOT_HAVE_REFCOUNT_INC_NOT_ZERO 1" > does_not_have_refcount_inc_not_zero.h

nla_parse_nested_does_not_have_extack.h: nla_parse_nested_does_not_have_extack.c
	truncate -s 0 nla_parse_nested_does_not_have_extack.h
	make -C $(KBUILD) M=$(PWD) obj-m=nla_parse_nested_does_not_have_extack.o modules 2>/dev/null || \
	echo "#define KZ_COMP_NLA_PARSE_NESTED_DOES_NOT_HAVE_EXTACK 1" > nla_parse_nested_does_not_have_extack.h

x_tables_does_not_have_helpers.h: x_tables_does_not_have_helpers.c
	truncate -s 0 x_tables_does_not_have_helpers.h
	make -C $(KBUILD) M=$(PWD) obj-m=x_tables_does_not_have_helpers.o modules 2>/dev/null || \
	echo "#define KZ_COMP_X_TABLES_DOES_NOT_HAVE_HELPERS 1" > x_tables_does_not_have_helpers.h

nf_defrag_does_not_have_net.h: nf_defrag_does_not_have_net.c
	truncate -s 0 nf_defrag_does_not_have_net.h
	make -C $(KBUILD) M=$(PWD) obj-m=nf_defrag_does_not_have_net.o modules 2>/dev/null || \
	echo "#define KZ_COMP_NF_DEFRAG_DOES_NOT_HAVE_NET 1" > nf_defrag_does_not_have_net.h

inet_lookup_does_not_have_skb_doff.h: inet_lookup_does_not_have_skb_doff.c
	truncate -s 0 inet_lookup_does_not_have_skb_doff.h
	make -C $(KBUILD) M=$(PWD) obj-m=inet_lookup_does_not_have_skb_doff.o modules 2>/dev/null || \
	echo "#define KZ_COMP_INET_LOOKUP_DOES_NOT_HAVE_SKB_DOFF 1" > inet_lookup_does_not_have_skb_doff.h

does_not_have_nla_put_u64_64bit.h: does_not_have_nla_put_u64_64bit.c
	truncate -s 0 does_not_have_nla_put_u64_64bit.h
	make -C $(KBUILD) M=$(PWD) obj-m=does_not_have_nla_put_u64_64bit.o modules 2>/dev/null || \
	echo "#define KZ_COMP_DOES_NOT_HAVE_NLA_PUT_U64_64BIT 1" > does_not_have_nla_put_u64_64bit.h

does_not_have_nf_nat_range2.h: does_not_have_nf_nat_range2.c
	truncate -s 0 does_not_have_nf_nat_range2.h
	make -C $(KBUILD) M=$(PWD) obj-m=does_not_have_nf_nat_range2.o modules 2>/dev/null || \
	echo "#define KZ_COMP_DOES_NOT_HAVE_NF_NAT_RANGE2 1" > does_not_have_nf_nat_range2.h

does_not_have_nf_ct_hook.h: does_not_have_nf_ct_hook.c
	truncate -s 0 does_not_have_nf_ct_hook.h
	make -C $(KBUILD) M=$(PWD) obj-m=does_not_have_nf_ct_hook.o modules 2>/dev/null || \
	echo "#define KZ_COMP_DOES_NOT_HAVE_NF_CT_HOOK 1" > does_not_have_nf_ct_hook.h

does_have_nf_ct_free_hashtable.h: does_have_nf_ct_free_hashtable.c
	truncate -s 0 does_have_nf_ct_free_hashtable.h
	make -C $(KBUILD) M=$(PWD) obj-m=does_have_nf_ct_free_hashtable.o modules 2>/dev/null && \
	echo "#define KZ_COMP_DOES_HAVE_NF_CT_FREE_HASHTABLE 1" > does_have_nf_ct_free_hashtable.h || true

does_not_have_skb_ext_find.h: does_not_have_skb_ext_find.c
	truncate -s 0 does_not_have_skb_ext_find.h
	make -C $(KBUILD) M=$(PWD) obj-m=does_not_have_skb_ext_find.o modules 2>/dev/null || \
	echo "#define KZ_COMP_DOES_NOT_HAVE_SKB_EXT_FIND 1" > does_not_have_skb_ext_find.h

compat.h: \
		does_not_have_timer_setup.h \
		inet_lookup_does_not_have_sdif.h \
		does_not_have_refcount_inc_not_zero.h \
		nla_parse_nested_does_not_have_extack.h \
		x_tables_does_not_have_helpers.h \
		nf_defrag_does_not_have_net.h \
		inet_lookup_does_not_have_skb_doff.h \
		does_not_have_nla_put_u64_64bit.h \
		does_not_have_nf_nat_range2.h \
		does_not_have_nf_ct_hook.h \
		does_have_nf_ct_free_hashtable.h \
		does_not_have_skb_ext_find.h

	cat \
	does_not_have_timer_setup.h \
	inet_lookup_does_not_have_sdif.h \
	does_not_have_refcount_inc_not_zero.h \
	nla_parse_nested_does_not_have_extack.h \
	x_tables_does_not_have_helpers.h \
	nf_defrag_does_not_have_net.h \
	inet_lookup_does_not_have_skb_doff.h \
	does_not_have_nla_put_u64_64bit.h \
	does_not_have_nf_nat_range2.h \
	does_not_have_nf_ct_hook.h \
	does_have_nf_ct_free_hashtable.h \
	does_not_have_skb_ext_find.h \
	> compat.h

compat_h: compat.h
