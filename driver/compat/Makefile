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

compat.h: \
		does_not_have_timer_setup.h \
		inet_lookup_does_not_have_sdif.h

	cat \
	does_not_have_timer_setup.h \
	inet_lookup_does_not_have_sdif.h \
	> compat.h

compat_h: compat.h
