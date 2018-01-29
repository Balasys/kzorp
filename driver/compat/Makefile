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

compat.h:
	touch compat.h

compat_h: compat.h
