# KBUILD is the path to the Linux kernel build tree.  It is usually the
# same as the kernel source tree, except when the kernel was compiled in
# a separate directory.
KBUILD ?= $(shell readlink -f /lib/modules/`uname -r`/build)

ifeq (,$(KBUILD))
$(error Kernel build tree not found - please set KBUILD to configured kernel)
endif

KCONFIG := $(KBUILD)/.config
ifeq (,$(wildcard $(KCONFIG)))
$(error No .config found in $(KBUILD), please set KBUILD to configured kernel)
endif

SRC_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

$(shell $(CC) $(SRC_DIR)/print_kernel_uts_release.c -I $(KBUILD)/include/ -o $(SRC_DIR)/print_kernel_uts_release)
KVERS := $(shell $(SRC_DIR)/print_kernel_uts_release)
$(info Build kZorp against kernel version $(KVERS))

INST_DIR = /lib/modules/$(KVERS)/kernel/net/netfilter

include $(KCONFIG)

EXTRA_CFLAGS += -I$(src)/include -I$(src)

PATCHED_UPSTREAM_MODULES = xt_socket_kzorp
PATCHED_UPSTREAM_OBJECTS = xt_socket_kzorp.o

MODULE_NAMES = kzorp xt_KZORP xt_rule xt_service xt_zone $(PATCHED_UPSTREAM_MODULES)

obj-m := kzorp.o xt_KZORP.o xt_rule.o xt_service.o xt_zone.o $(PATCHED_UPSTREAM_OBJECTS)
kzorp-y := kzorp_core.o kzorp_lookup.o kzorp_sockopt.o kzorp_netlink.o kzorp_ext.o

all: config_check modules

config_check:
	@if [ -z "$(CONFIG_NETFILTER_XT_TARGET_TPROXY)" ]; then \
		echo; echo; \
		echo "*** WARNING: This kernel lacks TPROXY Netfilter target."; \
		echo "kZorp will not work properly."; \
		echo; echo; \
	fi
	@if [ -z "$(CONFIG_NF_CONNTRACK_TIMESTAMP)" ]; then \
		echo; echo; \
		echo "*** WARNING: This kernel lacks TPROXY Netfilter target."; \
		echo "kZorp will not work properly."; \
		echo; echo; \
	fi
	@if [ -z "$(CONFIG_NETFILTER_NETLINK)" ]; then \
		echo; echo; \
		echo "*** WARNING: This kernel lacks Netfilter netlink support."; \
		echo "kZorp will not work properly."; \
		echo; echo; \
	fi
	@if [ -z "$(CONFIG_NF_CONNTRACK_EVENTS)" ]; then \
		echo; echo; \
		echo "*** WARNING: This kernel lacks conntrack entry event support."; \
		echo "kZorp will not work properly."; \
		echo; echo; \
	fi
	@if [ -z "$(CONFIG_X86_64)" ]; then \
		echo; echo; \
		echo "*** WARNING: This kernel compiled for non-x86 architecture"; \
		echo "kZorp is officially tested only on x86-64 platforms."; \
		echo; echo; \
	fi

compat_h:
	$(MAKE) -C compat KBUILD=$(KBUILD)

modules: compat_h
	$(MAKE) -C $(KBUILD) M=$(SRC_DIR)

clean:
	$(MAKE) -C compat clean
	rm -f *.o *.ko .*.cmd *.mod.c *.symvers modules.order *~ .\#*
	rm -rf .tmp_versions

install: config_check modules
	@for module in $(MODULE_NAMES); do \
		/sbin/modinfo $$module.ko | grep -q "^vermagic: *$(KVERS) " || \
			{ echo "$$module" is not for Linux $(KVERS); exit 1; }; \
	done
	mkdir -p -m 755 $(DESTDIR)$(INST_DIR)
	@for module in $(MODULE_NAMES); do \
		install -m 0644 $$module.ko $(DESTDIR)$(INST_DIR); \
	done
ifndef DESTDIR
	-/sbin/depmod -a $(KVERS)
endif

uninstall:
	@for module in $(MODULE_NAMES); do \
		rm -f $(DESTDIR)$(INST_DIR)/$$module.ko; \
	done
ifndef DESTDIR
	-/sbin/depmod -a $(KVERS)
endif

dist:
	@for file in $(DISTFILES); do \
		cp $$file $(distdir)/$$file || exit 1; \
	done

distclean:
	@for file in $(DISTFILES); do \
		rm -f $(distdir)/$$file; \
	done

check:
	$(MAKE) -C tests check

.PHONY: all modules clean install config_check dist distclean
