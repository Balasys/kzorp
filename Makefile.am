SUBDIRS = debian munin_plugins pylib daemon scripts tests
DIST_SUBDIRS = $(SUBDIRS)

EXTRA_DIST = VERSION driver dist.conf

DRIVER_SUBDIR = driver

all-driver:
	cd $(DRIVER_SUBDIR) && $(MAKE) $(AM_MAKEFLAGS) all
check-driver:
	cd $(DRIVER_SUBDIR) && $(MAKE) $(AM_MAKEFLAGS) check
clean-driver:
	cd $(DRIVER_SUBDIR) && $(MAKE) $(AM_MAKEFLAGS) clean
install-driver:
	cd $(DRIVER_SUBDIR) && $(MAKE) $(AM_MAKEFLAGS) install
uninstall-driver:
	cd $(DRIVER_SUBDIR) && $(MAKE) $(AM_MAKEFLAGS) uninstall
