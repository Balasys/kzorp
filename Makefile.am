SUBDIRS = munin_plugins pylib daemon scripts
DIST_SUBDIRS = $(SUBDIRS) driver

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
