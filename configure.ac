AC_INIT([kzorp], m4_esyscmd([tr -d '\n' < VERSION]))
AC_CONFIG_SRCDIR([driver/kzorp_core.c])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
AM_SILENT_RULES([yes])

AC_PROG_INSTALL
AC_PROG_CC
AM_PROG_CC_C_O

m4_define_default([_AM_PYTHON_INTERPRETER_LIST], [python2.7])
AM_PATH_PYTHON

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

KZORP_PYTHON_DIR="${pythondir}/kzorp"
ZORP_PYTHON_DIR="${pythondir}/Zorp"

KZORP_MUNIN_CONF_DIR="${sysconfdir}/munin/plugin-conf.d"
KZORP_MUNIN_DIR="${prefix}/share/munin/plugins"

AC_SUBST([PYTHON])
AC_SUBST(KZORP_MUNIN_CONF_DIR)
AC_SUBST(KZORP_MUNIN_DIR)
AC_SUBST(KZORP_PYTHON_DIR)
AC_SUBST(ZORP_PYTHON_DIR)

AC_CONFIG_FILES([
Makefile
daemon/Makefile
debian/Makefile
debian/source/Makefile
driver/tests/Makefile
driver/tests/communication/Makefile
driver/tests/query/Makefile
munin_plugins/Makefile
scripts/Makefile
pylib/Makefile
pylib/kzorp/Makefile
pylib/Zorp/Makefile
tests/Makefile
tests/python/Makefile
])
AC_OUTPUT
