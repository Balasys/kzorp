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

if test -r $srcdir/dist.conf; then
        # read defaults, dist.conf does not change
        # values for parameters that are already set
        source $srcdir/dist.conf
fi

if test -n "$SNAPSHOT_VERSION"; then
        VERSION=$VERSION+$SNAPSHOT_VERSION
fi

CURRDATE=`date -R`

if test -z "$RELEASE_TAG"; then
    RELEASE_TAG=release
fi

VERSION_NOSNAPSHOT="`echo $VERSION | cut -d '+' -f 1 | cut -d '~' -f 1`"

VERSION_MAJOR=`echo $VERSION_NOSNAPSHOT |  cut -d '.' -f 1`
VERSION_MINOR=`echo $VERSION_NOSNAPSHOT |  cut -d '.' -f 2`
VERSION_COMPAT=`echo $VERSION_NOSNAPSHOT |  cut -d '.' -f 3`

ZORP_PYTHON_MIN_VERSION_MICRO="4"
ZORP_PYTHON_MIN_VERSION="$VERSION_MAJOR.$VERSION_MINOR.$ZORP_PYTHON_MIN_VERSION_MICRO"

NEXT_VERSION_MAJOR=$(($VERSION_MAJOR + 1))

AC_SUBST([PYTHON])
AC_SUBST(KZORP_MUNIN_CONF_DIR)
AC_SUBST(KZORP_MUNIN_DIR)
AC_SUBST(KZORP_PYTHON_DIR)
AC_SUBST(ZORP_PYTHON_DIR)
AC_SUBST(CURRDATE)
AC_SUBST(RELEASE_TAG)
AC_SUBST(ZORP_PYTHON_MIN_VERSION)
AC_SUBST(VERSION_MAJOR)
AC_SUBST(NEXT_VERSION_MAJOR)
AC_SUBST(SNAPSHOT_VERSION)

AC_CONFIG_FILES([
Makefile
dist.conf
daemon/Makefile
debian/Makefile
debian/control
debian/changelog
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
