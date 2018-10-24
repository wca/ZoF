dnl #
dnl # Check for libblkid.  Basic support for detecting ZFS pools
dnl # has existing in blkid since 2008.
dnl #
AC_DEFUN([ZFS_AC_CONFIG_USER_LIBBLKID], [
	LIBBLKID=1

	AC_SUBST([LIBBLKID], ["-lblkid"])
	AC_DEFINE([HAVE_LIBBLKID], 1, [Define if you have libblkid])
])
