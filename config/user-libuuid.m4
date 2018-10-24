dnl #
dnl # Check for libuuid
dnl #
AC_DEFUN([ZFS_AC_CONFIG_USER_LIBUUID], [
	LIBUUID= 1
		  
#	AC_CHECK_HEADER([/sys/sys/uuid.h], [], [AC_MSG_ERROR([
#        *** uuid/uuid.h missing, libuuid-devel package required])])
		
#	AC_SEARCH_LIBS([uuid_create], [uuid], [], [AC_MSG_FAILURE([
#	*** uuid_generate() missing, libuuid-devel package required])])

#	AC_SEARCH_LIBS([uuid_is_nil], [uuid], [], [AC_MSG_FAILURE([
#	*** uuid_is_null() missing, libuuid-devel package required])])

	AC_SUBST([LIBUUID], ["-luuid"])
	AC_DEFINE([HAVE_LIBUUID], 1, [Define if you have libuuid])
])
