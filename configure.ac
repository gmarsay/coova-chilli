#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])
AC_INIT([coova-chilli],[1.8],[https://github.com/coova/coova-chilli/issues])
AC_CONFIG_SRCDIR([src/chilli.c])

AM_INIT_AUTOMAKE

AC_CONFIG_HEADERS([config.h])

AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CC_C_O
AC_PROG_CC_C99
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

LT_INIT
AC_ARG_PROGRAM

# Checks for libraries.

if test -r /dev/bpf -o -h /dev/bpf ; then
  V_DEV=bpf
  AC_DEFINE(HAVE_CLONING_BPF,1,[define if you have a cloning BPF device])
elif test -r /dev/bpf0 ; then
  V_DEV=bpf
elif test -r /usr/include/net/pfilt.h ; then
  V_DEV=pf
elif test -r /dev/enet ; then
  V_DEV=enet
elif test -r /dev/nit ; then
  V_DEV=snit
elif test -r /usr/include/sys/net/nit.h ; then
  V_DEV=nit
elif test -r /usr/include/linux/socket.h ; then
  V_DEV=linux
elif test -r /usr/include/net/raw.h ; then
  V_DEV=snoop
elif test -r /usr/include/odmi.h ; then
  V_DEV=bpf
elif test -c /dev/bpf0 ; then # check again in case not readable
  V_DEV=bpf
elif test -r /usr/include/sys/dlpi.h ; then
  V_DEV=dlpi
elif test -c /dev/enet ; then # check again in case not readable
  V_DEV=enet
elif test -c /dev/nit ; then # check again in case not readable
  V_DEV=snit
else
  V_DEV=null
fi
AC_MSG_RESULT($V_DEV)

# Do capture-mechanism-dependent tests.
case "$V_DEV" in
linux)
	AC_LBL_TPACKET_STATS
	AC_LBL_LINUX_TPACKET_AUXDATA_TP_VLAN_TCI
	;;
esac

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_RESOLV
AC_CHECK_HEADERS([arpa/inet.h errno.h fcntl.h dirent.h \
		  inttypes.h limits.h \
		  netdb.h netinet/in.h netinet/tcp.h \
		  stdint.h stddef.h stdlib.h string.h strings.h \
		  sys/ioctl.h sys/socket.h linux/sysinfo.h sys/sysinfo.h \
		  sys/param.h sys/time.h time.h \
		  sys/ipc.h sys/msg.h signal.h \
		  sys/wait.h sys/un.h ifaddrs.h \
		  sys/stat.h sys/types.h regex.h \
		  syslog.h poll.h sys/epoll.h \
		  unistd.h endian.h libgen.h \
		  asm/types.h pwd.h grp.h wchar.h stdarg.h])

AC_CHECK_HEADERS([resolv.h net/route.h net/if.h net/if_arp.h net/if_tun.h net/ethernet.h], [], [],
[
#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
])

AC_CHECK_HEADER(inttypes.h,[AC_DEFINE([JSON_C_HAVE_INTTYPES_H],[1],[Public define for json_inttypes.h])])
AC_CONFIG_HEADER(json/json_config.h)
AC_CHECK_DECLS([INFINITY], [], [], [[#include <math.h>]])
AC_CHECK_DECLS([nan], [], [], [[#include <math.h>]])
AC_CHECK_DECLS([isnan], [], [], [[#include <math.h>]])
AC_CHECK_DECLS([isinf], [], [], [[#include <math.h>]])
AC_CHECK_DECLS([_isnan], [], [], [[#include <float.h>]])
AC_CHECK_DECLS([_finite], [], [], [[#include <float.h>]])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])


# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_MKTIME
AC_FUNC_MMAP
AC_CHECK_FUNCS([bzero clock_gettime dup2 gethostbyname getprotoent gettimeofday inet_ntoa \
memchr memmove memset mkdir munmap regcomp select setenv socket strcasecmp \
strchr strcspn strdup strerror strncasecmp strndup strrchr strspn strstr strtol getline dirname \
glob getaddrinfo getnameinfo getifaddrs sysinfo strlcpy tzset snprintf vsnprintf vasprintf])
AC_CHECK_LIB(resolv, res_init)

dnl libbstring (Better String Library): required, via pkg-config module "bstring".
dnl See https://github.com/msteinert/bstring — set PKG_CONFIG_PATH if installed in a prefix.
AC_PATH_PROG([PKG_CONFIG], [pkg-config])
AS_IF([test "x$PKG_CONFIG" = x], [
  AC_MSG_ERROR([pkg-config is required to locate libbstring])])
AC_MSG_CHECKING([for libbstring via pkg-config])
AS_IF([$PKG_CONFIG --exists bstring], [
  AC_MSG_RESULT([yes])
  BSTRING_CFLAGS=`$PKG_CONFIG --cflags bstring`
  BSTRING_LIBS=`$PKG_CONFIG --libs bstring`
], [
  AC_MSG_RESULT([no])
  AC_MSG_ERROR([pkg-config module bstring not found; install libbstring (e.g. msteinert/bstring) and ensure bstring.pc is on PKG_CONFIG_PATH])])
AC_SUBST([BSTRING_CFLAGS])
AC_SUBST([BSTRING_LIBS])

dnl === Feature set (fixed): former stock defaults + always-on largelimits & JSON + bundled json/ ===
AC_DEFINE([ENABLE_CHILLIQUERY], [1], [Define to enable chilli_query])
AM_CONDITIONAL([WITH_CHILLIQUERY], [test yes = yes])

AC_DEFINE([ENABLE_LEAKYBUCKET], [1], [Define to enable Chilli Leaky Bucket shaping])
AC_DEFINE([ENABLE_UAMUIPORT], [1], [Define to enable uamuiport])
AC_DEFINE([ENABLE_ACCOUNTING_ONOFF], [1], [Define to enable Accounting-On and Accounting-Off])
AC_DEFINE([ENABLE_TCPRESET], [1], [Define to enable TCP reset support])
AC_DEFINE([ENABLE_DEBUG], [1], [Define to enable debugging])
AC_DEFINE([ENABLE_DHCPRADIUS], [1], [Define to enable DHCP/RADIUS integration])
AC_DEFINE([ENABLE_COA], [1], [Define for CoA RADIUS support])
AC_DEFINE([ENABLE_COOVACHILLICONFIG], [1], [Define to enable the use of the CoovaChilli-Config attribute])
AC_DEFINE([ENABLE_LARGELIMITS], [1], [Enable larger limits for use with non-embedded systems])
AC_DEFINE([HAVE_SFHASH], [1], [Define to use SuperFastHash])
AM_CONDITIONAL([WITH_SFHASH], [test yes = yes])

AC_DEFINE([ENABLE_JSON], [1], [Define to enable Chilli JSON])
AC_CHECK_LIB([json-c], [json_object_new_object],
  [AC_SUBST([LIBJSON], ["-ljson-c"])],
  [AC_CHECK_LIB([json], [json_object_new_object],
    [AC_SUBST([LIBJSON], ["-ljson"])],
    [AC_MSG_ERROR([libjson-c or libjson is required for JSON support])])])
AM_CONDITIONAL([WITH_JSONLIB], [test yes = yes])

dnl OpenSSL (optional; default on)
AC_ARG_WITH([openssl],
 [AS_HELP_STRING([--without-openssl], [build without OpenSSL/TLS])], [],
 [with_openssl=yes])
AS_IF([test x"$with_openssl" != xno],
  [AC_CHECK_LIB([crypto], [CRYPTO_malloc],
    [AC_SUBST([LIBSSL], ["-lssl -lcrypto"])
     AC_DEFINE([HAVE_OPENSSL], [1], [Define if you have openssl])],
    [AC_MSG_FAILURE([OpenSSL not found; install OpenSSL or use --without-openssl])],
    [-lssl -lcrypto])],
  [AC_SUBST([LIBSSL], [])])
AM_CONDITIONAL([WITH_OPENSSL], [test x"$with_openssl" != xno])
AM_CONDITIONAL([WITH_SSL], [test x"$with_openssl" != xno])

dnl Coova netfilter kernel helpers (optional)
AC_ARG_WITH([nfcoova],
 [AS_HELP_STRING([--with-nfcoova], [Coova netfilter kernel module helpers])], [],
 [with_nfcoova=no])
AS_IF([test x"$with_nfcoova" != xno],
  [AC_DEFINE([HAVE_NETFILTER_COOVA], [1], [Define to use coova kernel module])])
AM_CONDITIONAL([WITH_NETFILTER_COOVA], [test x"$with_nfcoova" != xno])

AC_CHECK_LIB(rt, clock_gettime)

AM_CONDITIONAL([HAVE_STRLCPY], [test "x$ac_cv_func_strlcpy" = xyes])

AC_SUBST(sysconfdir)
AC_CONFIG_FILES([Makefile
		 conf/Makefile
		 doc/Makefile
		 json/Makefile
		 src/Makefile
		 src/mssl/Makefile
		 www/Makefile])

AC_OUTPUT
