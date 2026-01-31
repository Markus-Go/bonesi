#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([BoNeSi],[0.3.2],[Markus-Go@users.noreply.github.com])
AM_INIT_AUTOMAKE
AC_CONFIG_FILES([Makefile src/Makefile man/Makefile])
AC_OUTPUT
AC_CONFIG_SRCDIR([src/bonesi.c])
AC_CONFIG_HEADERS([config.h])


# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB(pcap, pcap_open_live)
AC_CHECK_LIB(pthread, pthread_create)
AC_CHECK_LIB(net, libnet_init)

# Checks for header files.
# Autoupdate added the next two lines to ensure that your configure
# script's behavior did not change.  They are probably safe to remove.
AC_CHECK_INCLUDES_DEFAULT
AC_PROG_EGREP

AC_CHECK_HEADERS([stdlib.h string.h unistd.h pthread.h pcap.h libnet.h],,AC_MSG_ERROR(header missing))

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_HEADERS_ONCE([sys/time.h])

AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([bzero gettimeofday strncasecmp strrchr])

AC_OUTPUT
