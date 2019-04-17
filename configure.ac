#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
# modified by rovo98

AC_PREREQ([2.69])
AC_INIT(beat.c)
AM_INIT_AUTOMAKE(beat, 1.0)

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h unistd.h pcap.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([socket])

AC_OUTPUT(Makefile)
