#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT(ddoc, 1.0, rgonzale@darkterminal.net)
AM_INIT_AUTOMAKE(ddoc, 1.0)
AC_CONFIG_SRCDIR([src/main.c])
#AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h ncurses.h pthread.h pcap.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_FUNC_REALLOC
AC_CHECK_FUNCS([bzero inet_ntoa memset strcspn strstr])

AC_OUTPUT(Makefile src/Makefile)
