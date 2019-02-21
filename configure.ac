#;*****************************************************************************;
# Copyright (c) 2018 Fraunhofer SIT sponsored by Infineon Technologies AG
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of tpm2-tss-engine nor the names of its contributors
# may be used to endorse or promote products derived from this software
# without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.
#;*****************************************************************************;
AC_PREREQ([2.68])

AC_INIT([tpm2-tss-engine],
        [1.0.0-rc0],
        [https://github.com/tpm2-software/tpm2-tss-engine/issues],
        [],
        [https://github.com/tpm2-software/tpm2-tss-engine])

dnl Avoid setting CFLAGS to anything by default; we use AC_CFLAGS below for this.
: ${CFLAGS=""}

dnl Let's be FHS-conform by default.
if test "$prefix" = '/usr'; then
    test "$sysconfdir" = '${prefix}/etc' && sysconfdir="/etc"
    test "$sharedstatedir" = '${prefix}/com' && sharedstatedir="/var"
    test "$localstatedir" = '${prefix}/var' && localstatedir="/var"
fi

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/tpm2-tss-engine.c])
AC_CONFIG_AUX_DIR([build-aux])

# propagate configure arguments to distcheck
AC_SUBST([DISTCHECK_CONFIGURE_FLAGS],[$ac_configure_args])

AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE([foreign subdir-objects -Wall -Wno-portability])
#Backward compatible setting of "silent-rules"
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])]) 
AM_MAINTAINER_MODE([enable])

AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O
LT_INIT()

AC_PROG_MKDIR_P
AC_PROG_LN_S

AC_ARG_ENABLE([debug],
            [AS_HELP_STRING([--enable-debug],
                            [build with debug output (default is no)])],
            [enable_debug=$enableval],
            [enable_debug=no])
AS_IF([test "x$enable_debug" != "xno"],
      AC_DEFINE_UNQUOTED([DEBUG], [1], ["Debug output enabled"]))

AC_ARG_ENABLE([tctienvvar],
    [AS_HELP_STRING([--enable-tctienvvar],
                        [Set the TCTI option from an environment variable])],
    [AC_DEFINE([ENABLE_TCTIENVVAR], [1])],
    )

AC_CONFIG_FILES([Makefile])

AX_ADD_COMPILER_FLAG([-std=c99])
AX_ADD_COMPILER_FLAG([-Wall])
AX_ADD_COMPILER_FLAG([-Wextra])
AX_ADD_COMPILER_FLAG([-Wformat-security])
AX_ADD_COMPILER_FLAG([-Werror])
AX_ADD_COMPILER_FLAG([-fstack-protector-all])
AX_ADD_COMPILER_FLAG([-fpic])
AX_ADD_COMPILER_FLAG([-fPIC])

# work around GCC bug #53119
#   https://gcc.gnu.org/bugzilla/show_bug.cgi?id=53119
AX_ADD_COMPILER_FLAG([-Wno-missing-braces])

AX_ADD_LINK_FLAG([-Wl,--no-undefined])
AX_ADD_LINK_FLAG([-Wl,-z,noexecstack])
AX_ADD_LINK_FLAG([-Wl,-z,now])
AX_ADD_LINK_FLAG([-Wl,-z,relro])

AX_CODE_COVERAGE
m4_ifdef([_AX_CODE_COVERAGE_RULES],
         [AM_CONDITIONAL(AUTOCONF_CODE_COVERAGE_2019_01_06, [true])],
         [AM_CONDITIONAL(AUTOCONF_CODE_COVERAGE_2019_01_06, [false])])
AX_ADD_AM_MACRO_STATIC([])

PKG_PROG_PKG_CONFIG([0.25])
PKG_CHECK_MODULES([CRYPTO], [libcrypto >= 1.0.2g],
                  [ac_enginesdir=`$PKG_CONFIG --variable=enginesdir libcrypto`])
PKG_CHECK_MODULES([TSS2_ESYS], [tss2-esys >= 2.2],
                  [AC_DEFINE(TSS22, [1], ["tpm2tss version >= 2.2"])],
                  [PKG_CHECK_MODULES([TSS2_ESYS],[tss2-esys])])

AC_PATH_PROG([PANDOC], [pandoc])
AS_IF([test -z "$PANDOC"],
    [AC_MSG_WARN([Required executable pandoc not found, man pages will not be built])])
AM_CONDITIONAL([HAVE_PANDOC],[test -n "$PANDOC"])
AM_CONDITIONAL([HAVE_MAN_PAGES],[test -d "${srcdir}/man/man1" -o -n "$PANDOC"])

AC_PATH_PROG([EXPECT], [expect])
AS_IF([test -z "$EXPECT"],
    [AC_MSG_WARN([Required executable expect not found, some tests might fail])])

AC_ARG_WITH([enginesdir], 
            [AS_HELP_STRING([--with-enginesdir],
                            [Set the OpenSSL engine directory (default: use pkg-config)])],
            [],
            [with_enginesdir=$ac_enginesdir])
AS_IF([test -z "$with_enginesdir"],
    [AC_MSG_WARN([Empty enginesdir, using $libdir/engines instead.])])
# This weirdness is necessary to enable distcheck via DISTCHECK_CONFIGURE_FLAGS
AS_IF([test -z "$with_enginesdir"],
    [with_enginesdir=$libdir/engines])
AC_SUBST(ENGINESDIR, "$with_enginesdir")

AC_ARG_WITH([completionsdir],
            [AS_HELP_STRING([--with-completionsdir],
                            [Set the bash completions directory (default: use pkg-config)])],
            [],
            [with_completionsdir=`$PKG_CONFIG --variable=completionsdir bash-completion`])
AS_IF([test -z "$with_completionsdir"],
    [AC_MSG_WARN([Empty completionsdir, using $datarootdir/bash-completion/completions instead.])])
AS_IF([test -z "$with_completionsdir"],
    [with_completionsdir=$datarootdir/bash-completion/completions])
AC_SUBST(completionsdir, "$with_completionsdir")

AC_ARG_ENABLE([unit],
            [AS_HELP_STRING([--enable-unit],
                            [build cmocka unit tests (default is no)])],
            [enable_unit=$enableval],
            [enable_unit=no])
AS_IF([test "x$enable_unit" != "xno" ], 
      [PKG_CHECK_MODULES([CMOCKA], [cmocka >= 1.0])])
AM_CONDITIONAL([UNIT], [test "x$enable_unit" != xno])

AC_ARG_ENABLE([integration],
            [AS_HELP_STRING([--enable-integration],
                            [build integration tests against TPM (default is no)])],
            [enable_integration=$enableval],
            [enable_integration=no])
AM_CONDITIONAL([INTEGRATION], [test "x$enable_integration" != xno])

AC_OUTPUT

AC_MSG_RESULT([
$PACKAGE_NAME $VERSION
    man-pages:      $PANDOC
    enginesdir:     $with_enginesdir
    completionsdir: $with_completionsdir
])
    
