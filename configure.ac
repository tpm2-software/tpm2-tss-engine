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
        [1.1.0-rc1],
        [https://github.com/tpm2-software/tpm2-tss-engine/issues],
        [],
        [https://github.com/tpm2-software/tpm2-tss-engine])

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

AX_CHECK_ENABLE_DEBUG([info])

AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O
LT_INIT()

AC_PROG_MKDIR_P
AC_PROG_LN_S

AC_CONFIG_HEADERS([src/config.h])

AC_ARG_ENABLE([tctienvvar],
    [AS_HELP_STRING([--disable-tctienvvar],
                    [Disable setting the TCTI option from an environment variable])],,
    [enable_tctienvvar=yes])
AS_IF([test "x$enable_tctienvvar" = xyes], [AC_DEFINE([ENABLE_TCTIENVVAR], [1],
      'Enable getting TCTI from env variable')])

AC_CONFIG_FILES([Makefile])

AC_ARG_ENABLE([defaultflags],
              [AS_HELP_STRING([--disable-defaultflags],
                              [Disable default preprocessor, compiler, and linker flags.])],,
              [enable_defaultflags=yes])
AS_IF([test "x$enable_defaultflags" = "xyes"],
      [
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
      ])

AX_CODE_COVERAGE
m4_ifdef([_AX_CODE_COVERAGE_RULES],
         [AM_CONDITIONAL(AUTOCONF_CODE_COVERAGE_2019_01_06, [true])],
         [AM_CONDITIONAL(AUTOCONF_CODE_COVERAGE_2019_01_06, [false])])
AX_ADD_AM_MACRO_STATIC([])

PKG_PROG_PKG_CONFIG([0.25])
PKG_CHECK_MODULES([CRYPTO], [libcrypto >= 1.0.2g],
                  [ac_enginesdir=`$PKG_CONFIG --variable=enginesdir libcrypto`])
PKG_CHECK_MODULES([TSS2_ESYS], [tss2-esys >= 2.3])
PKG_CHECK_MODULES([TSS2_MU], [tss2-mu])
PKG_CHECK_MODULES([TSS2_TCTILDR], [tss2-tctildr])
AC_CHECK_LIB([crypto], EC_KEY_METHOD_set_compute_key,
      [AM_CONDITIONAL([HAVE_OPENSSL_ECDH], true)],
      [AM_CONDITIONAL([HAVE_OPENSSL_ECDH], false)])

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
                            [build cmocka unit tests])],,
            [enable_unit=no])
AS_IF([test "x$enable_unit" != "xno" ], 
      [PKG_CHECK_MODULES([CMOCKA], [cmocka >= 1.0])])
AM_CONDITIONAL([UNIT], [test "x$enable_unit" != xno])

AC_ARG_ENABLE([integration],
            [AS_HELP_STRING([--enable-integration],
                            [build integration tests against TPM])],,
            [enable_integration=no])
AM_CONDITIONAL([INTEGRATION], [test "x$enable_integration" != xno])

# Use physical TPM device for testing
AC_ARG_WITH([device],
            [AS_HELP_STRING([--with-device=<device>],[TPM device for testing])],
            [AS_IF([test \( -w "$with_device" \)  -a \( -r "$with_device" \)],
                   [AC_MSG_RESULT([success])
                    AX_NORMALIZE_PATH([with_device])
                    with_device_set=yes],
                   [AC_MSG_ERROR([TPM device provided does not exist or is not writable])])],
            [with_device_set=no])
AM_CONDITIONAL([TESTDEVICE],[test "x$with_device_set" = xyes])

# Integration test with simulator
AS_IF([test "x$enable_integration" = xyes && test "x$with_device_set" = xno],
      [integration_args=""
       AC_CHECK_PROG([tpm2_startup], [tpm2_startup], [yes])
       AS_IF([test "x$tpm2_startup" != xyes],
             [AC_MSG_ERROR([Integration tests require the tpm2_startup executable])])
       AC_CHECK_PROG([swtpm], [swtpm], [yes])
       AC_CHECK_PROG([tpm_server], [tpm_server], [yes])
       AS_IF([test "x$swtpm" != xyes && test "x$tpm_server" != xyes],
             [AC_MSG_ERROR([Integration tests require either the swtpm or the tpm_server executable])])
       AC_CHECK_PROG([realpath], [realpath], [yes])
       AS_IF([test "x$realpath" != xyes],
             [AC_MSG_ERROR([Integration tests require the realpath executable])])
       AC_CHECK_PROG([ss], [ss], [yes])
       AS_IF([test "x$ss" != xyes],
             [AC_MSG_ERROR([Integration tests require the ss executable])])
       AS_IF([test "x$enable_tctienvvar" != xyes],
             [AC_MSG_ERROR([Integration tests require building with TCTI environment variable support])])
       AC_SUBST([INTEGRATION_ARGS], [$integration_args])
      ])

# Integration test with physical device
AS_IF([test "x$enable_integration" = xyes &&  test "x$with_device_set" = xyes ],
      [integration_args="$with_device"
       AC_CHECK_PROG([realpath], [realpath], [yes])
       AS_IF([test "x$realpath" != xyes],
             [AC_MSG_ERROR([Integration tests require the realpath executable])])
       AS_IF([test "x$enable_tctienvvar" != xyes],
             [AC_MSG_ERROR([Integration tests require building with TCTI environment variable support])])
       AC_SUBST([INTEGRATION_ARGS], [$integration_args])
      ])

AX_VALGRIND_CHECK

#
# sanitizer compiler flags
#
AC_ARG_WITH([sanitizer],
            [AS_HELP_STRING([--with-sanitizer={none,address,undefined}],
                            [build with the given sanitizer])],,
            [with_sanitizer=none])
AS_CASE(["x$with_sanitizer"],
        ["xnone"],
        [],
        ["xaddress"],
        [
            SANITIZER_CFLAGS="-fsanitize=address -fno-omit-frame-pointer"
            SANITIZER_LDFLAGS="-lasan"
        ],
        ["xundefined"],
        [
            SANITIZER_CFLAGS="-fsanitize=undefined"
            SANITIZER_LDFLAGS="-lubsan"
        ],
        [AC_MSG_ERROR([Bad value for --with-sanitizer])])
AC_SUBST([SANITIZER_CFLAGS])
AC_SUBST([SANITIZER_LDFLAGS])

AC_OUTPUT

AC_MSG_RESULT([
$PACKAGE_NAME $VERSION
    man-pages:      $PANDOC
    enginesdir:     $with_enginesdir
    completionsdir: $with_completionsdir
    device:         $with_device
])

