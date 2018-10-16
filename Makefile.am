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

### Initialize global variables used throughout the file ###
INCLUDE_DIRS    = -I$(srcdir)/include -I$(srcdir)/src
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS       = $(INCLUDE_DIRS) $(EXTRA_CFLAGS) $(TSS2_ESYS_CFLAGS) \
                  $(CRYPTO_CFLAGS) $(CODE_COVERAGE_CFLAGS)
AM_LDFLAGS      = $(EXTRA_LDFLAGS) $(CODE_COVERAGE_LIBS)
AM_LDADD        = $(TSS2_ESYS_LIBS) $(CRYPTO_LIBS) -ldl

# Initialize empty variables to be extended throughout
lib_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST =
CLEANFILES =
MOSTLYCLEANFILES =
noinst_PROGRAMS =
bin_PROGRAMS =

### Add ax_* rules ###
# ax_code_coverage
@CODE_COVERAGE_RULES@

### OpenSSL Engine ###
openssl_enginedir = @libdir@/openssl/engines
openssl_engine_LTLIBRARIES = libtpm2tss.la

include_HEADERS = include/tpm2-tss-engine.h

libtpm2tss_la_SOURCES = src/tpm2-tss-engine.c \
                        src/tpm2-tss-engine-common.c \
                        src/tpm2-tss-engine-common.h \
                        src/tpm2-tss-engine-err.c \
                        src/tpm2-tss-engine-err.h \
                        src/tpm2-tss-engine-ecc.c \
                        src/tpm2-tss-engine-rand.c \
                        src/tpm2-tss-engine-rsa.c
libtpm2tss_la_CFLAGS = $(AM_CFLAGS)
libtpm2tss_la_LIBADD = $(AM_LDADD)
libtpm2tss_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined -avoid-version \
            -export-symbols-regex '(tpm2tss*|bind_engine|v_check)'

### KeyGenerator ###
bin_PROGRAMS += tpm2tss-genkey

tpm2tss_genkey_SOURCES = src/tpm2tss-genkey.c
tpm2tss_genkey_CFLAGS = $(AM_CFLAGS)
tpm2tss_genkey_LDADD = $(AM_LDADD) libtpm2tss.la
tpm2tss_genkey_LDFLAGS = $(AM_LDFLAGS) -ltss2-tcti-mssim -ltss2-tcti-device

### Tests ###
TESTS = test/ecdsa.sh \
        test/rand.sh \
        test/rsadecrypt.sh \
        test/rsasign.sh \
        test/failload.sh \
        test/failwrite.sh

EXTRA_DIST += $(TESTS)

# Adding user and developer information
EXTRA_DIST += \
    INSTALL.md \
    LICENSE \
    README.md

# Generate the AUTHORS file from git log
AUTHORS:
	$(AM_V_GEN)git log --format='%aN <%aE>' | \
			grep -v 'users.noreply.github.com' | sort -unr > $@
EXTRA_DIST += AUTHORS
CLEANFILES += AUTHORS

### Man Pages
man1_MANS = \
    man/tpm2tss-genkey.1
man3_MANS = \
    man/tpm2tss_tpm2data_write.3 \
    man/tpm2tss_rsa_makekey.3 \
    man/tpm2tss_rsa_genkey.3 \
    man/tpm2tss_ecc_makekey.3 \
    man/tpm2tss_ecc_genkey.3 \
    man/tpm2tss_ecc_getappdata.3 \
    man/tpm2tss_tpm2data_read.3 \
    man/tpm2tss_ecc_setappdata.3

define man_dir
    mkdir man 2>/dev/null || test -d man
endef

man/tpm2tss_tpm2data_read.3: man/tpm2tss_tpm2data_write.3
	$(AM_V_GEN)(rm $@ 2>/dev/null || true) && ln -s tpm2tss_tpm2data_write.3 $@

man/tpm2tss_ecc_setappdata.3: man/tpm2tss_ecc_getappdata.3
	$(AM_V_GEN)(rm $@ 2>/dev/null || true) && ln -s tpm2tss_ecc_getappdata.3 $@

man/%.1: man/%.1.md
	$(AM_V_GEN)$(call man_dir) && cat $< | $(PANDOC) -s -t man >$@

man/%.3: man/%.3.md
	$(AM_V_GEN)$(call man_dir) && cat $< | $(PANDOC) -s -t man >$@

EXTRA_DIST += \
    man/tpm2tss-genkey.1.md \
    man/tpm2tss_tpm2data_write.3.md \
    man/tpm2tss_rsa_makekey.3.md \
    man/tpm2tss_rsa_genkey.3.md \
    man/tpm2tss_ecc_makekey.3.md \
    man/tpm2tss_ecc_genkey.3.md \
    man/tpm2tss_ecc_getappdata.3.md

CLEANFILES += \
    $(man1_MANS) \
    $(man3_MANS)

### Bash Completion
bash_completiondir = $(sysconfdir)/bash_completion.d
bash_completion_DATA = tpm2tss_completion
EXTRA_DIST += tpm2tss_completion
