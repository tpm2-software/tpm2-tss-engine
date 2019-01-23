/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of tpm2-tss-engine nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include <openssl/err.h>

#include "tpm2-tss-engine-err.h"

#define TPM2TSS_LIB_NAME "tpm2-tss-engine"

#define xstr(s) str(s)
#define str(s) #s

#define ERR_F(f) { ERR_PACK(0, TPM2TSS_F_ ## f, 0), xstr(f) }
#define ERR_R(r, s) { ERR_PACK(0, 0, r), xstr(s) }

#ifndef OPENSSL_NO_ERR
static ERR_STRING_DATA TPM2TSS_f[] = {
    /* tpm2-tss-engine.c */
    ERR_F(loadkey),
    ERR_F(init_engine),
    ERR_F(get_auth),
    ERR_F(engine_ctrl),
    /* tpm2-tss-engine-common.c */
    ERR_F(tpm2tss_tpm2data_write),
    ERR_F(tpm2tss_tpm2data_read),
    ERR_F(tpm2tss_tpm2data_readtpm),
    ERR_F(init_tpm_parent),
    ERR_F(init_tpm_key),
    ERR_F(esys_auxctx_init),
    ERR_F(esys_auxctx_free),
    /* tpm2-tss-engine-ecc.c */
    ERR_F(ecdsa_sign),
    ERR_F(populate_ecc),
    ERR_F(tpm2tss_ecc_genkey),
    ERR_F(tpm2tss_ecc_makekey),
    /* tpm2-tss-engine-rand.c */
    ERR_F(rand_bytes),
    /* tpm2-tss-engine-rsa.c */
    ERR_F(rsa_priv_enc),
    ERR_F(rsa_priv_dec),
    ERR_F(tpm2tss_rsa_genkey),
    ERR_F(populate_rsa),
    /* tpm2-tss-engine-tcti.c */
    ERR_F(tcti_expand_dlname),
    ERR_F(tcti_dlopen),
    ERR_F(tcti_get_init),
    ERR_F(__tcti_get_ctx),
    ERR_F(tcti_set_opts),
    ERR_F(tcti_get_ctx),
    ERR_F(tcti_free_ctx),
    {0, NULL}
};

static ERR_STRING_DATA TPM2TSS_r[] = {
    ERR_R(TPM2TSS_R_TPM2DATA_READ_FAILED, Failed to read TPM2 data),
    ERR_R(TPM2TSS_R_UNKNOWN_ALG, The algorithm is unknown (neither RSA, ECDSA)),
    ERR_R(TPM2TSS_R_CANNOT_MAKE_KEY, Cannot create OpenSSL key object),
    ERR_R(TPM2TSS_R_SUBINIT_FAILED, Could not initialize submodule),
    ERR_R(TPM2TSS_R_FILE_WRITE, Could not create file for writing),
    ERR_R(TPM2TSS_R_DATA_CORRUPTED, Data is corrupted and could not be parsed),
    ERR_R(TPM2TSS_R_FILE_READ, Could not open file for reading),
    ERR_R(TPM2TSS_R_PADDING_UNKNOWN, Unknown padding scheme requested),
    ERR_R(TPM2TSS_R_PADDING_FAILED, Padding operation failed),
    ERR_R(TPM2TSS_R_UNKNOWN_TPM_ERROR, Unknown TPM error occured. Please check tpm2tss logs),
    ERR_R(TPM2TSS_R_DIGEST_TOO_LARGE, The provided digest value is too large),
    ERR_R(TPM2TSS_R_GENERAL_FAILURE, Some unknown error occured),
    ERR_R(TPM2TSS_R_UNKNOWN_CURVE, Unknown ECC curve),
    ERR_R(TPM2TSS_R_UI_ERROR, User interaction),
    ERR_R(TPM2TSS_R_UNKNOWN_CTRL, Unknown engine ctrl),
    ERR_R(TPM2TSS_R_DL_OPEN_FAILED, Failed to open TCTI library),
    ERR_R(TPM2TSS_R_DL_INVALID, The TCTI library is invalid),
    /* TPM/TSS Reasons that are useful to the user */
    ERR_R(TPM2TSS_R_AUTH_FAILURE, Authorization failed),
    ERR_R(TPM2TSS_R_OWNER_AUTH_FAILED, Owner authorization failed),
    ERR_R(TPM2TSS_R_OLD_TSS, An old TSS (<2.2) was detected and a TPM session may have leaked),
    {0, NULL}
};
#endif /* OPENSSL_NO_ERR */

static int TPM2TSS_lib_error_code = 0;
static int TPM2TSS_error_init = 0;

static ERR_STRING_DATA TPM2TSS_lib_name[] = {
    {0, TPM2TSS_LIB_NAME},
    {0, NULL}
};

/** Load TPM2TSS error string
 *
 * Load the errorstring from TPM2TSS_f and TPM2TSS_r into OpenSSL's error
 * handling stack.
 */
void
ERR_load_TPM2TSS_strings(void)
{
    if (TPM2TSS_lib_error_code == 0)
        TPM2TSS_lib_error_code = ERR_get_next_error_library();

    if (!TPM2TSS_error_init) {
        TPM2TSS_error_init = 1;
#ifndef OPENSSL_NO_ERR
        ERR_load_strings(TPM2TSS_lib_error_code, TPM2TSS_f);
        ERR_load_strings(TPM2TSS_lib_error_code, TPM2TSS_r);
#endif /* OPENSSL_NO_ERR */

        TPM2TSS_lib_name->error = ERR_PACK(TPM2TSS_lib_error_code, 0, 0);
        ERR_load_strings(0, TPM2TSS_lib_name);
    }
}

/** Unload TPM2TSS error string
 *
 * Unload the errorstring from TPM2TSS_f and TPM2TSS_r into OpenSSL's error
 * handling stack.
 */
void
ERR_unload_TPM2TSS_strings(void)
{
    if (TPM2TSS_error_init) {
#ifndef OPENSSL_NO_ERR
        ERR_unload_strings(TPM2TSS_lib_error_code, TPM2TSS_f);
        ERR_unload_strings(TPM2TSS_lib_error_code, TPM2TSS_r);
#endif /* OPENSSL_NO_ERR */

        ERR_unload_strings(0, TPM2TSS_lib_name);
        TPM2TSS_error_init = 0;
    }
}

/** Add error to error stack
 *
 * Add the error to the error stack of OpenSSL.
 * This function is usually not called directly but using the macros ERR(f,r)
 * or ERRchktss(f, r, s) from source code.
 * @param function Identifier of the function invocing the error.
 * @param reason Identifier of the reason for the error.
 * @param file File from which the error originates.
 * @param line Line inside the file from which the error originates.
 */
void
ERR_error(int function, int reason, const char *file, int line)
{
    if (TPM2TSS_lib_error_code == 0)
        TPM2TSS_lib_error_code = ERR_get_next_error_library();
    ERR_PUT_error(TPM2TSS_lib_error_code, function, reason, file, line);
}

/** Print a buffer to stderr
 *
 * A helper function to print data buffers to stderr. This function is usually
 * not called directly, but the macro DBGBUF() is used instead.
 * @param b The buffer
 * @param s The buffer's size
 */
void
printbuf(const uint8_t *b, size_t s)
{
    if (s > 1000)
        return;
    for (size_t i = 0; i < s; i++)
        fprintf(stderr, "%02x", b[i]);
    fprintf(stderr, "\n");
}
