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
#ifndef TPM2_TSS_ENGINE_ERR_H
#define TPM2_TSS_ENGINE_ERR_H

#include <stdint.h>

#ifndef NDEBUG
#define DBG(...) fprintf(stderr, __VA_ARGS__)
#define DBGBUF(...) printbuf(__VA_ARGS__)
void printbuf(const uint8_t *b, size_t s);

#else /* DEBUG */
#define DBG(...)
#define DBGBUF(...)
#endif /* DEBUG */

#define ERR(f,r) ERR_error(TPM2TSS_F_ ## f, r, __FILE__, __LINE__)

/* This macro checks for common TPM error codes which are meaningful to the
   user */
#define ERRchktss(f, r, s) do { \
    if (r) { \
        switch(r) { \
        case TSS2_ESYS_RC_MEMORY: \
            ERR(f, ERR_R_MALLOC_FAILURE); \
            break; \
        case 0x000009a2: \
            ERR(f, TPM2TSS_R_AUTH_FAILURE); \
            break; \
        default: \
            ERR(f, TPM2TSS_R_UNKNOWN_TPM_ERROR); \
        } \
        s; \
    } \
} while (0);

void ERR_load_TPM2TSS_strings(void);
void ERR_unload_TPM2TSS_strings(void);
void ERR_error(int function, int reason, const char *file, int line);

/* Function codes */
/* tpm2-tss-engine.c */
#define TPM2TSS_F_loadkey          100
#define TPM2TSS_F_init_engine          101
#define TPM2TSS_F_get_auth                  102
#define TPM2TSS_F_engine_ctrl               103
/* tpm2-tss-engine-common.c */
#define TPM2TSS_F_tpm2tss_tpm2data_write        110
#define TPM2TSS_F_tpm2tss_tpm2data_read         111
#define TPM2TSS_F_tpm2tss_tpm2data_readtpm      112
#define TPM2TSS_F_init_tpm_parent      113
#define TPM2TSS_F_init_tpm_key          114
#define TPM2TSS_F_esys_ctx_init      115
#define TPM2TSS_F_esys_ctx_free      116
/* tpm2-tss-engine-ecc.c */
#define TPM2TSS_F_ecdsa_sign    120
#define TPM2TSS_F_populate_ecc          121
#define TPM2TSS_F_tpm2tss_ecc_genkey    122
#define TPM2TSS_F_tpm2tss_ecc_makekey      123
/* tpm2-tss-engine-rand.c */
#define TPM2TSS_F_rand_bytes    130
/* tpm2-tss-engine-rsa.c */
#define TPM2TSS_F_rsa_priv_enc     140
#define TPM2TSS_F_rsa_priv_dec     141
#define TPM2TSS_F_tpm2tss_rsa_genkey    142
#define TPM2TSS_F_populate_rsa          143

/* Reason codes */
#define TPM2TSS_R_TPM2DATA_READ_FAILED  100
#define TPM2TSS_R_UNKNOWN_ALG           101
#define TPM2TSS_R_CANNOT_MAKE_KEY       102
#define TPM2TSS_R_SUBINIT_FAILED        103
#define TPM2TSS_R_FILE_WRITE            104
#define TPM2TSS_R_DATA_CORRUPTED        105
#define TPM2TSS_R_FILE_READ             106
#define TPM2TSS_R_PADDING_UNKNOWN       107
#define TPM2TSS_R_PADDING_FAILED        108
#define TPM2TSS_R_UNKNOWN_TPM_ERROR     109
#define TPM2TSS_R_DIGEST_TOO_LARGE      110
#define TPM2TSS_R_GENERAL_FAILURE       111
#define TPM2TSS_R_UNKNOWN_CURVE         112
#define TPM2TSS_R_UI_ERROR              113
#define TPM2TSS_R_UNKNOWN_CTRL          114
#define TPM2TSS_R_DL_OPEN_FAILED        115
#define TPM2TSS_R_DL_INVALID            116
/* TPM/TSS Reasons that are useful to the user */
#define TPM2TSS_R_AUTH_FAILURE          150
#define TPM2TSS_R_OWNER_AUTH_FAILED     151
#define TPM2TSS_R_OLD_TSS               152

#endif /* TPM2_TSS_ENGINE_ERR_H */
