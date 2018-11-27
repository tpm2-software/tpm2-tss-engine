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
#ifndef TPM2_TSS_ENGINE_H
#define TPM2_TSS_ENGINE_H

#include <openssl/engine.h>
#include <tss2/tss2_tpm2_types.h>

typedef enum {
    KEY_TYPE_BLOB,
    KEY_TYPE_HANDLE
} KEY_TYPE;

typedef struct {
    int emptyAuth;
    TPM2B_DIGEST userauth;
    TPM2B_PUBLIC pub;
    TPM2_HANDLE parent;
    KEY_TYPE privatetype;
    union {
      TPM2B_PRIVATE priv;
      TPM2_HANDLE handle;
    };
} TPM2_DATA;

#define TPM2TSS_SET_OWNERAUTH ENGINE_CMD_BASE

int
tpm2tss_tpm2data_write(const TPM2_DATA *tpm2data, const char *filename);

int
tpm2tss_tpm2data_read(const char *filename, TPM2_DATA **tpm2Datap);

int
tpm2tss_tpm2data_readtpm(uint32_t handle, TPM2_DATA **tpm2Datap);

EVP_PKEY *
tpm2tss_rsa_makekey(TPM2_DATA *tpm2Data);

int
tpm2tss_rsa_genkey(RSA *rsa, int bits, BIGNUM *e, char *password,
                   TPM2_HANDLE parentHandle);

EVP_PKEY *
tpm2tss_ecc_makekey(TPM2_DATA *tpm2Data);

int
tpm2tss_ecc_genkey(EC_KEY *key, TPMI_ECC_CURVE curve, const char *password,
                   TPM2_HANDLE parentHandle);

TPM2_DATA *
tpm2tss_ecc_getappdata(EC_KEY *key);

int
tpm2tss_ecc_setappdata(EC_KEY *key, TPM2_DATA *data);

#endif /* TPM2_TSS_ENGINE_H */
