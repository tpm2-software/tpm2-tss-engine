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
#ifndef TPM2_TSS_ENGINE_COMMON_H
#define TPM2_TSS_ENGINE_COMMON_H

#include <tpm2-tss-engine.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>

#include "tpm2-tss-engine-err.h"

#include <openssl/asn1t.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>

extern TPM2B_DIGEST ownerauth;

int init_ecc(ENGINE *e);
int init_rand(ENGINE *e);
int init_rsa(ENGINE *e);

typedef void* dl_handle_t;

typedef struct {
    dl_handle_t     dlhandle;
    ESYS_CONTEXT    *ectx;
} ESYS_AUXCONTEXT;

TSS2_RC esys_auxctx_init (ESYS_AUXCONTEXT *eactx_p);

TSS2_RC esys_auxctx_free (ESYS_AUXCONTEXT *eactx_p);

TSS2_RC init_tpm_parent(ESYS_CONTEXT **ctx, uint32_t parentHandle,
                        ESYS_TR *parent);
TSS2_RC init_tpm_key(ESYS_CONTEXT **ctx, ESYS_TR *keyHandle,
                     TPM2_DATA *tpm2Data);

#define ENGINE_HASH_ALG TPM2_ALG_SHA256

#define TPM2B_PUBLIC_PRIMARY_TEMPLATE { \
    .publicArea = { \
        .type = TPM2_ALG_ECC, \
        .nameAlg = ENGINE_HASH_ALG, \
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | \
                             TPMA_OBJECT_RESTRICTED | \
                             TPMA_OBJECT_DECRYPT | \
                             TPMA_OBJECT_NODA | \
                             TPMA_OBJECT_FIXEDTPM | \
                             TPMA_OBJECT_FIXEDPARENT | \
                             TPMA_OBJECT_SENSITIVEDATAORIGIN), \
        .authPolicy = { \
             .size = 0, \
         }, \
        .parameters.eccDetail = { \
             .symmetric = { \
                 .algorithm = TPM2_ALG_AES, \
                 .keyBits.aes = 128, \
                 .mode.aes = TPM2_ALG_CFB, \
              }, \
             .scheme = { \
                .scheme = TPM2_ALG_NULL, \
                .details = {} \
             }, \
             .curveID = TPM2_ECC_NIST_P256, \
             .kdf = { \
                .scheme = TPM2_ALG_NULL, \
                .details = {} \
             }, \
         }, \
        .unique.ecc = { \
             .x.size = 0, \
             .y.size = 0 \
         } \
     } \
}

typedef struct {
	ASN1_OBJECT *type;
	ASN1_BOOLEAN emptyAuth;
	ASN1_INTEGER *parent;
	ASN1_OCTET_STRING *pubkey;
	ASN1_OCTET_STRING *privkey;
} TSSPRIVKEY;


DECLARE_ASN1_FUNCTIONS(TSSPRIVKEY);

DECLARE_PEM_write_bio(TSSPRIVKEY, TSSPRIVKEY);
DECLARE_PEM_read_bio(TSSPRIVKEY, TSSPRIVKEY);

#define OID_loadableKey "2.23.133.10.1.3"

#endif /* TPM2_TSS_ENGINE_COMMON_H */
