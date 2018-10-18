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

#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/pem.h>

#include "tpm2-tss-engine.h"
#include "tpm2-tss-engine-common.h"

ASN1_SEQUENCE(TSSPRIVKEY) = {
	ASN1_SIMPLE(TSSPRIVKEY, type, ASN1_OBJECT),
	ASN1_EXP_OPT(TSSPRIVKEY, emptyAuth, ASN1_BOOLEAN, 0),
	ASN1_SIMPLE(TSSPRIVKEY, parent, ASN1_INTEGER),
	ASN1_SIMPLE(TSSPRIVKEY, pubkey, ASN1_OCTET_STRING),
	ASN1_SIMPLE(TSSPRIVKEY, privkey, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(TSSPRIVKEY)

#define TSSPRIVKEY_PEM_STRING "TSS2 PRIVATE KEY"

IMPLEMENT_ASN1_FUNCTIONS(TSSPRIVKEY);
IMPLEMENT_PEM_write_bio(TSSPRIVKEY, TSSPRIVKEY, TSSPRIVKEY_PEM_STRING, TSSPRIVKEY);
IMPLEMENT_PEM_read_bio(TSSPRIVKEY, TSSPRIVKEY, TSSPRIVKEY_PEM_STRING, TSSPRIVKEY);


/** Serialize tpm2data onto disk
 *
 * Write the tpm2tss key data into a file using PEM encoding.
 * @param tpm2Data The data to be written to disk.
 * @param filename The filename to write the data to.
 * @retval 1 on success
 * @retval 0 on failure
 */
int
tpm2tss_tpm2data_write(const TPM2_DATA *tpm2Data, const char *filename)
{
    TSS2_RC r;
    BIO *bio = NULL;
    TSSPRIVKEY *tpk = NULL;

    uint8_t privbuf[sizeof(tpm2Data->priv)];
    uint8_t pubbuf[sizeof(tpm2Data->pub)];
    size_t privbuf_len = 0, pubbuf_len = 0;

    if ((bio = BIO_new_file(filename, "w")) == NULL) {
        ERR(tpm2tss_tpm2data_write, TPM2TSS_R_FILE_WRITE);
        goto error;
    }

    tpk = TSSPRIVKEY_new();
    if (!tpk) {
	    ERR(tpm2tss_tpm2data_write, ERR_R_MALLOC_FAILURE);
	    goto error;
    }

    r = Tss2_MU_TPM2B_PRIVATE_Marshal(&tpm2Data->priv, &privbuf[0],
                                  sizeof(privbuf), &privbuf_len);
    if (r) {
        ERR(tpm2tss_tpm2data_write, TPM2TSS_R_DATA_CORRUPTED);
        goto error;
    }

    r = Tss2_MU_TPM2B_PUBLIC_Marshal(&tpm2Data->pub, &pubbuf[0],
                                 sizeof(pubbuf), &pubbuf_len);
    if (r) {
        ERR(tpm2tss_tpm2data_write, TPM2TSS_R_DATA_CORRUPTED);
        goto error;
    }
    tpk->type = OBJ_txt2obj(OID_loadableKey, 1);
    tpk->parent = ASN1_INTEGER_new();
    tpk->privkey = ASN1_OCTET_STRING_new();
    tpk->pubkey = ASN1_OCTET_STRING_new();
    if (!tpk->type || !tpk->privkey || !tpk->pubkey || !tpk->parent) {
        ERR(tpm2tss_tpm2data_write, ERR_R_MALLOC_FAILURE);
        goto error;
    }

    tpk->emptyAuth = !!tpm2Data->emptyAuth;
    /* Only TPM2_RH_OWNER is supported for now */
    ASN1_INTEGER_set(tpk->parent, TPM2_RH_OWNER);
    ASN1_STRING_set(tpk->privkey, &privbuf[0], privbuf_len);
    ASN1_STRING_set(tpk->pubkey, &pubbuf[0], pubbuf_len);

    PEM_write_bio_TSSPRIVKEY(bio, tpk);
    TSSPRIVKEY_free(tpk);
	BIO_free(bio);

    return 1;
error:
    if (bio) BIO_free(bio);
    if (tpk) TSSPRIVKEY_free(tpk);
    return 0;
}

/** Create tpm2data from a TPM key
 *
 * Retrieve the public key of tpm2data from the TPM for a given handle.
 * @param handle The TPM's key handle.
 * @param tpm2Datap The data after read.
 * @retval 1 on success
 * @retval 0 on failure
 */
int
tpm2tss_tpm2data_readtpm(uint32_t handle, TPM2_DATA **tpm2Datap)
{
    TSS2_RC r;
    TPM2_DATA *tpm2Data = NULL;
    ESYS_TR keyHandle;
    ESYS_CONTEXT *ectx;
    TPM2B_PUBLIC *outPublic;

    tpm2Data = OPENSSL_malloc(sizeof(*tpm2Data));
    if (tpm2Data == NULL) {
        ERR(tpm2tss_tpm2data_readtpm, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    memset(tpm2Data, 0, sizeof(*tpm2Data));

    tpm2Data->privatetype = KEY_TYPE_HANDLE;
    tpm2Data->handle = handle;

    r = Esys_Initialize(&ectx, NULL, NULL);
    if (r) {
        ERR(tpm2tss_tpm2data_readtpm, TPM2TSS_R_GENERAL_FAILURE);
        goto error;
    }

    r = Esys_TR_FromTPMPublic(ectx, tpm2Data->handle, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, &keyHandle);
    if (r) {
        ERR(tpm2tss_tpm2data_readtpm, TPM2TSS_R_GENERAL_FAILURE);
        goto error;
    }

    r = Esys_ReadPublic(ectx, keyHandle, ESYS_TR_NONE, ESYS_TR_NONE,
                        ESYS_TR_NONE, &outPublic, NULL, NULL);
    if (r) {
        ERR(tpm2tss_tpm2data_readtpm, TPM2TSS_R_GENERAL_FAILURE);
        goto error;
    }

    Esys_TR_Close(ectx, &keyHandle);
    Esys_Finalize(&ectx);
    tpm2Data->pub = *outPublic;
    free(outPublic);

    *tpm2Datap = tpm2Data;
    return 1;
error:
    if (tpm2Data) OPENSSL_free(tpm2Data);
    return 0;
}


/** Deserialize tpm2data from disk
 *
 * Read the tpm2tss key data from a file using PEM encoding.
 * @param filename The filename to read the data from.
 * @param tpm2Datap The data after read.
 * @retval 1 on success
 * @retval 0 on failure
 */
int
tpm2tss_tpm2data_read(const char *filename, TPM2_DATA **tpm2Datap)
{
    TSS2_RC r;
    BIO *bio = NULL;
    TSSPRIVKEY *tpk = NULL;
    TPM2_DATA *tpm2Data = NULL;
    TPM2_HANDLE parent;
    char type_oid[64];

    if ((bio = BIO_new_file(filename, "r")) == NULL) {
        ERR(tpm2tss_tpm2data_read, TPM2TSS_R_FILE_READ);
        goto error;
    }

    tpk = PEM_read_bio_TSSPRIVKEY(bio, NULL, NULL, NULL);
    if (!tpk) {
	ERR(tpm2tss_tpm2data_read, TPM2TSS_R_DATA_CORRUPTED);
        goto error;
    }
    BIO_free(bio);
    bio = NULL;

    tpm2Data = OPENSSL_malloc(sizeof(*tpm2Data));
    if (tpm2Data == NULL) {
        ERR(tpm2tss_tpm2data_read, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    memset(tpm2Data, 0, sizeof(*tpm2Data));

    tpm2Data->privatetype = KEY_TYPE_BLOB;

    tpm2Data->emptyAuth = tpk->emptyAuth;

    parent = ASN1_INTEGER_get(tpk->parent);
    if (parent != TPM2_RH_OWNER) {
        ERR(tpm2tss_tpm2data_read, TPM2TSS_R_CANNOT_MAKE_KEY);
	goto error;
    }

    if (!OBJ_obj2txt(type_oid, sizeof(type_oid), tpk->type, 1) ||
	strcmp(type_oid, OID_loadableKey)) {
        ERR(tpm2tss_tpm2data_read, TPM2TSS_R_CANNOT_MAKE_KEY);
	goto error;
    }
    r = Tss2_MU_TPM2B_PRIVATE_Unmarshal(tpk->privkey->data, tpk->privkey->length,
					NULL, &tpm2Data->priv);
    if (r) {
        ERR(tpm2tss_tpm2data_read, TPM2TSS_R_DATA_CORRUPTED);
        goto error;
    }
    r = Tss2_MU_TPM2B_PUBLIC_Unmarshal(tpk->pubkey->data, tpk->pubkey->length,
				       NULL, &tpm2Data->pub);
    if (r) {
        ERR(tpm2tss_tpm2data_read, TPM2TSS_R_DATA_CORRUPTED);
        goto error;
    }

    TSSPRIVKEY_free(tpk);

    *tpm2Datap = tpm2Data;
    return 1;
error:
    if (tpm2Data) OPENSSL_free(tpm2Data);
	if (bio) BIO_free(bio);
    if (tpk) TSSPRIVKEY_free(tpk);

    return 0;
}

static TPM2B_PUBLIC primaryTemplate = TPM2B_PUBLIC_PRIMARY_TEMPLATE;
static TPM2B_SENSITIVE_CREATE primarySensitive = {
    .sensitive = {
        .userAuth = {
             .size = 0,
         },
        .data = {
             .size = 0,
         }
    }
};
static TPM2B_DATA allOutsideInfo = {
    .size = 0,
};
static TPML_PCR_SELECTION allCreationPCR = {
    .count = 0,
};

/** Initialize the ESYS TPM connection and primary key
 *
 * Establish a connection with the TPM using ESYS libraries and create a primary
 * key under the owner hierarchy.
 * @param ctx The resulting ESYS context.
 * @param primaryHandle The resulting handle for the primary key.
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RCs according to the error
 */
TSS2_RC
init_tpm_primary(ESYS_CONTEXT **ctx, ESYS_TR *primaryHandle)
{
    TSS2_RC r;
    *primaryHandle = ESYS_TR_NONE;

    DBG("Establishing connection with TPM.\n");
    r = Esys_Initialize(ctx, NULL, NULL);
    ERRchktss(init_tpm_primary, r, goto error);

    r = Esys_Startup(*ctx, TPM2_SU_CLEAR);
    if (r == TPM2_RC_INITIALIZE)
        DBG("TPM was already started up thus false positive failing in tpm2tss"
            " log.\n");
    else
        ERRchktss(init_tpm_primary, r, goto error);

    DBG("Creating primary key under owner.\n");
    r = Esys_TR_SetAuth(*ctx, ESYS_TR_RH_OWNER, &ownerauth);
    ERRchktss(init_tpm_primary, r, goto error);

    r = Esys_CreatePrimary(*ctx, ESYS_TR_RH_OWNER,
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           &primarySensitive, &primaryTemplate,
                           &allOutsideInfo, &allCreationPCR,
                           primaryHandle, NULL, NULL, NULL, NULL);
    if (r == 0x000009a2) {
        ERR(init_tpm_primary, TPM2TSS_R_OWNER_AUTH_FAILED);
        goto error;
    }
    ERRchktss(init_tpm_primary, r, goto error);

    return TSS2_RC_SUCCESS;
error:
    if (*primaryHandle != ESYS_TR_NONE)
        Esys_FlushContext(*ctx, *primaryHandle);
    *primaryHandle = ESYS_TR_NONE;

    Esys_Finalize(ctx);
    return r;
}

/** Initialize the ESYS TPM connection and load the key
 *
 * Establish a connection with the TPM using ESYS libraries, create a primary
 * key under the owner hierarchy and then load the TPM key and set its auth
 * value.
 * @param ctx The resulting ESYS context.
 * @param keyHandle The resulting handle for the key key.
 * @param tpm2Data The key data, owner auth and key auth to be used
 * @retval TSS2_RC_SUCCESS on success
 * @retval TSS2_RCs according to the error
 */
TSS2_RC
init_tpm_key(ESYS_CONTEXT **ctx, ESYS_TR *keyHandle, TPM2_DATA *tpm2Data)
{
    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;
    *keyHandle = ESYS_TR_NONE;

    if (tpm2Data->privatetype == KEY_TYPE_HANDLE) {
        DBG("Establishing connection with TPM.\n");
        r = Esys_Initialize(ctx, NULL, NULL);
        ERRchktss(init_tpm_key, r, goto error);

        r = Esys_Startup(*ctx, TPM2_SU_CLEAR);
        if (r == TPM2_RC_INITIALIZE)
            DBG("TPM was already started up thus false positive failing in tpm2tss"
                " log.\n");
        else
            ERRchktss(init_tpm_key, r, goto error);

        r = Esys_TR_FromTPMPublic(*ctx, tpm2Data->handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, keyHandle);
        ERRchktss(init_tpm_key, r, goto error);
    } else if (tpm2Data->privatetype == KEY_TYPE_BLOB) {
        r = init_tpm_primary(ctx, &primaryHandle);
        ERRchktss(init_tpm_key, r, goto error);

        DBG("Loading key blob.\n");
        r = Esys_Load(*ctx, primaryHandle,
                      ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                      &tpm2Data->priv, &tpm2Data->pub,
                      keyHandle);
        ERRchktss(init_tpm_key, r, goto error);

        r = Esys_FlushContext(*ctx, primaryHandle);
        ERRchktss(rsa_priv_enc, r, goto error);
        primaryHandle = ESYS_TR_NONE;
    } else {
        r = -1;
        ERRchktss(init_tpm_key, r, goto error);
    }

    r = Esys_TR_SetAuth(*ctx, *keyHandle, &tpm2Data->userauth);
    ERRchktss(init_tpm_key, r, goto error);

    return TSS2_RC_SUCCESS;
error:
    if (primaryHandle != ESYS_TR_NONE)
        Esys_FlushContext(*ctx, primaryHandle);
    if (*keyHandle != ESYS_TR_NONE)
        Esys_FlushContext(*ctx, *keyHandle);
    *keyHandle = ESYS_TR_NONE;

    Esys_Finalize(ctx);
    return r;
}
