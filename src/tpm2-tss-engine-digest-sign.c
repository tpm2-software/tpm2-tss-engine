/*******************************************************************************
 * Copyright 2021, Graphiant, Inc.
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

#include <string.h>

#include <openssl/evp.h>

#include <tss2/tss2_esys.h>

#include "tpm2-tss-engine-common.h"

#ifndef TPM2_TSS_ENGINE_HAVE_C11_ATOMICS
/* fall back to using GCC/clang atomic builtins */
# define atomic_fetch_add(PTR, VAL) \
    __atomic_fetch_add((PTR), (VAL), __ATOMIC_SEQ_CST)
#define atomic_fetch_sub(PTR, VAL) \
    __atomic_fetch_sub ((PTR), (VAL), __ATOMIC_SEQ_CST)
#endif /* TPM2_TSS_ENGINE_HAVE_C11_ATOMICS */

/**
 * Initialise a digest operation for digest and sign.
 *
 * @param ctx OpenSSL message digest context
 * @param data Digest and sign data
 * @retval 1 on success
 * @retval 0 on failure
 */
static int
digest_init(EVP_MD_CTX *ctx, TPM2_SIG_DATA *data)
{
    TPM2B_AUTH null_auth = { .size = 0 };
    const EVP_MD *md;
    TSS2_RC r;

    md = EVP_MD_CTX_md(ctx);
    if (!md) {
        ERR(digest_init, TPM2TSS_R_GENERAL_FAILURE);
        return 0;
    }

    switch (EVP_MD_type(md)) {
    case NID_sha1:
        data->hash_alg = TPM2_ALG_SHA1;
        break;
    case NID_sha256:
        data->hash_alg = TPM2_ALG_SHA256;
        break;
    case NID_sha384:
        data->hash_alg = TPM2_ALG_SHA384;
        break;
    case NID_sha512:
        data->hash_alg = TPM2_ALG_SHA512;
        break;
    default:
        ERR(digest_init, TPM2TSS_R_UNKNOWN_ALG);
        return 0;
    }

    r = Esys_HashSequenceStart(data->key->esys_ctx, ESYS_TR_NONE,
                               ESYS_TR_NONE, ESYS_TR_NONE, &null_auth,
                               data->hash_alg, &data->seq_handle);
    ERRchktss(digest_init, r, return 0);

    return 1;
}

/**
 * Update a digest with more data
 *
 * @param ctx OpenSSL message digest context
 * @param data Data to add to digest
 * @param count Length of data to add
 * @retval 1 on success
 * @retval 0 on failure
 */
int
digest_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    EVP_PKEY_CTX *pctx = EVP_MD_CTX_pkey_ctx(ctx);
    TPM2_SIG_DATA *sig_data = EVP_PKEY_CTX_get_app_data(pctx);
    TSS2_RC r;

    DBG("digest_update %p %p\n", pctx, ctx);

    TPM2B_MAX_BUFFER digest_data = { .size = count };
    if (count > sizeof(digest_data.buffer)) {
        ERR(digest_update, TPM2TSS_R_DIGEST_TOO_LARGE);
        return 0;
    }
    memcpy(&digest_data.buffer[0], data, count);

    r = Esys_SequenceUpdate(sig_data->key->esys_ctx, sig_data->seq_handle,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE,
                            ESYS_TR_NONE, &digest_data);
    ERRchktss(digest_update, r, return 0);

    return 1;
}

/**
 * Finish a digest operation for digest and sign
 *
 * @param data Digest and sign data
 * @param digest Digest calculated by TPM
 * @param validation Validation ticket for the digest calculated by TPM
 * @retval 1 on success
 * @retval 0 on failure
 */
int
digest_finish(TPM2_SIG_DATA *data, TPM2B_DIGEST **digest,
              TPMT_TK_HASHCHECK **validation)
{
    TSS2_RC r;

    r = Esys_SequenceComplete(data->key->esys_ctx, data->seq_handle,
                              ESYS_TR_PASSWORD, ESYS_TR_NONE,
                              ESYS_TR_NONE, NULL, ESYS_TR_RH_OWNER,
                              digest, validation);
    ERRchktss(digest_finish, r, return 0);

    /* Esys_SequenceComplete consumes the handle */
    data->seq_handle = ESYS_TR_NONE;

    return 1;
}

/**
 * Initialise a digest and sign operation
 *
 * @param ctx OpenSSL pkey context
 * @param mctx OpenSSL message digest context
 * @param tpm2data TPM data for the key to use
 * @param sig_size Size of the signature data
 * @retval 1 on success
 * @retval 0 on failure
 */
int
digest_sign_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx, TPM2_DATA *tpm2data,
                 size_t sig_size)
{
    TSS2_RC r;

    if (!tpm2data)
        /* non-TPM key - nothing to do */
        return 1;

    TPM2_SIG_DATA *data = OPENSSL_malloc(sizeof(*data));
    if (!data) {
        ERR(digest_sign_init, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    data->seq_handle = ESYS_TR_NONE;
    data->sig_size = sig_size;

    data->key = OPENSSL_malloc(sizeof(*data->key));
    if (!data->key) {
        ERR(digest_sign_init, ERR_R_MALLOC_FAILURE);
        goto error;
    }

    data->key->refcount = 1;

    r = init_tpm_key(&data->key->esys_ctx, &data->key->key_handle, tpm2data);
    ERRchktss(digest_sign_init, r, goto error);
    data->key->privatetype = tpm2data->privatetype;

    EVP_PKEY_CTX_set_app_data(ctx, data);
    /*
     * Override the update function so that the TPM performs the
     * digest, which is required for restricted keys - the TPM will
     * reject a null validation ticket in this case for the signing
     * operation.
     */
    EVP_MD_CTX_set_update_fn(mctx, digest_update);

    if (!digest_init(mctx, data))
        goto error;

    return 1;

 error:
    if (data->key) {
        if (data->key->key_handle != ESYS_TR_NONE) {
            if (data->key->privatetype == KEY_TYPE_HANDLE) {
                Esys_TR_Close(data->key->esys_ctx, &data->key->key_handle);
            } else {
                Esys_FlushContext(data->key->esys_ctx, data->key->key_handle);
            }
        }
        if (data->key->esys_ctx)
            esys_ctx_free(&data->key->esys_ctx);
        OPENSSL_free(data->key);
    }
    OPENSSL_free(data);
    return 0;
}

/**
 * Copy digest and sign context
 *
 * @param dst Destination OpenSSL pkey context
 * @param src Source OpenSSL pkey context
 * @retval 1 on success
 * @retval 0 on failure
 */
int
digest_sign_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    TPM2_SIG_DATA *src_sig_data = EVP_PKEY_CTX_get_app_data(src);
    TPMS_CONTEXT *context = NULL;
    TPM2_SIG_DATA *dst_sig_data = NULL;
    TSS2_RC r;

    if (src_sig_data) {
        dst_sig_data = OPENSSL_malloc(sizeof(*dst_sig_data));
        if (!dst_sig_data) {
            ERR(digest_sign_copy, ERR_R_MALLOC_FAILURE);
            return 0;
        }

        dst_sig_data->hash_alg = src_sig_data->hash_alg;
        dst_sig_data->sig_size = src_sig_data->sig_size;

        if (src_sig_data->seq_handle != ESYS_TR_NONE) {
            /* duplicate sequence handle */

            r = Esys_ContextSave(src_sig_data->key->esys_ctx,
                                 src_sig_data->seq_handle, &context);
            ERRchktss(digest_sign_copy, r, goto error);
            dst_sig_data->seq_handle = ESYS_TR_NONE;
            r = Esys_ContextLoad(src_sig_data->key->esys_ctx, context,
                                 &dst_sig_data->seq_handle);
            ERRchktss(digest_sign_copy, r, goto error);
        }

        dst_sig_data->key = src_sig_data->key;
        atomic_fetch_add(&dst_sig_data->key->refcount, 1);

        EVP_PKEY_CTX_set_app_data(dst, dst_sig_data);
    }

    Esys_Free(context);
    return 1;

 error:
    Esys_Free(context);
    OPENSSL_free(dst_sig_data);
    return 0;
}

/**
 * Clean up digest and sign context
 *
 * @param ctx OpenSSL pkey context
 * @retval 1 on success
 * @retval 0 on failure
 */
void
digest_sign_cleanup(EVP_PKEY_CTX *ctx)
{
    TPM2_SIG_DATA *sig_data = EVP_PKEY_CTX_get_app_data(ctx);

    if (sig_data) {
        if (sig_data->seq_handle != ESYS_TR_NONE)
            Esys_FlushContext(sig_data->key->esys_ctx, sig_data->seq_handle);

        if (atomic_fetch_sub(&sig_data->key->refcount, 1) == 1) {
            if (sig_data->key->key_handle != ESYS_TR_NONE) {
                if (sig_data->key->privatetype == KEY_TYPE_HANDLE) {
                    Esys_TR_Close(sig_data->key->esys_ctx,
                                  &sig_data->key->key_handle);
                } else {
                    Esys_FlushContext(sig_data->key->esys_ctx,
                                      sig_data->key->key_handle);
                }
            }
            esys_ctx_free(&sig_data->key->esys_ctx);
            OPENSSL_free(sig_data->key);
        }
        OPENSSL_free(sig_data);
        EVP_PKEY_CTX_set_app_data(ctx, NULL);
    }
}
