/*******************************************************************************
 * Copyright 2017-2021, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 * 
 * Author:  Aaron <zhangya@uniontech.com>
 * Maintainer: Aaron <zhangya@uniontech.com>
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

#include <openssl/engine.h>
#include <openssl/evp.h>

#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>

#include "tpm2-tss-engine.h"
#include "tpm2-tss-engine-common.h"

#ifndef NID_sm3
#define NID_sm3 1143
#endif

typedef struct tpm2_digest_state_st {
    ESYS_CONTEXT* esys_contest;
    TSS2_RC handle;   
    int startSequence; // 0 sequence not start; 1 sequence already started
} TPM2_DIGEST_CTX;


/*
 * @retval 1 on success
 * @retval 0 on failure
 */
static int tpm_digest_init(EVP_MD_CTX *ctx)
{
    TPM2_DIGEST_CTX* data = EVP_MD_CTX_md_data(ctx);
    memset(data, 0, sizeof(TPM2_DIGEST_CTX));
    return 1;
}

/*
 * @retval 1 on success
 * @retval 0 on failure
 */
static int tpm_digest_update(EVP_MD_CTX *ctx, const void *data, \
                            size_t count, TPMI_ALG_HASH hash_method)
{

     TSS2_RC rc;
    TPM2_DIGEST_CTX* ctx_data = EVP_MD_CTX_md_data(ctx);

    /* may we should put this init in tpm_digest_init(), 
       but in sign function, will recursive digest call  like
        digest_init()
            digest_init()
            digest_update()
            digest_update()
            digest_final()
            digest_cleanup()
        digest_update()
        digest_final()
        ...
    */
    if(ctx_data->startSequence == 0){
        ESYS_CONTEXT *esys_ctx = NULL;
        rc = esys_ctx_init(&esys_ctx);

        ESYS_TR sequenceHandle;
        // data size < 1024 also use sequence hash
        rc = Esys_HashSequenceStart( esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                ESYS_TR_NONE, NULL, hash_method, &sequenceHandle);

        if (rc != TSS2_RC_SUCCESS) {
            ERR(tpm_digest_update, rc);
            return 0;
        }

        ctx_data->esys_contest = esys_ctx;
        ctx_data->startSequence = 1;
        ctx_data->handle = sequenceHandle;
    }

    BYTE* cur_data = (BYTE*)data;
    size_t left_count = count;
    TPM2B_MAX_BUFFER buffer;
    while(left_count > 0){
        buffer.size = left_count > TPM2_MAX_DIGEST_BUFFER ? TPM2_MAX_DIGEST_BUFFER: left_count;
        memcpy( buffer.buffer, cur_data, buffer.size );

        left_count -= buffer.size;
        cur_data += buffer.size;

        rc = Esys_SequenceUpdate( ctx_data->esys_contest, ctx_data->handle, ESYS_TR_PASSWORD,
            ESYS_TR_NONE, ESYS_TR_NONE, &buffer);
        if (rc != TSS2_RC_SUCCESS) {
            ERR(tpm_digest_update, rc);
            return 0;
        }
    }

    return 1;
}

/*
 * @retval 1 on success
 * @retval 0 on failure
 */
static int tpm_sha1_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return tpm_digest_update(ctx, data, count, TPM2_ALG_SHA1);
}

/*
 * @retval 1 on success
 * @retval 0 on failure
 */
static int tpm_sha256_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return tpm_digest_update(ctx, data, count, TPM2_ALG_SHA256);
}

/*
 * @retval 1 on success
 * @retval 0 on failure
 */
static int tpm_sha384_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return tpm_digest_update(ctx, data, count, TPM2_ALG_SHA384);
}

/*
 * @retval 1 on success
 * @retval 0 on failure
 */
static int tpm_sha512_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return tpm_digest_update(ctx, data, count, TPM2_ALG_SHA512);
}

/*
 * @retval 1 on success
 * @retval 0 on failure
 */
static int tpm_sm3_256_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return tpm_digest_update(ctx, data, count, TPM2_ALG_SM3_256);
}

/*
 * @retval 1 on success
 * @retval 0 on failure
 */
static int tpm_sha3_256_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return tpm_digest_update(ctx, data, count, TPM2_ALG_SHA3_256);
}

/*
 * @retval 1 on success
 * @retval 0 on failure
 */
static int tpm_sha3_384_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return tpm_digest_update(ctx, data, count, TPM2_ALG_SHA3_384);
}

/*
 * @retval 1 on success
 * @retval 0 on failure
 */
static int tpm_sha3_512_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return tpm_digest_update(ctx, data, count, TPM2_ALG_SHA3_512);
}

/*
 * @retval 1 on success
 * @retval 0 on failure
 */
static int tpm_digest_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    TPM2_DIGEST_CTX* ctx_data = EVP_MD_CTX_md_data(ctx);
    if(ctx_data->startSequence == 0){
        return 0;
    }

    TPM2B_MAX_BUFFER buffer;
    buffer.size = 0;
    TPM2B_DIGEST* result;
    TSS2_RC rc = Esys_SequenceComplete(ctx_data->esys_contest, ctx_data->handle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &buffer,
            ESYS_TR_RH_NULL, &result, NULL);
    if(rc != TSS2_RC_SUCCESS){
        ERR(tpm_digest_final, rc);
        return 0;
    }

    memcpy(md, result->buffer, result->size);
    free(result);
    return 1;
}

/*
 * @retval 1 on success
 * @retval 0 on failure
 */
static int tpm_digest_cleanup(__attribute__((unused))EVP_MD_CTX *ctx)
{
    TPM2_DIGEST_CTX* ctx_data = EVP_MD_CTX_md_data(ctx);
    if(ctx_data->startSequence == 0){
        return 0;
    }

    esys_ctx_free( &ctx_data->esys_contest);
    return 1;
}

//typedef int (*tpm_digest_update_type)(EVP_MD_CTX *ctx, const void *data, size_t count);
static EVP_MD* tpm2_engine_digest_methods[8] = { NULL };
static int  tpm2_engine_digest_nids[8] = { 0 };
static int  tpm2_engine_digest_nids_size = 0;

/* digest selector by nid
 * @retval 1 on success
 * @retval 0 on failure
 */
int digest_selector(__attribute__((unused)) ENGINE *e, const EVP_MD **digest,
                    const int **nids, int nid)
{
    DBG("%s[%s %d]\n", __FUNCTION__, __FILE__, __LINE__);
    if (!digest) {
        /* We are returning a list of supported nids */
        *nids = tpm2_engine_digest_nids;
        return tpm2_engine_digest_nids_size;
    }

    int ok = 0;
    /* We are being asked for a specific digest */
    for(int i = 0; i < tpm2_engine_digest_nids_size; ++i){
        if(tpm2_engine_digest_nids[i] == nid){
            *digest = tpm2_engine_digest_methods[i];
            ok = 1;
            break;
        }
    }

    return ok;
}

/* Initialize the digest evp method
 *
 * @retval 1 on success
 * @retval 0 on failure
 */
int int_digest_method(int nid, int block_size, int result_size)
{
    EVP_MD* digest_method = EVP_MD_meth_new(nid, NID_undef);
    if(digest_method == NULL){
        return 0;
    }

    EVP_MD_meth_set_init(digest_method, tpm_digest_init);
    EVP_MD_meth_set_cleanup(digest_method, tpm_digest_cleanup);
    switch(nid){
        case NID_sha1:
            EVP_MD_meth_set_update(digest_method, tpm_sha1_update);
            break;
        case NID_sha256:
            EVP_MD_meth_set_update(digest_method, tpm_sha256_update);
            break;
        case NID_sha384:
            EVP_MD_meth_set_update(digest_method, tpm_sha384_update);
            break;
        case NID_sha512:
            EVP_MD_meth_set_update(digest_method, tpm_sha512_update);
            break;
        case NID_sm3:
            EVP_MD_meth_set_update(digest_method, tpm_sm3_256_update);
            break;
        case NID_sha3_256:
            EVP_MD_meth_set_update(digest_method, tpm_sha3_256_update);
            break;
        case NID_sha3_384:
            EVP_MD_meth_set_update(digest_method, tpm_sha3_384_update);
            break;
        case NID_sha3_512:
            EVP_MD_meth_set_update(digest_method, tpm_sha3_512_update);
            break;
        default:
            return 0;
    }

    EVP_MD_meth_set_final(digest_method, tpm_digest_final);
    EVP_MD_meth_set_input_blocksize(digest_method, block_size);
    EVP_MD_meth_set_app_datasize(digest_method, sizeof(EVP_MD*) + sizeof(TPM2_DIGEST_CTX));
    EVP_MD_meth_set_result_size(digest_method, result_size);

    tpm2_engine_digest_nids[tpm2_engine_digest_nids_size] = nid;
    tpm2_engine_digest_methods[tpm2_engine_digest_nids_size] = digest_method;
    ++tpm2_engine_digest_nids_size;
    return 1;
}

/** Initialize the tpm2tss engine's digest submodule
 * @retval 1 on success
 * @retval 0 on failure
 */
int init_digests(ENGINE *e)
{
    TPMS_CAPABILITY_DATA* caps;

    ESYS_CONTEXT *esys_ctx = NULL;
    TSS2_RC rc = esys_ctx_init(&esys_ctx);
    if(rc != TSS2_RC_SUCCESS){
        return 1;
    }

    TPMI_YES_NO more_data;
    rc = Esys_GetCapability( esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                ESYS_TR_NONE, TPM2_CAP_ALGS, TPM2_PERSISTENT_FIRST, TPM2_MAX_CAP_HANDLES,
                &more_data, &caps);
    if(rc != TSS2_RC_SUCCESS){
        return 1;
    }

    for(UINT32 i = 0; i < caps->data.algorithms.count; ++i){
        TPMS_ALG_PROPERTY* alg_property = &(caps->data.algorithms.algProperties[i]);
        TPM2_ALG_ID id = alg_property->alg;
        switch(id){
            case TPM2_ALG_SHA1:
                int_digest_method(NID_sha1, SHA_CBLOCK, SHA_DIGEST_LENGTH);
                break;
            case TPM2_ALG_SHA256:
                int_digest_method(NID_sha256, SHA256_CBLOCK, SHA256_DIGEST_LENGTH);
                break;
            case TPM2_ALG_SHA384:
                int_digest_method(NID_sha384, SHA512_CBLOCK, SHA384_DIGEST_LENGTH);
                break;
            case TPM2_ALG_SHA512:
                int_digest_method(NID_sha512, SHA512_CBLOCK, SHA512_DIGEST_LENGTH);
                break;
            case TPM2_ALG_SM3_256:
                int_digest_method(NID_sm3, SHA256_CBLOCK, SHA256_DIGEST_LENGTH);
                break;
            case TPM2_ALG_SHA3_256:
                int_digest_method(NID_sha3_256, SHA256_CBLOCK, SHA256_DIGEST_LENGTH);
                break;
            case TPM2_ALG_SHA3_384:
                int_digest_method(NID_sha3_384, SHA512_CBLOCK, SHA384_DIGEST_LENGTH);
                break;
            case TPM2_ALG_SHA3_512:
                int_digest_method(NID_sha3_512, SHA256_CBLOCK, SHA512_DIGEST_LENGTH);
                break;
            default:
                continue;
        }
    }
    esys_ctx_free( &esys_ctx );

    if(tpm2_engine_digest_nids_size < 1){
        return 1;
    }

    return ENGINE_set_digests(e, &digest_selector);
}
