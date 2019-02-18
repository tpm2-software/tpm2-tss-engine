/*******************************************************************************
 * Copyright 2019, Schneider-Electric
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
#define _DEFAULT_SOURCE // used for be32toh()
#include <string.h>
#include <endian.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <tss2/tss2_esys.h>

#include "tpm2-tss-engine.h"
#include "tpm2-tss-engine-common.h"

#define HANDLE_SIZE 8

static int tpm2_cipher_nids[] = {
    NID_aes_256_cfb128,
    NID_aes_256_ofb128,
    0
};

static int
big_endian_array_to_native(const unsigned char *in, size_t size)
{
    uint32_t r;

    memcpy(&r, in, size);
    r = be32toh(r);

    return r;
}

static int
populate_tpm2data(const unsigned char *key, TPM2_DATA **tpm2Data)
{
    uint32_t keyHandle = 0;

    /* Use an empty Key */
    if (key == NULL) {
        *tpm2Data = NULL;

    /* Read persistent key, use for openssl app : openssl enc */
    } else if ((key[0] == 0x81) && (key[HANDLE_SIZE/2 + 1] == 0)) {
        keyHandle = big_endian_array_to_native(key, HANDLE_SIZE/2);
        if (!tpm2tss_tpm2data_readtpm(keyHandle, tpm2Data))
            return 0;

    /* Use blob context */
    } else {
        return 0;
    }

    return 1;
}

static TPMI_ALG_SYM_MODE
tpm2_get_cipher_mode(EVP_CIPHER_CTX *ctx, TPM2_DATA *tpm2Data)
{
    if (tpm2Data->pub.publicArea.parameters.symDetail.sym.mode.sym == TPM2_ALG_NULL) {
        switch (EVP_CIPHER_CTX_mode(ctx)) {
            case EVP_CIPH_CFB_MODE:
                return TPM2_ALG_CFB;
            case EVP_CIPH_OFB_MODE:
                return TPM2_ALG_OFB;
            case EVP_CIPH_CTR_MODE:
                return TPM2_ALG_CTR;
            case EVP_CIPH_ECB_MODE:
                return TPM2_ALG_ECB;
            case EVP_CIPH_CBC_MODE:
                return TPM2_ALG_CBC;
            default:
                return TPM2_ALG_CBC;
        }
    } else {
        return tpm2Data->pub.publicArea.parameters.symDetail.sym.mode.sym;
    }
}

static int
tpm2_cipher_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
    (void)(iv);
    (void)(enc);
    TPM2_DATA *tpm2Data = NULL;

    DBG("Init Cipher Key ...\n");

    /* Init Struct */
    tpm2Data = OPENSSL_malloc(sizeof(TPM2_DATA));
    if (tpm2Data == NULL) {
        ERR(tpm2_cipher_init_key, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    memset(tpm2Data, 0, sizeof(TPM2_DATA));

    /* Fill TPM2_DATA depending of KEY */
    if (!populate_tpm2data(key, &tpm2Data)) {
        ERR(tpm2_cipher_init_key, TPM2TSS_R_TPM2DATA_READ_FAILED);
        goto error;
    }

    /* Set App Data */
    EVP_CIPHER_CTX_set_app_data(ctx, tpm2Data);

    DBG("algo : %#x", tpm2Data->pub.publicArea.parameters.symDetail.sym.algorithm);
    DBG(" | mode : %#x", tpm2_get_cipher_mode(ctx, tpm2Data));
    DBG(" | size : %d", tpm2Data->pub.publicArea.parameters.symDetail.sym.keyBits.sym);
    DBG(" | enc  : %d", !EVP_CIPHER_CTX_encrypting(ctx));
    DBG(" | iv   : %d\n", EVP_CIPHER_CTX_iv_length(ctx));

    return 1;

error :
    if (tpm2Data)
        OPENSSL_free(tpm2Data);
    return 0;
}

static int
tpm2_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    TPM2_DATA *tpm2Data;
    TSS2_RC ret;
    ESYS_AUXCONTEXT eactx = (ESYS_AUXCONTEXT){ NULL, NULL};
    ESYS_TR keyHandle = ESYS_TR_NONE;
    TPM2B_MAX_BUFFER *out_data, in_data;
    TPM2B_IV *iv_out, iv_in;
    TPMI_ALG_SYM_MODE mode;
    TPMI_YES_NO enc;

    DBG("Ciphering ...\n");

    /* Get App Data */
    tpm2Data = EVP_CIPHER_CTX_get_app_data(ctx);
    if (tpm2Data == NULL || tpm2Data->pub.size == 0 || inl == 0) {
        return 0;
    }

    /* Init TPM key */
    ret = init_tpm_key(&eactx, &keyHandle, tpm2Data);
    ERRchktss(tpm2_do_cipher, ret, goto error);

    /* Copy in_data : unsigned char* to TPM2B_MAX_BUFFER */
    if (inl >= sizeof(in_data.buffer)) {
        ERR(tpm2_do_cipher, TPM2TSS_R_GENERAL_FAILURE);
        goto error;
    }
    memcpy(in_data.buffer, in, inl);
    in_data.size = inl;

    /* Get mode value */
    mode = tpm2_get_cipher_mode(ctx, tpm2Data);

    /* Get IV and Enc*/
    iv_in.size = EVP_CIPHER_CTX_iv_length(ctx);
#if OPENSSL_VERSION_NUMBER < 0x10100000
    memcpy(iv_in.buffer, ctx->iv, iv_in.size);
    // Note: Openssl (encrypt:1) != TSS (encrypt:0)
    enc = !(ctx->encrypt);
#else
    memcpy(iv_in.buffer, EVP_CIPHER_CTX_iv(ctx), iv_in.size);
    enc = !EVP_CIPHER_CTX_encrypting(ctx);
#endif

    /* Trying to encrypt */
    ret = Esys_EncryptDecrypt2( eactx.ectx,
                                keyHandle,
                                ESYS_TR_PASSWORD,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                &in_data,
                                enc,
                                mode,
                                &iv_in,
                                &out_data,
                                &iv_out );
    if (ret == TPM2_RC_COMMAND_CODE) {
        DBG("Esys_EncryptDecrypt2 : FAILED\n");
        DBG("Failing back to Esys_EncryptDecrypt\n");
        ret = Esys_EncryptDecrypt( eactx.ectx,
                                   keyHandle,
                                   ESYS_TR_PASSWORD,
                                   ESYS_TR_NONE,
                                   ESYS_TR_NONE,
                                   enc,
                                   mode,
                                   &iv_in,
                                   &in_data,
                                   &out_data,
                                   &iv_out );
        if(ret == TPM2_RC_SUCCESS) {
            DBG("Esys_EncryptDecrypt  : SUCCESS\n");
        }
        else {
            DBG("Esys_EncryptDecrypt  : FAILED\n");
        }
    }
    ERRchktss(tpm2_do_cipher, ret, goto error);

    /* Copy out_data : TPM2B_MAX_BUFFER to unsigned char* */
    memcpy(out, out_data->buffer, out_data->size);
    out[out_data->size] = '\0';

    /* Close TPM session */
    if (keyHandle != ESYS_TR_NONE) {
        if (tpm2Data->privatetype == KEY_TYPE_HANDLE) {
            Esys_TR_Close(eactx.ectx, &keyHandle);
        } else {
            Esys_FlushContext(eactx.ectx, keyHandle);
        }
    }
    esys_auxctx_free(&eactx);

    return out_data->size;

error :
    /* Close TPM session */
    if (keyHandle != ESYS_TR_NONE) {
        if (tpm2Data->privatetype == KEY_TYPE_HANDLE) {
            Esys_TR_Close(eactx.ectx, &keyHandle);
        } else {
            Esys_FlushContext(eactx.ectx, keyHandle);
        }
    }
    esys_auxctx_free(&eactx);

    if (tpm2Data)
        OPENSSL_free(tpm2Data);
    return 0;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000
static EVP_CIPHER tpm2_aes_256_ofb =
{
    NID_aes_256_ofb128,                 // ID
    TPM2_MAX_SYM_BLOCK_SIZE,            // Block size
    TPM2_MAX_SYM_KEY_BYTES,             // Key length
    TPM2_MAX_SYM_BLOCK_SIZE,            // IV length
    EVP_CIPH_OFB_MODE,                  // Flags
    tpm2_cipher_init_key,               // Init key
    tpm2_do_cipher,                     // Encrypt/Decrypt
    NULL,                               // Cleanup
    sizeof(TPM2_DATA),                  // Context size
    NULL,                               // Set ASN1 parameters
    NULL,                               // Get ASN1 parameters
    NULL,                               // CTRL
    NULL                                // App data
};
#else
static EVP_CIPHER *_tpm2_aes_256_ofb = NULL;
const EVP_CIPHER *tpm2_aes_256_ofb(void)
{
    if (_tpm2_aes_256_ofb == NULL &&
        ((_tpm2_aes_256_ofb = EVP_CIPHER_meth_new(NID_aes_256_ofb128, TPM2_MAX_SYM_BLOCK_SIZE, TPM2_MAX_SYM_KEY_BYTES)) == NULL
         || !EVP_CIPHER_meth_set_iv_length(_tpm2_aes_256_ofb, TPM2_MAX_SYM_BLOCK_SIZE)
         || !EVP_CIPHER_meth_set_flags(_tpm2_aes_256_ofb, EVP_CIPH_OFB_MODE | EVP_CIPH_FLAG_CUSTOM_CIPHER)
         || !EVP_CIPHER_meth_set_init(_tpm2_aes_256_ofb, tpm2_cipher_init_key)
         || !EVP_CIPHER_meth_set_do_cipher(_tpm2_aes_256_ofb, tpm2_do_cipher)
         || !EVP_CIPHER_meth_set_cleanup(_tpm2_aes_256_ofb, NULL)
         || !EVP_CIPHER_meth_set_impl_ctx_size(_tpm2_aes_256_ofb, sizeof(TPM2_DATA))
         || !EVP_CIPHER_meth_set_set_asn1_params(_tpm2_aes_256_ofb, NULL)
         || !EVP_CIPHER_meth_set_get_asn1_params(_tpm2_aes_256_ofb, NULL)
         || !EVP_CIPHER_meth_set_ctrl(_tpm2_aes_256_ofb, NULL)))
    {
        EVP_CIPHER_meth_free(_tpm2_aes_256_ofb);
        _tpm2_aes_256_ofb = NULL;
    }
    return _tpm2_aes_256_ofb;
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000
static EVP_CIPHER tpm2_aes_256_cfb =
{
    NID_aes_256_cfb128,                 // ID
    TPM2_MAX_SYM_BLOCK_SIZE,            // Block size
    TPM2_MAX_SYM_KEY_BYTES,             // Key length
    TPM2_MAX_SYM_BLOCK_SIZE,            // IV length
    EVP_CIPH_CFB_MODE,                  // Flags
    tpm2_cipher_init_key,               // Init key
    tpm2_do_cipher,                     // Encrypt/Decrypt
    NULL,                               // Cleanup
    sizeof(TPM2_DATA),                  // Context size
    NULL,                               // Set ASN1 parameters
    NULL,                               // Get ASN1 parameters
    NULL,                               // CTRL
    NULL                                // App data
};
#else
static EVP_CIPHER *_tpm2_aes_256_cfb = NULL;
const EVP_CIPHER *tpm2_aes_256_cfb(void)
{
    if (_tpm2_aes_256_cfb == NULL &&
        ((_tpm2_aes_256_cfb = EVP_CIPHER_meth_new(NID_aes_256_cfb128, TPM2_MAX_SYM_BLOCK_SIZE, TPM2_MAX_SYM_KEY_BYTES)) == NULL
         || !EVP_CIPHER_meth_set_iv_length(_tpm2_aes_256_cfb, TPM2_MAX_SYM_BLOCK_SIZE)
         || !EVP_CIPHER_meth_set_flags(_tpm2_aes_256_cfb, EVP_CIPH_CFB_MODE | EVP_CIPH_FLAG_CUSTOM_CIPHER)
         || !EVP_CIPHER_meth_set_init(_tpm2_aes_256_cfb, tpm2_cipher_init_key)
         || !EVP_CIPHER_meth_set_do_cipher(_tpm2_aes_256_cfb, tpm2_do_cipher)
         || !EVP_CIPHER_meth_set_cleanup(_tpm2_aes_256_cfb, NULL)
         || !EVP_CIPHER_meth_set_impl_ctx_size(_tpm2_aes_256_cfb, sizeof(TPM2_DATA))
         || !EVP_CIPHER_meth_set_set_asn1_params(_tpm2_aes_256_cfb, NULL)
         || !EVP_CIPHER_meth_set_get_asn1_params(_tpm2_aes_256_cfb, NULL)
         || !EVP_CIPHER_meth_set_ctrl(_tpm2_aes_256_cfb, NULL)))
    {
        EVP_CIPHER_meth_free(_tpm2_aes_256_cfb);
        _tpm2_aes_256_cfb = NULL;
    }
    return _tpm2_aes_256_cfb;
}
#endif

static int
tpm2_ciphers_selector(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
    (void)(e);
    int ret = 1;

    if (cipher == NULL) {
        *nids = tpm2_cipher_nids;
        return sizeof(tpm2_cipher_nids) / sizeof(tpm2_cipher_nids[0]) - 1;
    }

   switch (nid) {
    case NID_aes_256_ofb128:
#if OPENSSL_VERSION_NUMBER < 0x10100000
        *cipher = &tpm2_aes_256_ofb;
#else
        *cipher = tpm2_aes_256_ofb();
#endif
        break;

    case NID_aes_256_cfb128:
#if OPENSSL_VERSION_NUMBER < 0x10100000
        *cipher = &tpm2_aes_256_cfb;
#else
        *cipher = tpm2_aes_256_cfb();
#endif
        break;
    default:
        *cipher = NULL;
        ret = 0;
        break;
    }

    return ret;
}

int
init_ciphers(ENGINE *e)
{
    if (!ENGINE_set_ciphers(e, tpm2_ciphers_selector)) {
        DBG("ENGINE_set_ciphers failed\n");
        return 0;
    }

    return 1;
}
