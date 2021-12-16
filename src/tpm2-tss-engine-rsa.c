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

#include <string.h>

#include <openssl/engine.h>
#include <tss2/tss2_esys.h>

#include "tpm2-tss-engine.h"
#include "tpm2-tss-engine-common.h"

#define chkerr_goto(x) if (x) { DBG("%s:%i:%s: Error 0x%04x\n", __FILE__, \
                                       __LINE__, __func__, x); goto error; }

const RSA_METHOD *default_rsa = NULL;

#if OPENSSL_VERSION_NUMBER < 0x10100000
RSA_METHOD rsa_methods;
#else /* OPENSSL_VERSION_NUMBER < 0x10100000 */
RSA_METHOD *rsa_methods = NULL;
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */

#ifdef HAVE_OPENSSL_DIGEST_SIGN
static int (*rsa_pkey_orig_copy)(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);
static void (*rsa_pkey_orig_cleanup)(EVP_PKEY_CTX *ctx);
#endif /* HAVE_OPENSSL_DIGEST_SIGN */

static TPM2B_DATA allOutsideInfo = {
    .size = 0,
};

static TPML_PCR_SELECTION allCreationPCR = {
    .count = 0,
};

static TPM2B_PUBLIC keyTemplate = {
    .publicArea = {
        .type = TPM2_ALG_RSA,
        .nameAlg = ENGINE_HASH_ALG,
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                             TPMA_OBJECT_SIGN_ENCRYPT |
                             TPMA_OBJECT_DECRYPT |
                             TPMA_OBJECT_FIXEDTPM |
                             TPMA_OBJECT_FIXEDPARENT |
                             TPMA_OBJECT_SENSITIVEDATAORIGIN |
                             TPMA_OBJECT_NODA),
        .authPolicy.size = 0,
        .parameters.rsaDetail = {
             .symmetric = {
                 .algorithm = TPM2_ALG_NULL,
                 .keyBits.aes = 0,
                 .mode.aes = 0,
              },
             .scheme = {
                .scheme = TPM2_ALG_NULL,
                .details = {}
             },
             .keyBits = 0,          /* to be set by the genkey function */
             .exponent = 0,         /* to be set by the genkey function */
         },
        .unique.rsa.size = 0
     }
};

/** Sign data using a TPM key
 *
 * This function performs the encrypt function using the private key in RSA.
 * This operation is usually used to perform signature and authentication
 * operations.
 * @param flen Length of the from buffer.
 * @param from The data to be signed.
 * @param to The buffer to write the signature to.
 * @param rsa The rsa key object.
 * @param padding The padding scheme to be used.
 * @retval 0 on failure
 * @retval size Size of the returned signature
 */
static int
rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa,
             int padding)
{
    TPM2_DATA *tpm2Data = RSA_get_app_data(rsa);

    /* If this is not a TPM2 key, fall through to software functions */
    if (tpm2Data == NULL) {
        DBG("Non-TPM key passed. Calling standard function.\n");
#if OPENSSL_VERSION_NUMBER < 0x10100000
        return default_rsa->rsa_priv_enc(flen, from, to, rsa, padding);
#else /* OPENSSL_VERSION_NUMBER < 0x10100000 */
        return RSA_meth_get_priv_enc(default_rsa)(flen, from, to, rsa, padding);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */
    }

    DBG("rsa_priv_enc called for scheme %i and input data(size=%i):\n",
        padding, flen);
    DBGBUF(from, flen);

    int ret = 0;
    TSS2_RC r = TSS2_RC_SUCCESS;
    ESYS_CONTEXT *esys_ctx = NULL;
    ESYS_TR keyHandle = ESYS_TR_NONE;
    TPM2B_DATA label = { .size = 0 };
    TPM2B_PUBLIC_KEY_RSA *sig = NULL;
    TPMT_RSA_DECRYPT inScheme = { .scheme = TPM2_ALG_NULL };

    TPM2B_PUBLIC_KEY_RSA digest;
    digest.size = RSA_size(rsa);
    if (digest.size > sizeof(digest.buffer)) {
        ERR(rsa_priv_enc, TPM2TSS_R_DIGEST_TOO_LARGE);
        goto error;
    }

    switch (padding) {
    case RSA_PKCS1_PADDING:
        ret = RSA_padding_add_PKCS1_type_1(&digest.buffer[0], digest.size,
                                           from, flen);
        break;
    case RSA_X931_PADDING:
        ret = RSA_padding_add_X931(&digest.buffer[0], digest.size, from, flen);
        break;
    case RSA_NO_PADDING:
        ret = RSA_padding_add_none(&digest.buffer[0], digest.size, from, flen);
        break;
    default:
        ERR(rsa_priv_enc, TPM2TSS_R_PADDING_UNKNOWN);
        goto error;
    }
    if (ret <= 0) {
        ERR(rsa_priv_enc, TPM2TSS_R_PADDING_FAILED);
        goto error;
    }

    DBG("Padded digest data (size=%i):\n", digest.size);
    DBGBUF(&digest.buffer[0], digest.size);

    r = init_tpm_key(&esys_ctx, &keyHandle, tpm2Data);
    ERRchktss(rsa_priv_enc, r, goto error);

    DBG("Signing (via decrypt operation).\n");
    r = Esys_RSA_Decrypt(esys_ctx, keyHandle,
                         ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                         &digest, &inScheme, &label, &sig);
    ERRchktss(rsa_priv_enc, r, goto error);

    DBG("Signature done (size=%i):\n", sig->size);
    DBGBUF(&sig->buffer[0], sig->size);

    ret = sig->size;
    if (ret > RSA_size(rsa) || ret <= 0) {
        ERR(rsa_priv_enc, TPM2TSS_R_DIGEST_TOO_LARGE);
        goto error;
    }
    memcpy(to, &sig->buffer[0], ret);

    goto out;

 error:
    r = -1;

 out:
    free(sig);
    if (keyHandle != ESYS_TR_NONE) {
        if (tpm2Data->privatetype == KEY_TYPE_HANDLE) {
            Esys_TR_Close(esys_ctx, &keyHandle);
        } else {
            Esys_FlushContext(esys_ctx, keyHandle);
        }
    }
    esys_ctx_free(&esys_ctx);
    return (r == TSS2_RC_SUCCESS) ? ret : 0;
}

/** Decrypt data using a TPM key
 *
 * This function performs the decrypt function using the private key in RSA.
 * @param flen Length of the from buffer.
 * @param from The data to be decrypted.
 * @param to The buffer to write the plaintext to.
 * @param rsa The rsa key object.
 * @param padding The padding scheme to be used.
 * @retval 0 on failure
 * @retval size Size of the returned plaintext
 */
static int
rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA * rsa,
             int padding)
{
    TPM2_DATA *tpm2Data = RSA_get_app_data(rsa);

    /* If this is not a TPM2 key, fall through to software functions */
    if (tpm2Data == NULL)
#if OPENSSL_VERSION_NUMBER < 0x10100000
        return default_rsa->rsa_priv_dec(flen, from, to, rsa, padding);
#else /* OPENSSL_VERSION_NUMBER < 0x10100000 */
        return RSA_meth_get_priv_dec(default_rsa)(flen, from, to, rsa, padding);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */

    DBG("rsa_priv_dec called for scheme %i and input data(size=%i):\n",
        padding, flen);
    DBGBUF(from, flen);

    TSS2_RC r;
    ESYS_CONTEXT *esys_ctx = NULL;
    ESYS_TR keyHandle = ESYS_TR_NONE;
    TPM2B_DATA label = { .size = 0 };
    TPM2B_PUBLIC_KEY_RSA *message = NULL;
    TPMT_RSA_DECRYPT inScheme;

    TPM2B_PUBLIC_KEY_RSA cipher = { .size = flen };
    if (flen > (int)sizeof(cipher.buffer) || flen < 0) {
        ERR(rsa_priv_dec, TPM2TSS_R_DIGEST_TOO_LARGE);
        goto error;
    }
    memcpy(&cipher.buffer[0], from, flen);

    switch (padding) {
    case RSA_PKCS1_PADDING:
        inScheme.scheme = TPM2_ALG_RSAES;
        break;
    case RSA_PKCS1_OAEP_PADDING:
        inScheme.scheme = TPM2_ALG_OAEP;
        inScheme.details.oaep.hashAlg = TPM2_ALG_SHA1;
        break;
    default:
        ERR(rsa_priv_dec, TPM2TSS_R_PADDING_UNKNOWN);
        goto error;
    }

    r = init_tpm_key(&esys_ctx, &keyHandle, tpm2Data);
    ERRchktss(rsa_priv_dec, r, goto out);

    r = Esys_RSA_Decrypt(esys_ctx, keyHandle,
                         ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                         &cipher, &inScheme, &label, &message);
    ERRchktss(rsa_priv_dec, r, goto out);

    DBG("Decrypted message (size=%i):\n", message->size);
    DBGBUF(&message->buffer[0], message->size);

    flen = message->size;
    if (flen > RSA_size(rsa) || flen <= 0) {
        ERR(rsa_priv_dec, TPM2TSS_R_DIGEST_TOO_LARGE);
        goto error;
    }
    memcpy(to, &message->buffer[0], flen);

    goto out;

 error:
    r = -1;

 out:
    free(message);
    if (keyHandle != ESYS_TR_NONE) {
        if (tpm2Data->privatetype == KEY_TYPE_HANDLE) {
            Esys_TR_Close(esys_ctx, &keyHandle);
        } else {
            Esys_FlushContext(esys_ctx, keyHandle);
        }
    }

    esys_ctx_free(&esys_ctx);
    return (r == TSS2_RC_SUCCESS) ? flen : 0;
}

/** Clean up the RSA key
 *
 * @param rsa The rsa key object.
 * @retval 1 on success, or 0 on failure
 */
static int
rsa_finish(RSA *rsa)
{
    TPM2_DATA *tpm2Data = RSA_get_app_data(rsa);

    if (tpm2Data != NULL)
        OPENSSL_free(tpm2Data);

    return 1;
}

/** Helper to populate the RSA key object.
 *
 * In order to use an RSA key object in a typical manner, all fields of the
 * OpenSSL's corresponding object bust be filled. This function fills the public
 * values correctly and fill the private values with 0.
 * @param rsa The key object to fill.
 * @retval 0 on failure
 * @retval 1 on success
 */
static int
populate_rsa(RSA *rsa)
{
    TPM2_DATA *tpm2Data = RSA_get_app_data(rsa);
    UINT32 exponent;

    if (tpm2Data == NULL)
        goto error;

    exponent = tpm2Data->pub.publicArea.parameters.rsaDetail.exponent;
    if (!exponent)
        exponent = 0x10001;

#if OPENSSL_VERSION_NUMBER < 0x10100000
    /* Setting the public portion of the key */
    rsa->n = BN_bin2bn(tpm2Data->pub.publicArea.unique.rsa.buffer,
                       tpm2Data->pub.publicArea.unique.rsa.size, rsa->n);
    if (rsa->n == NULL) {
        ERR(populate_rsa, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    if (rsa->e == NULL)
        rsa->e = BN_new();
    if (rsa->e == NULL) {
        ERR(populate_rsa, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    BN_set_word(rsa->e, exponent);

    /* Setting private portions to 0 values so the public key can be extracted
       from the keyfile if this is desired. */
    if (rsa->d == NULL)
        rsa->d = BN_new();
    if (rsa->d == NULL) {
        ERR(populate_rsa, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    BN_set_word(rsa->d, 0);
    if (rsa->p == NULL)
        rsa->p = BN_new();
    if (rsa->p == NULL) {
        ERR(populate_rsa, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    BN_set_word(rsa->p, 0);
    if (rsa->q == NULL)
        rsa->q = BN_new();
    if (rsa->q == NULL) {
        ERR(populate_rsa, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    BN_set_word(rsa->q, 0);
    if (rsa->dmp1 == NULL)
        rsa->dmp1 = BN_new();
    if (rsa->dmp1 == NULL) {
        ERR(populate_rsa, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    BN_set_word(rsa->dmp1, 0);
    if (rsa->dmq1 == NULL)
        rsa->dmq1 = BN_new();
    if (rsa->dmq1 == NULL) {
        ERR(populate_rsa, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    BN_set_word(rsa->dmq1, 0);
    if (rsa->iqmp == NULL)
        rsa->iqmp = BN_new();
    if (rsa->iqmp == NULL) {
        ERR(populate_rsa, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    BN_set_word(rsa->iqmp, 0);
#else /* OPENSSL_VERSION_NUMBER < 0x10100000 */
    BIGNUM *n = BN_bin2bn(tpm2Data->pub.publicArea.unique.rsa.buffer,
                          tpm2Data->pub.publicArea.unique.rsa.size, NULL);
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *dmp1 = BN_new();
    BIGNUM *dmq1 = BN_new();
    BIGNUM *iqmp = BN_new();

    if (!n || !e || !d || !p || !q || !dmp1 || !dmq1 || !iqmp) {
        if (n)
            BN_free(n);
        if (e)
            BN_free(e);
        if (d)
            BN_free(d);
        if (p)
            BN_free(p);
        if (q)
            BN_free(q);
        if (dmp1)
            BN_free(dmp1);
        if (dmq1)
            BN_free(dmq1);
        if (iqmp)
            BN_free(iqmp);

        ERR(populate_rsa, ERR_R_MALLOC_FAILURE);
        goto error;
    }

    BN_set_word(e, exponent);
    BN_set_word(d, 0);
    BN_set_word(p, 0);
    BN_set_word(q, 0);
    BN_set_word(dmp1, 0);
    BN_set_word(dmq1, 0);
    BN_set_word(iqmp, 0);

    RSA_set0_key(rsa, n, e, d);
    RSA_set0_factors(rsa, p, q);
    RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */

    return 1;
 error:
    return 0;
}

/** Helper to load an RSA key from a tpm2Data
 *
 * This function creates a key object given a TPM2_DATA object. The resulting
 * key object can then be used for signing and decrypting with the tpm2tss
 * engine. Ownership of the TPM2_DATA object is taken on success.
 * @param tpm2Data The key data to use. Must have been allocated using
 * OPENSSL_malloc.
 * @retval key The key object
 * @retval NULL on failure.
 */
EVP_PKEY *
tpm2tss_rsa_makekey(TPM2_DATA *tpm2Data)
{
    EVP_PKEY *pkey;
    RSA *rsa;

    DBG("Creating RSA key object.\n");

    /* create the new objects to return */
    if ((pkey = EVP_PKEY_new()) == NULL) {
        ERR(populate_rsa, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if ((rsa = RSA_new()) == NULL) {
        ERR(populate_rsa, ERR_R_MALLOC_FAILURE);
        EVP_PKEY_free(pkey);
        return NULL;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000
    rsa->meth = &rsa_methods;
#else /* OPENSSL_VERSION_NUMBER < 0x10100000 */
    RSA_set_method(rsa, rsa_methods);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */

    if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
        ERR(populate_rsa, TPM2TSS_R_GENERAL_FAILURE);
        RSA_free(rsa);
        goto error;
    }

    if (!RSA_set_app_data(rsa, tpm2Data)) {
        ERR(populate_rsa, TPM2TSS_R_GENERAL_FAILURE);
        goto error;
    }

    if (!populate_rsa(rsa)) {
        RSA_set_app_data(rsa, NULL);
        goto error;
    }

    DBG("Created RSA key object.\n");

    return pkey;
 error:
    EVP_PKEY_free(pkey);
    return NULL;
}

/** Generate a tpm2tss rsa key object.
 *
 * This function creates a new TPM RSA key. The TPM data is stored inside the
 * object*s app data and can be retrieved using RSA_get_app_data().
 * @param rsa The key object for the TPM RSA key to be created.
 * @param bits The key size
 * @param e The key's exponent
 * @param password The Password to be set for the new key
 * @retval 1 on success
 * @retval 0 on failure
 */
int
tpm2tss_rsa_genkey(RSA *rsa, int bits, BIGNUM *e, char *password,
                   TPM2_HANDLE parentHandle)
{
    DBG("Generating RSA key for %i bits keysize.\n", bits);

    TSS2_RC r = TSS2_RC_SUCCESS;
    ESYS_CONTEXT *esys_ctx = NULL;
    ESYS_TR parent = ESYS_TR_NONE;
    TPM2B_PUBLIC *keyPublic = NULL;
    TPM2B_PRIVATE *keyPrivate = NULL;
    TPM2_DATA *tpm2Data = NULL;
    TPM2B_PUBLIC inPublic = keyTemplate;
    TPM2B_SENSITIVE_CREATE inSensitive = {
        .sensitive = {
            .userAuth = {
                 .size = 0,
             },
            .data = {
                 .size = 0,
             }
        }
    };

    tpm2Data = OPENSSL_malloc(sizeof(*tpm2Data));
    if (tpm2Data == NULL) {
        ERR(tpm2tss_rsa_genkey, TPM2TSS_R_GENERAL_FAILURE);
        goto error;
    }
    memset(tpm2Data, 0, sizeof(*tpm2Data));

    inPublic.publicArea.parameters.rsaDetail.keyBits = bits;
    if (e)
        inPublic.publicArea.parameters.rsaDetail.exponent = BN_get_word(e);

    if (password) {
        DBG("Setting a password for the created key.\n");
        if (strlen(password) > sizeof(tpm2Data->userauth.buffer) - 1) {
            goto error;
        }
        tpm2Data->userauth.size = strlen(password);
        memcpy(&tpm2Data->userauth.buffer[0], password,
               tpm2Data->userauth.size);

        inSensitive.sensitive.userAuth.size = strlen(password);
        memcpy(&inSensitive.sensitive.userAuth.buffer[0], password,
               strlen(password));
    } else
        tpm2Data->emptyAuth = 1;

    r = init_tpm_parent(&esys_ctx, parentHandle, &parent);
    ERRchktss(tpm2tss_rsa_genkey, r, goto error);

    tpm2Data->parent = parentHandle;

    DBG("Generating the RSA key inside the TPM.\n");

    r = Esys_Create(esys_ctx, parent,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                    &inSensitive, &inPublic, &allOutsideInfo, &allCreationPCR,
                    &keyPrivate, &keyPublic, NULL, NULL, NULL);
    ERRchktss(tpm2tss_rsa_genkey, r, goto error);

    DBG("Generated the RSA key inside the TPM.\n");

    tpm2Data->pub = *keyPublic;
    tpm2Data->priv = *keyPrivate;

    if (!RSA_set_app_data(rsa, tpm2Data)) {
        ERR(tpm2tss_rsa_genkey, TPM2TSS_R_GENERAL_FAILURE);
        goto error;
    }

    if (!populate_rsa(rsa)) {
        goto error;
    }

    goto end;
 error:
    r = -1;
    if (rsa)
        RSA_set_app_data(rsa, NULL);
    if (tpm2Data)
        OPENSSL_free(tpm2Data);

 end:
    free(keyPrivate);
    free(keyPublic);

    if (parent != ESYS_TR_NONE && !parentHandle)
        Esys_FlushContext(esys_ctx, parent);

    esys_ctx_free(&esys_ctx);

    return (r == TSS2_RC_SUCCESS);
}

#if OPENSSL_VERSION_NUMBER < 0x10100000
RSA_METHOD rsa_methods = {
    "TPM2TSS RSA methods",
    NULL,                       /* tpm_rsa_pub_enc */
    NULL,                       /* tpm_rsa_pub_dec */
    rsa_priv_enc,               /* act sign */
    rsa_priv_dec,               /* act decrypt */
    NULL,                       /* rsa_mod_exp */
    NULL,                       /* bn_mod_exp */
    NULL,                       /* init */
    NULL,                       /* finish */
    0,
    NULL,                       /* app_data */
    NULL,                       /* sign */
    NULL,                       /* verify */
    NULL                        /* genkey */
};
#endif                          /* OPENSSL_VERSION_NUMBER < 0x10100000 */

#ifdef HAVE_OPENSSL_DIGEST_SIGN
static int
rsa_pkey_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    if (rsa_pkey_orig_copy && !rsa_pkey_orig_copy(dst, src))
        return 0;

    return digest_sign_copy(dst, src);
}

static void
rsa_pkey_cleanup(EVP_PKEY_CTX *ctx)
{
    digest_sign_cleanup(ctx);

    if (rsa_pkey_orig_cleanup)
        rsa_pkey_orig_cleanup(ctx);
}

/* called for digest & sign init, after message digest algorithm set */
static int
rsa_digest_custom(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    TPM2_DATA *tpm2data = RSA_get_app_data(rsa);

    DBG("rsa_digest_custom %p %p\n", ctx, mctx);

    return digest_sign_init(ctx, mctx, tpm2data, RSA_size(rsa));
}

static int
rsa_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
            EVP_MD_CTX *mctx)
{
    TPM2_SIG_DATA *sig_data = EVP_PKEY_CTX_get_app_data(ctx);
    TSS2_RC r = TSS2_RC_SUCCESS;
    TPMT_TK_HASHCHECK *validation_ptr = NULL;
    TPM2B_DIGEST *digest_ptr = NULL;
    TPMT_SIGNATURE *tpm_sig = NULL;
    int pad_mode;

    DBG("rsa_signctx %p %p sig_data %p\n", ctx, mctx, sig_data);

    if (!sig) {
        /* caller just wants to know the size */
        *siglen = sig_data->sig_size;
        return 1;
    }

    if (!sig_data) {
        /* handle non-TPM key */
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int md_len = 0;

        if (!EVP_DigestFinal_ex(mctx, md, &md_len))
            return 0;
        if (EVP_PKEY_sign(ctx, sig, siglen, md, md_len) <= 0)
            return 0;
        return 1;
    }

    if (EVP_PKEY_CTX_get_rsa_padding(ctx, &pad_mode) <= 0)
        return 0;

    TPMT_SIG_SCHEME in_scheme = {
        .scheme = TPM2_ALG_NULL,
        .details.rsassa.hashAlg = sig_data->hash_alg,
    };
    switch (pad_mode) {
    case RSA_PKCS1_PADDING:
        in_scheme.scheme = TPM2_ALG_RSASSA;
        break;
    case RSA_PKCS1_PSS_PADDING:
        in_scheme.scheme = TPM2_ALG_RSAPSS;
        break;
    default:
        ERR(rsa_signctx, TPM2TSS_R_PADDING_UNKNOWN);
        return 0;
    }

    if (!digest_finish(sig_data, &digest_ptr, &validation_ptr))
        return 0;

    r = Esys_Sign(sig_data->key->esys_ctx, sig_data->key->key_handle,
                  ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                  digest_ptr, &in_scheme, validation_ptr, &tpm_sig);
    ERRchktss(rsa_signctx, r, goto error);

    memcpy(sig, tpm_sig->signature.rsassa.sig.buffer, sig_data->sig_size);
    *siglen = sig_data->sig_size;

    r = 1;
    goto out;

 error:
    r = 0;
 out:
    free(tpm_sig);
    free(digest_ptr);
    free(validation_ptr);

    return r;
}
#endif /* HAVE_OPENSSL_DIGEST_SIGN */

/** Initialize the tpm2tss engine's rsa submodule
 *
 * Initialize the tpm2tss engine's submodule by setting function pointer.
 * @param e The engine context.
 * @retval 1 on success
 * @retval 0 on failure
 */
int
init_rsa(ENGINE *e)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000
    default_rsa = RSA_PKCS1_SSLeay();
    if (default_rsa == NULL)
        return 0;

    rsa_methods.rsa_pub_enc = default_rsa->rsa_pub_enc;
    rsa_methods.rsa_pub_dec = default_rsa->rsa_pub_dec;
    rsa_methods.rsa_mod_exp = default_rsa->rsa_mod_exp;
    rsa_methods.bn_mod_exp = default_rsa->bn_mod_exp;

    if (!ENGINE_set_RSA(e, &rsa_methods))
        return 0;
#else /* OPENSSL_VERSION_NUMBER < 0x10100000 */
    default_rsa = RSA_PKCS1_OpenSSL();
    if (default_rsa == NULL)
        return 0;

    rsa_methods = RSA_meth_dup(default_rsa);
    RSA_meth_set1_name(rsa_methods, "TPM2TSS RSA methods");
    RSA_meth_set_priv_enc(rsa_methods, rsa_priv_enc);
    RSA_meth_set_priv_dec(rsa_methods, rsa_priv_dec);
    RSA_meth_set_finish(rsa_methods, rsa_finish);

    if (!ENGINE_set_RSA(e, rsa_methods))
        return 0;
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */

#if HAVE_OPENSSL_DIGEST_SIGN
    /* digest and sign support */

    EVP_PKEY_METHOD *pkey_rsa_methods;

    pkey_rsa_methods = EVP_PKEY_meth_new(EVP_PKEY_RSA,
                                         EVP_PKEY_FLAG_AUTOARGLEN);
    if (pkey_rsa_methods == NULL)
        return 0;

    const EVP_PKEY_METHOD *pkey_orig_rsa_methods =
        EVP_PKEY_meth_find(EVP_PKEY_RSA);
    if (pkey_orig_rsa_methods == NULL)
        return 0;
    EVP_PKEY_meth_copy(pkey_rsa_methods, pkey_orig_rsa_methods);
    /*
     * save originals since we only override some of the pkey
     * functionality, rather than reimplementing all of it
     */
    EVP_PKEY_meth_get_copy(pkey_rsa_methods, &rsa_pkey_orig_copy);
    EVP_PKEY_meth_get_cleanup(pkey_rsa_methods, &rsa_pkey_orig_cleanup);

    EVP_PKEY_meth_set_copy(pkey_rsa_methods, rsa_pkey_copy);
    EVP_PKEY_meth_set_cleanup(pkey_rsa_methods, rsa_pkey_cleanup);
    EVP_PKEY_meth_set_signctx(pkey_rsa_methods, NULL, rsa_signctx);
    EVP_PKEY_meth_set_digest_custom(pkey_rsa_methods, rsa_digest_custom);
    EVP_PKEY_meth_add0(pkey_rsa_methods);
#endif /* HAVE_OPENSSL_DIGEST_SIGN */

    return 1;
}
