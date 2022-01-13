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
#include <openssl/ec.h>
#include <openssl/ecdsa.h>

#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>

#include "tpm2-tss-engine.h"
#include "tpm2-tss-engine-common.h"

static int ec_key_app_data = -1;

#if OPENSSL_VERSION_NUMBER < 0x10100000
const ECDSA_METHOD *ecc_method_default = NULL;
ECDSA_METHOD *ecc_methods = NULL;
#else /* OPENSSL_VERSION_NUMBER < 0x10100000 */
const EC_KEY_METHOD *ecc_method_default = NULL;
EC_KEY_METHOD *ecc_methods = NULL;
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */

#ifdef HAVE_OPENSSL_DIGEST_SIGN
static int (*ecdsa_pkey_orig_copy)(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);
static void (*ecdsa_pkey_orig_cleanup)(EVP_PKEY_CTX *ctx);
#endif /* HAVE_OPENSSL_DIGEST_SIGN */

static TPM2B_DATA allOutsideInfo = {
    .size = 0,
};

static TPML_PCR_SELECTION allCreationPCR = {
    .count = 0,
};

static TPM2B_PUBLIC keyEcTemplate = {
    .publicArea = {
        .type = TPM2_ALG_ECC,
        .nameAlg = ENGINE_HASH_ALG,
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                             TPMA_OBJECT_SIGN_ENCRYPT |
                             TPMA_OBJECT_FIXEDTPM |
                             TPMA_OBJECT_FIXEDPARENT |
                             TPMA_OBJECT_SENSITIVEDATAORIGIN |
                             TPMA_OBJECT_NODA),
        .parameters.eccDetail = {
             .curveID = 0, /* To be filled out later */
             .symmetric = {
                 .algorithm = TPM2_ALG_NULL,
                 .keyBits.aes = 0,
                 .mode.aes = 0,
              },
             .scheme = {
                .scheme = TPM2_ALG_NULL,
                .details = {}
             },
             .kdf = {
                .scheme = TPM2_ALG_NULL,
                .details = {}
             },
         },
        .unique.ecc = {
             .x.size = 0,
             .y.size = 0
         }
     }
};

#if OPENSSL_VERSION_NUMBER < 0x10100000
static int EC_GROUP_order_bits(const EC_GROUP *group)
{
    if (!group)
        return 0;

    BIGNUM *order = BN_new();

    if (order == NULL) {
        ERR_clear_error();
        return 0;
    }

    int ret = 0;

    if (!EC_GROUP_get_order(group, order, NULL)) {
        ERR_clear_error();
        BN_free(order);
        return 0;
    }

    ret = BN_num_bits(order);
    BN_free(order);
    return ret;
}
#else /* OPENSSL_VERSION_NUMBER < 0x10100000 */
 /**
  * Initialize a TPM2B_ECC_POINT from an OpenSSL EC_POINT.
  *
  * @param point Pointer to output tpm point
  * @param pub_key OpenSSL public key to convert
  * @param group Curve group
  * @retval 0 on failure
  */
static int
init_tpm_public_point(TPM2B_ECC_POINT *point, const EC_POINT *ec_point,
                        const EC_GROUP *ec_group)
{
    unsigned char buffer[1 + sizeof(point->point.x.buffer)
                           + sizeof(point->point.y.buffer)] = {0};

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx)
        return 0;

    BN_CTX_start(ctx);

    size_t len = 0;

    // first, check for actual buffer size required
    if ((len = EC_POINT_point2oct(ec_group, ec_point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx)) <= sizeof(buffer)) {
        len = EC_POINT_point2oct(ec_group, ec_point,
                    POINT_CONVERSION_UNCOMPRESSED, buffer, sizeof(buffer), ctx);
    }

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    if (len == 0 || len > sizeof(buffer))
        return 0;

    len = (len - 1) / 2;

    point->point.x.size = len;
    point->point.y.size = len;
    memcpy(point->point.x.buffer, &buffer[1], len);
    memcpy(point->point.y.buffer, &buffer[1 + len], len);

    return 1;
}

/**
 * Generate a shared secret using a TPM key
 *
 * @param psec Pointer to output buffer holding shared secret
 * @param pseclen Size of the psec buffer
 * @param pub_key The peer's public key
 * @param ecdh The ECC key object for the host private key
 * @retval 0 on failure
 */
static int
ecdh_compute_key(unsigned char **psec, size_t *pseclen,
                    const EC_POINT *pub_key, const EC_KEY *eckey)
{
    /*
     * If this is not a TPM2 key, bail out since fall through to software
     * functions requires a non-const EC_KEY, yet the ECDH prototype only
     * provides it as const.
     */
    TPM2_DATA *tpm2Data = tpm2tss_ecc_getappdata(eckey);
    if (tpm2Data == NULL)
        return 0;

    TPM2B_ECC_POINT inPoint;
    TPM2B_ECC_POINT *outPoint = NULL;
    const EC_GROUP *group = EC_KEY_get0_group(eckey);

    int ret = init_tpm_public_point(&inPoint, pub_key, group);
    if (!ret)
        return 0;

    ESYS_CONTEXT *esys_ctx = NULL;
    ESYS_TR keyHandle = ESYS_TR_NONE;
    TSS2_RC r = init_tpm_key(&esys_ctx, &keyHandle, tpm2Data);
    ERRchktss(ecdh_compute_key, r, goto error);

    r = Esys_ECDH_ZGen(esys_ctx, keyHandle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &inPoint, &outPoint);
    ERRchktss(ecdh_compute_key, r, goto error);

    *pseclen = outPoint->point.x.size;
    *psec = OPENSSL_malloc(*pseclen);
    if (!*psec)
        goto error;

    memcpy(*psec, outPoint->point.x.buffer, *pseclen);
    ret = 1;
    goto out;
error:
    ret = 0;
out:
    if (keyHandle != ESYS_TR_NONE) {
        if (tpm2Data->privatetype == KEY_TYPE_HANDLE) {
            Esys_TR_Close(esys_ctx, &keyHandle);
        } else {
            Esys_FlushContext(esys_ctx, keyHandle);
        }
    }
    Esys_Free(outPoint);
    esys_ctx_free(&esys_ctx);
    return ret;
}
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */

static ECDSA_SIG *
ecdsa_sign(ESYS_CONTEXT *esys_ctx, ESYS_TR key_handle,
	   TPM2B_DIGEST *digest, TPMT_TK_HASHCHECK *validation,
	   TPM2_ALG_ID hash_alg)
{
    TPMT_SIG_SCHEME inScheme = {
      .scheme = TPM2_ALG_ECDSA,
      .details.ecdsa.hashAlg = hash_alg,
    };
    BIGNUM *bns = NULL, *bnr = NULL;
    ECDSA_SIG *ret = NULL;
    TPMT_SIGNATURE *sig = NULL;
    TSS2_RC r;

    r = Esys_Sign(esys_ctx, key_handle, ESYS_TR_PASSWORD,
                  ESYS_TR_NONE, ESYS_TR_NONE, digest, &inScheme,
                  validation, &sig);
    ERRchktss(ecdsa_sign, r, goto error);

    ret = ECDSA_SIG_new();
    if (ret == NULL) {
        ERR(ecdsa_sign, ERR_R_MALLOC_FAILURE);
        goto error;
    }

    bns = BN_bin2bn(&sig->signature.ecdsa.signatureS.buffer[0],
                    sig->signature.ecdsa.signatureS.size, NULL);
    bnr = BN_bin2bn(&sig->signature.ecdsa.signatureR.buffer[0],
                    sig->signature.ecdsa.signatureR.size, NULL);
    if (!bns || !bnr) {
        ERR(ecdsa_sign, ERR_R_MALLOC_FAILURE);
        goto error;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000
    ret->s = bns;
    ret->r = bnr;
#else /* OPENSSL_VERSION_NUMBER < 0x10100000 */
    ECDSA_SIG_set0(ret, bnr, bns);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */

    goto out;

 error:
    if (bns)
      BN_free(bns);
    if (bnr)
      BN_free(bnr);
    if (ret)
      ECDSA_SIG_free(ret);
    ret = NULL;
 out:
    Esys_Free(sig);
    return ret;
}

/** Sign data using a TPM key
 *
 * This function performs the sign function using the private key in ECDSA.
 * This operation is usually used to perform signature and authentication
 * operations.
 * @param dgst The data to be signed.
 * @param dgst_len Length of the from buffer.
 * @param inv Ignored
 * @param rp Ignored
 * @param eckey The ECC key object.
 * @retval 0 on failure
 * @retval size Size of the returned signature
 */
static ECDSA_SIG *
ecdsa_ec_key_sign(const unsigned char *dgst, int dgst_len, const BIGNUM *inv,
		  const BIGNUM *rp, EC_KEY *eckey)
{
    ECDSA_SIG *ret = NULL;
    TPM2_DATA *tpm2Data = tpm2tss_ecc_getappdata(eckey);
    TPM2_ALG_ID hash_alg;

    /* If this is not a TPM2 key, fall through to software functions */
    if (tpm2Data == NULL) {
#if OPENSSL_VERSION_NUMBER < 0x10100000
        ECDSA_set_method(eckey, ecc_method_default);
        ret = ECDSA_do_sign_ex(dgst, dgst_len, inv, rp, eckey);
        ECDSA_set_method(eckey, ecc_methods);
        return ret;
#else /* OPENSSL_VERSION_NUMBER < 0x10100000 */
        EC_KEY_set_method(eckey, ecc_method_default);
        ret = ECDSA_do_sign_ex(dgst, dgst_len, inv, rp, eckey);
        EC_KEY_set_method(eckey, ecc_methods);
        return ret;
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */
    }

    DBG("ecdsa_sign called for input data(size=%i):\n", dgst_len);
    DBGBUF(dgst, dgst_len);

    TSS2_RC r;
    ESYS_CONTEXT *esys_ctx = NULL;
    ESYS_TR keyHandle = ESYS_TR_NONE;

    TPMT_TK_HASHCHECK validation = { .tag = TPM2_ST_HASHCHECK,
                                     .hierarchy = TPM2_RH_NULL,
                                     .digest.size = 0 };

    /*
     * ECDSA signatures truncate the incoming hash to fit the curve,
     * and the signature mechanism is the same regardless of the
     * hash being used.
     *
     * The TPM bizarrely wants to be told the hash algorithm, and
     * either it or the TSS will validate that the digest length
     * matches the hash that it's told, despite it having no business
     * caring about such things.
     *
     * So, we can truncate the digest any pretend it's any smaller
     * digest that the TPM actually does support, as long as that
     * digest is larger than the size of the curve.
     */
    int curve_len = (EC_GROUP_order_bits(EC_KEY_get0_group(eckey)) + 7) / 8;
    /* If we couldn't work it out, don't truncate */
    if (!curve_len)
	    curve_len = dgst_len;

    if (dgst_len == SHA_DIGEST_LENGTH ||
	(curve_len <= SHA_DIGEST_LENGTH && dgst_len > SHA_DIGEST_LENGTH)) {
	    hash_alg = TPM2_ALG_SHA1;
	    dgst_len = SHA_DIGEST_LENGTH;
    } else if (dgst_len == SHA256_DIGEST_LENGTH ||
	(curve_len <= SHA256_DIGEST_LENGTH && dgst_len > SHA256_DIGEST_LENGTH)) {
	    hash_alg = TPM2_ALG_SHA256;
	    dgst_len = SHA256_DIGEST_LENGTH;
    } else if (dgst_len == SHA384_DIGEST_LENGTH ||
	(curve_len <= SHA384_DIGEST_LENGTH && dgst_len > SHA384_DIGEST_LENGTH)) {
	    hash_alg = TPM2_ALG_SHA384;
	    dgst_len = SHA384_DIGEST_LENGTH;
    } else if (dgst_len == SHA512_DIGEST_LENGTH ||
	(curve_len <= SHA512_DIGEST_LENGTH && dgst_len > SHA512_DIGEST_LENGTH)) {
	    hash_alg = TPM2_ALG_SHA512;
	    dgst_len = SHA512_DIGEST_LENGTH;
    } else {
        ERR(ecdsa_sign, TPM2TSS_R_PADDING_UNKNOWN);
        goto error;
    }

    TPM2B_DIGEST digest = { .size = dgst_len };
    if (digest.size > sizeof(digest.buffer)) {
        ERR(ecdsa_sign, TPM2TSS_R_DIGEST_TOO_LARGE);
        goto error;
    }
    memcpy(&digest.buffer[0], dgst, digest.size);

    r = init_tpm_key(&esys_ctx, &keyHandle, tpm2Data);
    ERRchktss(ecdsa_sign, r, goto error);

    ret = ecdsa_sign(esys_ctx, keyHandle, &digest, &validation, hash_alg);

    goto out;
 error:
    r = -1;
 out:
    if (keyHandle != ESYS_TR_NONE) {
        if (tpm2Data->privatetype == KEY_TYPE_HANDLE) {
            Esys_TR_Close(esys_ctx, &keyHandle);
        } else {
            Esys_FlushContext(esys_ctx, keyHandle);
        }
    }

    esys_ctx_free(&esys_ctx);
    return (r == TSS2_RC_SUCCESS) ? ret : NULL;
}

#ifdef HAVE_OPENSSL_DIGEST_SIGN
static int
ecdsa_pkey_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    if (ecdsa_pkey_orig_copy && !ecdsa_pkey_orig_copy(dst, src))
        return 0;

    return digest_sign_copy(dst, src);
}

static void
ecdsa_pkey_cleanup(EVP_PKEY_CTX *ctx)
{
    digest_sign_cleanup(ctx);

    if (ecdsa_pkey_orig_cleanup)
        ecdsa_pkey_orig_cleanup(ctx);
}

/* called for digest & sign init, after message digest algorithm set */
static int
ecdsa_digest_custom(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    EC_KEY *eckey = EVP_PKEY_get0_EC_KEY(pkey);
    TPM2_DATA *tpm2data = tpm2tss_ecc_getappdata(eckey);

    DBG("ecdsa_digest_custom %p %p\n", ctx, mctx);

    return digest_sign_init(ctx, mctx, tpm2data, ECDSA_size(eckey));
}

static int
ecdsa_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
              EVP_MD_CTX *mctx)
{
    TPM2_SIG_DATA *sig_data = EVP_PKEY_CTX_get_app_data(ctx);
    TSS2_RC r = TSS2_RC_SUCCESS;
    TPMT_TK_HASHCHECK *validation_ptr = NULL;
    TPM2B_DIGEST *digest_ptr = NULL;
    ECDSA_SIG *ecdsa_s = NULL;

    DBG("ecdsa_signctx %p %p sig_data %p\n", ctx, mctx, sig_data);

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

    if (!digest_finish(sig_data, &digest_ptr, &validation_ptr))
        return 0;

    ecdsa_s = ecdsa_sign(sig_data->key->esys_ctx, sig_data->key->key_handle,
                         digest_ptr, validation_ptr,
                         sig_data->hash_alg);
    if (!ecdsa_s)
        goto error;

    *siglen = i2d_ECDSA_SIG(ecdsa_s, &sig);

    r = 1;
    goto out;

 error:
    r = 0;
 out:
    ECDSA_SIG_free(ecdsa_s);
    Esys_Free(digest_ptr);
    Esys_Free(validation_ptr);

    return r;
}
#endif /* HAVE_OPENSSL_DIGEST_SIGN */

/** Helper to populate the ECC key object.
 *
 * In order to use an ECC key object in a typical manner, all fields of the
 * OpenSSL's corresponding object bust be filled. This function fills the public
 * values correctly.
 * @param key The key object to fill.
 * @retval 0 on failure
 * @retval 1 on success
 */
static int
populate_ecc(EC_KEY *key)
{
    EC_GROUP *ecgroup = NULL;
    int nid;
    BIGNUM *x = NULL, *y = NULL;
    TPM2_DATA *tpm2Data = tpm2tss_ecc_getappdata(key);
    if (tpm2Data == NULL)
        return 0;

    switch (tpm2Data->pub.publicArea.parameters.eccDetail.curveID) {
    case TPM2_ECC_NIST_P256:
        nid = EC_curve_nist2nid("P-256");
        break;
    case TPM2_ECC_NIST_P384:
        nid = EC_curve_nist2nid("P-384");
        break;
    default:
        nid = -1;
    }
    if (nid < 0) {
        ERR(populate_ecc, TPM2TSS_R_UNKNOWN_CURVE);
        return 0;
    }
    ecgroup = EC_GROUP_new_by_curve_name(nid);
    if (ecgroup == NULL) {
        ERR(populate_ecc, TPM2TSS_R_UNKNOWN_CURVE);
        return 0;
    }
    if (!EC_KEY_set_group(key, ecgroup)) {
        ERR(populate_ecc, TPM2TSS_R_GENERAL_FAILURE);
        EC_GROUP_free(ecgroup);
        return 0;
    }
    EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);
    EC_GROUP_free(ecgroup);

    x = BN_bin2bn(tpm2Data->pub.publicArea.unique.ecc.x.buffer,
                  tpm2Data->pub.publicArea.unique.ecc.x.size, NULL);

    y = BN_bin2bn(tpm2Data->pub.publicArea.unique.ecc.y.buffer,
                  tpm2Data->pub.publicArea.unique.ecc.y.size, NULL);

    if (!x || !y) {
        ERR(populate_ecc, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (!EC_KEY_set_public_key_affine_coordinates(key, x, y)) {
        ERR(populate_ecc, TPM2TSS_R_GENERAL_FAILURE);
        BN_free(y);
        BN_free(x);
        return 0;
    }

    BN_free(y);
    BN_free(x);

    return 1;
}

/** Helper to load an ECC key from a tpm2Data
 *
 * This function creates a key object given a TPM2_DATA object. The resulting
 * key object can then be used for signing with the tpm2tss engine. Ownership
 * of the TPM2_DATA object is taken on success.
 * @param tpm2Data The key data to use. Must have been allocated using
 * OPENSSL_malloc.
 * @retval key The key object
 * @retval NULL on failure.
 */
EVP_PKEY *
tpm2tss_ecc_makekey(TPM2_DATA *tpm2Data)
{
    DBG("Creating ECC key object.\n");

    EVP_PKEY *pkey;
    EC_KEY *eckey;

    /* create the new objects to return */
    if ((pkey = EVP_PKEY_new()) == NULL) {
        ERR(tpm2tss_ecc_makekey, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if ((eckey = EC_KEY_new()) == NULL) {
        ERR(tpm2tss_ecc_makekey, ERR_R_MALLOC_FAILURE);
        EVP_PKEY_free(pkey);

        return NULL;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000
    if (!ECDSA_set_method(eckey, ecc_methods)) {
#else /* OPENSSL_VERSION_NUMBER < 0x10100000 */
    if (!EC_KEY_set_method(eckey, ecc_methods)) {
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */
        ERR(tpm2tss_ecc_makekey, TPM2TSS_R_GENERAL_FAILURE);
        EC_KEY_free(eckey);
        goto error;
    }

    if (!EVP_PKEY_assign_EC_KEY(pkey, eckey)) {
        ERR(tpm2tss_ecc_makekey, TPM2TSS_R_GENERAL_FAILURE);
        EC_KEY_free(eckey);
        goto error;
    }

    if (!tpm2tss_ecc_setappdata(eckey, tpm2Data)) {
        ERR(tpm2tss_ecc_makekey, TPM2TSS_R_GENERAL_FAILURE);
        goto error;
    }

    if (!populate_ecc(eckey))
        goto error;

    DBG("Created ECC key object.\n");

    return pkey;
 error:
    EVP_PKEY_free(pkey);
    return NULL;
}

/** Retrieve app data
 *
 * Since the ECC api (opposed to the RSA api) does not provide a standardized
 * way to retrieve app data between the library and an application, this helper
 * is defined
 * @param key The key object
 * @retval tpm2Data The corresponding TPM data
 * @retval NULL on failure.
 */
TPM2_DATA *
#if OPENSSL_VERSION_NUMBER < 0x10100000
tpm2tss_ecc_getappdata(EC_KEY *key)
#else /* OPENSSL_VERSION_NUMBER < 0x10100000 */
tpm2tss_ecc_getappdata(const EC_KEY *key)
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */
{
    if (ec_key_app_data == -1) {
        DBG("Module uninitialized\n");
        return NULL;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000
    return ECDSA_get_ex_data(key, ec_key_app_data);
#else /* OPENSSL_VERSION_NUMBER < 0x10100000 */
    return EC_KEY_get_ex_data(key, ec_key_app_data);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */
}

/** Set app data
 *
 * Since the ECC api (opposed to the RSA api) does not provide a standardized
 * way to set app data between the library and an application, this helper
 * is defined
 * @param key The key object
 * @param tpm2Data The corresponding TPM data
 * @retval 1 on success
 * @retval 0 on failure
 */
int
tpm2tss_ecc_setappdata(EC_KEY *key, TPM2_DATA *tpm2Data)
{
    if (ec_key_app_data == -1) {
        DBG("Module uninitialized\n");
        return 0;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000
    return ECDSA_set_ex_data(key, ec_key_app_data, tpm2Data);
#else /* OPENSSL_VERSION_NUMBER < 0x10100000 */
    return EC_KEY_set_ex_data(key, ec_key_app_data, tpm2Data);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */
}

static void
free_ecc_appdata(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx,
                 long argl, void *argp)
{
    TPM2_DATA *tpm2Data = ptr;

    (void)parent;
    (void)ad;
    (void)idx;
    (void)argl;
    (void)argp;

    if (!ptr)
        return;

    OPENSSL_free(tpm2Data);
}

/** Generate a tpm2tss ecc key object.
 *
 * This function creates a new TPM ECC key. The TPM data is stored inside the
 * object*s app data and can be retrieved using tpm2tss_ecc_getappdata().
 * @param key The key object for the TPM ECC key to be created
 * @param curve The curve to be used for the key
 * @param password The Password to be set for the new key
 * @retval 1 on success
 * @retval 0 on failure
 */
int
tpm2tss_ecc_genkey(EC_KEY *key, TPMI_ECC_CURVE curve, const char *password,
                   TPM2_HANDLE parentHandle)
{
    DBG("GenKey for ecdsa.\n");

    TSS2_RC r;
    ESYS_CONTEXT *esys_ctx = NULL;
    ESYS_TR parent = ESYS_TR_NONE;
    TPM2B_PUBLIC *keyPublic = NULL;
    TPM2B_PRIVATE *keyPrivate = NULL;
    TPM2_DATA *tpm2Data = NULL;
    TPM2B_PUBLIC inPublic = keyEcTemplate;
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
        ERR(tpm2tss_ecc_genkey, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    memset(tpm2Data, 0, sizeof(*tpm2Data));

    inPublic.publicArea.parameters.eccDetail.curveID = curve;

    if (password) {
        DBG("Setting a password for the created key.\n");
        if (strlen(password) > sizeof(tpm2Data->userauth.buffer) - 1 || strlen(password) > sizeof(inSensitive.sensitive.userAuth.buffer) - 1) {
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
    ERRchktss(tpm2tss_ecc_genkey, r, goto error);

    tpm2Data->parent = parentHandle;

    DBG("Generating the ECC key inside the TPM.\n");

    r = Esys_Create(esys_ctx, parent,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                    &inSensitive, &inPublic, &allOutsideInfo, &allCreationPCR,
                    &keyPrivate, &keyPublic, NULL, NULL, NULL);
    ERRchktss(tpm2tss_ecc_genkey, r, goto error);

    DBG("Generated the ECC key inside the TPM.\n");

    tpm2Data->pub = *keyPublic;
    tpm2Data->priv = *keyPrivate;

    if (!tpm2tss_ecc_setappdata(key, tpm2Data)) {
        ERR(tpm2tss_ecc_genkey, TPM2TSS_R_GENERAL_FAILURE);
        goto error;
    }

    if (!populate_ecc(key)) {
        goto error;
    }

    goto end;
 error:
    r = -1;
    tpm2tss_ecc_setappdata(key, NULL);
    if (tpm2Data)
        OPENSSL_free(tpm2Data);

 end:
    Esys_Free(keyPrivate);
    Esys_Free(keyPublic);

    if (parent != ESYS_TR_NONE && !parentHandle)
        Esys_FlushContext(esys_ctx, parent);

    esys_ctx_free(&esys_ctx);

    return (r == TSS2_RC_SUCCESS);
}

/** Initialize the tpm2tss engine's ecc submodule
 *
 * Initialize the tpm2tss engine's submodule by setting function pointer.
 * @param e The engine context.
 * @retval 1 on success
 * @retval 0 on failure
 */
int
init_ecc(ENGINE *e)
{
    (void)(e);

#if OPENSSL_VERSION_NUMBER < 0x10100000
    ecc_method_default = ECDSA_OpenSSL();
    if (ecc_method_default == NULL)
        return 0;

    ecc_methods = ECDSA_METHOD_new(ecc_method_default);
    if (ecc_methods == NULL)
        return 0;

    ECDSA_METHOD_set_sign(ecc_methods, ecdsa_ec_key_sign);

    if (ec_key_app_data == -1)
        ec_key_app_data = ECDSA_get_ex_new_index(0, NULL, NULL, NULL,
                                                 free_ecc_appdata);
#else /* OPENSSL_VERSION_NUMBER < 0x10100000 */
    ecc_method_default = EC_KEY_OpenSSL();
    if (ecc_method_default == NULL)
        return 0;

    ecc_methods = EC_KEY_METHOD_new(ecc_method_default);
    if (ecc_methods == NULL)
        return 0;

    int (*orig_sign) (int, const unsigned char *, int, unsigned char *,
                      unsigned int *, const BIGNUM *, const BIGNUM *, EC_KEY *)
        = NULL;
    EC_KEY_METHOD_get_sign(ecc_methods, &orig_sign, NULL, NULL);
    EC_KEY_METHOD_set_sign(ecc_methods, orig_sign, NULL, ecdsa_ec_key_sign);
    EC_KEY_METHOD_set_compute_key(ecc_methods, ecdh_compute_key);

    if (ec_key_app_data == -1)
        ec_key_app_data = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL,
                                                  free_ecc_appdata);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */

#if HAVE_OPENSSL_DIGEST_SIGN
    /* digest and sign support */

    EVP_PKEY_METHOD *pkey_ecc_methods;

    pkey_ecc_methods = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
    if (pkey_ecc_methods == NULL)
        return 0;

    const EVP_PKEY_METHOD *pkey_orig_ecc_methods =
        EVP_PKEY_meth_find(EVP_PKEY_EC);
    if (pkey_orig_ecc_methods == NULL)
        return 0;
    EVP_PKEY_meth_copy(pkey_ecc_methods, pkey_orig_ecc_methods);
    /*
     * save originals since we only override some of the pkey
     * functionality, rather than reimplementing all of it
     */
    EVP_PKEY_meth_get_copy(pkey_ecc_methods, &ecdsa_pkey_orig_copy);
    EVP_PKEY_meth_get_cleanup(pkey_ecc_methods, &ecdsa_pkey_orig_cleanup);

    EVP_PKEY_meth_set_copy(pkey_ecc_methods, ecdsa_pkey_copy);
    EVP_PKEY_meth_set_cleanup(pkey_ecc_methods, ecdsa_pkey_cleanup);
    EVP_PKEY_meth_set_signctx(pkey_ecc_methods, NULL, ecdsa_signctx);
    EVP_PKEY_meth_set_digest_custom(pkey_ecc_methods, ecdsa_digest_custom);
    EVP_PKEY_meth_add0(pkey_ecc_methods);
#endif /* HAVE_OPENSSL_DIGEST_SIGN */

    return 1;
}
