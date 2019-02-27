/*******************************************************************************
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
#include "tpm2-tss-engine.h"
#include "tpm2-tss-engine-common.h"
#include "tpm2-tss-engine-pmeth.h"

typedef struct {
    void *p_default_ctx;
    int nbits;
    TPM2_HANDLE parentHandle;
    BIGNUM *p_pub_exp;
} TPM2TSS_RSA_PKEY_CTX;

static EVP_PKEY_METHOD *p_rsa_new_pkey_meth;
static TPM2TSS_RSA_ORIG_METH tpm2tss_rsa_orig_meth;

static int tpm2tss_pkey_rsa_init(EVP_PKEY_CTX *ctx)
{
    TPM2TSS_RSA_PKEY_CTX *rctx;

    if (tpm2tss_rsa_orig_meth.pinit(ctx) != 1)
        return 0;

    rctx = OPENSSL_malloc(sizeof(TPM2TSS_RSA_PKEY_CTX));
    if (!rctx)
        return 0;

    rctx->nbits = 2048;
    rctx->p_pub_exp = NULL;
    rctx->parentHandle = 0;

    rctx->p_default_ctx = EVP_PKEY_CTX_get_data(ctx);
    EVP_PKEY_CTX_set_data(ctx, rctx);

    return 1;
}

static int tpm2tss_pkey_rsa_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    TPM2TSS_RSA_PKEY_CTX *rctx_dst = NULL;
    TPM2TSS_RSA_PKEY_CTX *rctx_src = NULL;
    int rc = 0;

    if (!tpm2tss_pkey_rsa_init(dst))
        return 0;

    rctx_dst = EVP_PKEY_CTX_get_data(dst);
    rctx_src = EVP_PKEY_CTX_get_data(src);

    EVP_PKEY_CTX_set_data(dst, rctx_dst->p_default_ctx);
    EVP_PKEY_CTX_set_data(src, rctx_src->p_default_ctx);

    rc = tpm2tss_rsa_orig_meth.pcopy(dst, src);

    if (rc == 1) {
        rctx_dst->nbits = rctx_src->nbits;
        rctx_dst->parentHandle = rctx_src->parentHandle;
        if (rctx_src->p_pub_exp) {
            rctx_dst->p_pub_exp = BN_dup(rctx_src->p_pub_exp);
            if (!rctx_dst->p_pub_exp)
                rc = 0;
        }
    }

    EVP_PKEY_CTX_set_data(dst, rctx_dst);
    EVP_PKEY_CTX_set_data(src, rctx_src);

    return rc;
}

static void tpm2tss_pkey_rsa_cleanup(EVP_PKEY_CTX *ctx)
{
    TPM2TSS_RSA_PKEY_CTX *rctx;

    rctx = EVP_PKEY_CTX_get_data(ctx);
    EVP_PKEY_CTX_set_data(ctx, rctx->p_default_ctx);

    tpm2tss_rsa_orig_meth.pcleanup(ctx);

    if (rctx) {
        if (rctx->p_pub_exp)
            BN_free(rctx->p_pub_exp);
        OPENSSL_free(rctx);
    }
}

static int tpm2tss_pkey_rsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
                         size_t *siglen, const unsigned char *tbs,
                         size_t tbslen)
{
    int rc = 0;
    TPM2TSS_RSA_PKEY_CTX *rctx;

    rctx = EVP_PKEY_CTX_get_data(ctx);
    EVP_PKEY_CTX_set_data(ctx, rctx->p_default_ctx);

    rc = tpm2tss_rsa_orig_meth.psign(ctx, sig, siglen, tbs, tbslen);
    EVP_PKEY_CTX_set_data(ctx, rctx);

    return rc;
}

static int tpm2tss_pkey_rsa_verifyrecover(EVP_PKEY_CTX *ctx,
                                  unsigned char *rout, size_t *routlen,
                                  const unsigned char *sig, size_t siglen)
{
    int rc = 0;
    TPM2TSS_RSA_PKEY_CTX *rctx;

    rctx = EVP_PKEY_CTX_get_data(ctx);
    EVP_PKEY_CTX_set_data(ctx, rctx->p_default_ctx);

    rc = tpm2tss_rsa_orig_meth.pverify_recover(ctx, rout, routlen, sig, siglen);
    EVP_PKEY_CTX_set_data(ctx, rctx);

    return rc;
}

static int tpm2tss_pkey_rsa_verify(EVP_PKEY_CTX *ctx,
                           const unsigned char *sig, size_t siglen,
                           const unsigned char *tbs, size_t tbslen)
{
    int rc = 0;
    TPM2TSS_RSA_PKEY_CTX *rctx;

    rctx = EVP_PKEY_CTX_get_data(ctx);
    EVP_PKEY_CTX_set_data(ctx, rctx->p_default_ctx);

    rc = tpm2tss_rsa_orig_meth.pverify(ctx, sig, siglen, tbs, tbslen);
    EVP_PKEY_CTX_set_data(ctx, rctx);

    return rc;
}

static int tpm2tss_pkey_rsa_encrypt(EVP_PKEY_CTX *ctx,
                            unsigned char *out, size_t *outlen,
                            const unsigned char *in, size_t inlen)
{
    int rc = 0;
    TPM2TSS_RSA_PKEY_CTX *rctx;

    rctx = EVP_PKEY_CTX_get_data(ctx);
    EVP_PKEY_CTX_set_data(ctx, rctx->p_default_ctx);

    rc = tpm2tss_rsa_orig_meth.pencryptfn(ctx, out, outlen, in, inlen);
    EVP_PKEY_CTX_set_data(ctx, rctx);

    return rc;
}

static int tpm2tss_pkey_rsa_decrypt(EVP_PKEY_CTX *ctx,
                            unsigned char *out, size_t *outlen,
                            const unsigned char *in, size_t inlen)
{
    int rc = 0;
    TPM2TSS_RSA_PKEY_CTX *rctx;

    rctx = EVP_PKEY_CTX_get_data(ctx);
    EVP_PKEY_CTX_set_data(ctx, rctx->p_default_ctx);

    rc = tpm2tss_rsa_orig_meth.pdecrypt(ctx, out, outlen, in, inlen);
    EVP_PKEY_CTX_set_data(ctx, rctx);

    return rc;
}

static int tpm2tss_pkey_rsa_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    int rc = -2;
    TPM2TSS_RSA_PKEY_CTX *rctx;

    rctx = EVP_PKEY_CTX_get_data(ctx);
    EVP_PKEY_CTX_set_data(ctx, rctx->p_default_ctx);

    switch (type) {
    case EVP_PKEY_CTRL_RSA_KEYGEN_BITS:
        rc = tpm2tss_rsa_orig_meth.pctrl(ctx, type, p1, p2);
        if (rc == 1)
            rctx->nbits = p1;
        break;
    case EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP:
        rc = tpm2tss_rsa_orig_meth.pctrl(ctx, type, p1, p2);
        if (rc == 1) {
            BN_free(rctx->p_pub_exp);
            rctx->p_pub_exp = BN_dup(p2);
        }
        break;
    default:
        rc = tpm2tss_rsa_orig_meth.pctrl(ctx, type, p1, p2);
        break;
    }

    EVP_PKEY_CTX_set_data(ctx, rctx);
    return rc;
}

static int tpm2tss_pkey_rsa_ctrl_str(EVP_PKEY_CTX *ctx,
                             const char *type, const char *value)
{

    int rc = -2;
    TPM2TSS_RSA_PKEY_CTX *rctx;

    rctx = EVP_PKEY_CTX_get_data(ctx);
    EVP_PKEY_CTX_set_data(ctx, rctx->p_default_ctx);

    rc = tpm2tss_rsa_orig_meth.pctrl_str(ctx, type, value);

    if (rc == 1) {
        if (!strcmp(type, "rsa_keygen_bits")) {
            rctx->nbits = atoi(value);
        }

        if (!strcmp(type, "rsa_keygen_pubexp")) {
            BIGNUM *pubexp = NULL;
            if (!BN_asc2bn(&pubexp, value))
                rc = 0;
            else
                rctx->p_pub_exp = pubexp;
        }
    }

    EVP_PKEY_CTX_set_data(ctx, rctx);
    return rc;
}

static int tpm2tss_pkey_rsa_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    TPM2TSS_RSA_PKEY_CTX *rctx;
    RSA * rsa = NULL;
    int rc = 0;
    EVP_PKEY *local_pkey = NULL;
    void *local_rsa_key = NULL;

    rctx = EVP_PKEY_CTX_get_data(ctx);
    EVP_PKEY_CTX_set_data(ctx, rctx->p_default_ctx);

    if (!rctx->p_pub_exp) {
        rctx->p_pub_exp = BN_new();
        if (!rctx->p_pub_exp)
            goto exit;

        if (!BN_set_word(rctx->p_pub_exp, RSA_F4)) {
            goto exit;
        }
    }

    rsa = RSA_new();
    if (!rsa) {
        goto exit;
    }

    if (!tpm2tss_rsa_genkey(rsa, rctx->nbits, rctx->p_pub_exp,
            NULL, rctx->parentHandle)) {
        goto exit;
    }

    TPM2_DATA *tpm2Data = OPENSSL_malloc(sizeof(*tpm2Data));
    if (tpm2Data == NULL) {
        goto exit;
    }
    memcpy(tpm2Data, RSA_get_app_data(rsa), sizeof(*tpm2Data));

    local_pkey = tpm2tss_rsa_makekey(tpm2Data);
    if (!local_pkey) {
        goto exit;
    }

    local_rsa_key = EVP_PKEY_get1_RSA(local_pkey);
    EVP_PKEY_assign_RSA(pkey, local_rsa_key);

    rc = 1;

exit:
    if (local_pkey)
        EVP_PKEY_free(local_pkey);

    if (rsa)
        RSA_free(rsa);

    if ((rc != 1) && rctx->p_pub_exp) {
        BN_free(rctx->p_pub_exp);
        rctx->p_pub_exp = NULL;
    }

    EVP_PKEY_CTX_set_data(ctx, rctx);
    return rc;
}

EVP_PKEY_METHOD *tpm2tss_get_pkey_method_rsa()
{
    EVP_PKEY_METHOD *p_orig_meth = NULL;
    TPM2TSS_RSA_ORIG_METH *p_meth_saved = &tpm2tss_rsa_orig_meth;

    p_orig_meth = (EVP_PKEY_METHOD *)EVP_PKEY_meth_find(EVP_PKEY_RSA);
    if (!p_orig_meth)
        return NULL;

    p_rsa_new_pkey_meth = EVP_PKEY_meth_new(EVP_PKEY_RSA,
            EVP_PKEY_FLAG_AUTOARGLEN);
    if (!p_rsa_new_pkey_meth) {
        return NULL;
    }

    EVP_PKEY_meth_get_init(p_orig_meth,
            &p_meth_saved->pinit);
    EVP_PKEY_meth_get_copy(p_orig_meth,
            &p_meth_saved->pcopy);
    EVP_PKEY_meth_get_cleanup(p_orig_meth,
            &p_meth_saved->pcleanup);
    EVP_PKEY_meth_get_sign(p_orig_meth,
            &p_meth_saved->psign_init,
            &p_meth_saved->psign);
    EVP_PKEY_meth_get_verify_recover(p_orig_meth,
            &p_meth_saved->pverify_recover_init,
            &p_meth_saved->pverify_recover);
    EVP_PKEY_meth_get_verify(p_orig_meth,
            &p_meth_saved->pverify_init,
            &p_meth_saved->pverify);
    EVP_PKEY_meth_get_encrypt(p_orig_meth,
            &p_meth_saved->pencrypt_init,
            &p_meth_saved->pencryptfn);
    EVP_PKEY_meth_get_ctrl(p_orig_meth,
            &p_meth_saved->pctrl,
            &p_meth_saved->pctrl_str);
    EVP_PKEY_meth_get_decrypt(p_orig_meth,
            &p_meth_saved->pdecrypt_init,
            &p_meth_saved->pdecrypt);

    EVP_PKEY_meth_set_init(p_rsa_new_pkey_meth,
            tpm2tss_pkey_rsa_init);
    EVP_PKEY_meth_set_copy(p_rsa_new_pkey_meth,
            tpm2tss_pkey_rsa_copy);
    EVP_PKEY_meth_set_cleanup(p_rsa_new_pkey_meth,
            tpm2tss_pkey_rsa_cleanup);
    EVP_PKEY_meth_set_sign(p_rsa_new_pkey_meth,
            NULL,
            tpm2tss_pkey_rsa_sign);
    EVP_PKEY_meth_set_verify_recover(p_rsa_new_pkey_meth,
            NULL,
            tpm2tss_pkey_rsa_verifyrecover);
    EVP_PKEY_meth_set_verify(p_rsa_new_pkey_meth,
            NULL,
            tpm2tss_pkey_rsa_verify);
    EVP_PKEY_meth_set_encrypt(p_rsa_new_pkey_meth,
            NULL,
            tpm2tss_pkey_rsa_encrypt);
    EVP_PKEY_meth_set_decrypt(p_rsa_new_pkey_meth,
            NULL,
            tpm2tss_pkey_rsa_decrypt);
    EVP_PKEY_meth_set_ctrl(p_rsa_new_pkey_meth,
                tpm2tss_pkey_rsa_ctrl,
                tpm2tss_pkey_rsa_ctrl_str);
    EVP_PKEY_meth_set_keygen(p_rsa_new_pkey_meth, NULL,
            tpm2tss_pkey_rsa_keygen);

    return p_rsa_new_pkey_meth;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000
static int tpm2tss_pkey_asn1_priv_decode(EVP_PKEY *pkey,
        PKCS8_PRIV_KEY_INFO *p8)
#else
static int tpm2tss_pkey_asn1_priv_decode(EVP_PKEY *pkey,
        const PKCS8_PRIV_KEY_INFO *p8)
#endif
{
    const unsigned char *p;
    int pklen;
    TSSPRIVKEY *tpk = NULL;
    TSS2_RC r;
    TPM2_DATA *tpm2Data = NULL;
    char type_oid[64];
    EVP_PKEY *local_pkey = NULL;
    RSA *local_rsa_key = NULL;

    if (!PKCS8_pkey_get0(NULL, &p, &pklen, NULL, p8))
        return 0;

    tpk = d2i_TSSPRIVKEY(NULL, &p, pklen);
    if (!tpk)
        return 0;

    tpm2Data = OPENSSL_malloc(sizeof(*tpm2Data));
    if (tpm2Data == NULL) {
        goto error;
    }
    memset(tpm2Data, 0, sizeof(*tpm2Data));

    tpm2Data->privatetype = KEY_TYPE_BLOB;

    tpm2Data->emptyAuth = tpk->emptyAuth;

    tpm2Data->parent = ASN1_INTEGER_get(tpk->parent);
    if (tpm2Data->parent == 0)
        tpm2Data->parent = TPM2_RH_OWNER;

    if (!OBJ_obj2txt(type_oid, sizeof(type_oid), tpk->type, 1) ||
    strcmp(type_oid, OID_loadableKey)) {
        goto error;
    }
    r = Tss2_MU_TPM2B_PRIVATE_Unmarshal(tpk->privkey->data, tpk->privkey->length,
                    NULL, &tpm2Data->priv);
    if (r) {
        goto error;
    }
    r = Tss2_MU_TPM2B_PUBLIC_Unmarshal(tpk->pubkey->data, tpk->pubkey->length,
                       NULL, &tpm2Data->pub);
    if (r) {
        goto error;
    }

    TSSPRIVKEY_free(tpk);

    local_pkey = tpm2tss_rsa_makekey(tpm2Data);
    if (!local_pkey) {
        goto error;
    }

    local_rsa_key = EVP_PKEY_get1_RSA(local_pkey);
    EVP_PKEY_assign_RSA(pkey, local_rsa_key);

    EVP_PKEY_free(local_pkey);

    return 1;
error:
    if (tpm2Data) OPENSSL_free(tpm2Data);
    if (tpk) TSSPRIVKEY_free(tpk);
    if (local_pkey) EVP_PKEY_free(local_pkey);
    return 0;
}

static int tpm2tss_pkey_asn1_priv_encode(PKCS8_PRIV_KEY_INFO *p8,
        const EVP_PKEY *pk)
{
    TSSPRIVKEY *tpk = NULL;
    RSA *p_rsa = (RSA *)EVP_PKEY_get0((EVP_PKEY *)pk);
    TPM2_DATA *tpm2Data = RSA_get_app_data(p_rsa);
    uint8_t privbuf[sizeof(tpm2Data->priv)];
    uint8_t pubbuf[sizeof(tpm2Data->pub)];
    size_t privbuf_len = 0, pubbuf_len = 0;
    TSS2_RC r;
    size_t tpkderlen = 0;
    unsigned char *tpkder = NULL;

    if (!p_rsa || !tpm2Data)
        return 0;

    tpk = TSSPRIVKEY_new();
    if (!tpk) {
        goto error;
    }

    r = Tss2_MU_TPM2B_PRIVATE_Marshal(&tpm2Data->priv, &privbuf[0],
                                  sizeof(privbuf), &privbuf_len);
    if (r) {
        goto error;
    }

    r = Tss2_MU_TPM2B_PUBLIC_Marshal(&tpm2Data->pub, &pubbuf[0],
                                 sizeof(pubbuf), &pubbuf_len);
    if (r) {
        goto error;
    }

    tpk->type = OBJ_txt2obj(OID_loadableKey, 1);
    tpk->parent = ASN1_INTEGER_new();
    tpk->privkey = ASN1_OCTET_STRING_new();
    tpk->pubkey = ASN1_OCTET_STRING_new();
    if (!tpk->type || !tpk->privkey || !tpk->pubkey || !tpk->parent) {
        goto error;
    }

    tpk->emptyAuth = !!tpm2Data->emptyAuth;
    ASN1_INTEGER_set(tpk->parent, tpm2Data->parent);
    ASN1_STRING_set(tpk->privkey, &privbuf[0], privbuf_len);
    ASN1_STRING_set(tpk->pubkey, &pubbuf[0], pubbuf_len);

    tpkderlen = i2d_TSSPRIVKEY(tpk, &tpkder);
    if (tpkderlen <= 0)
        goto error;

    if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_rsaEncryption), 0,
                         V_ASN1_NULL, NULL, tpkder, tpkderlen)) {
        return 0;
    }

    TSSPRIVKEY_free(tpk);
    return 1;
error:
        if (tpk) TSSPRIVKEY_free(tpk);
        return 0;
}

EVP_PKEY_ASN1_METHOD *tpm2tss_get_pkey_asn1_method_rsa()
{
    const EVP_PKEY_ASN1_METHOD *p_orig_meth = NULL;
    EVP_PKEY_ASN1_METHOD *p_new_asn1_meth = NULL;

    p_orig_meth = EVP_PKEY_asn1_find(NULL, EVP_PKEY_RSA);
    if (!p_orig_meth)
        return NULL;

    p_new_asn1_meth = EVP_PKEY_asn1_new(EVP_PKEY_RSA,
            ASN1_PKEY_SIGPARAM_NULL, "TPM2TSSRSA", "TPM2TSS RSA METHOD");
    if (!p_new_asn1_meth)
        return NULL;

    EVP_PKEY_asn1_copy(p_new_asn1_meth, p_orig_meth);
    EVP_PKEY_asn1_set_private(p_new_asn1_meth,
            tpm2tss_pkey_asn1_priv_decode,
            tpm2tss_pkey_asn1_priv_encode, NULL);

    return p_new_asn1_meth;
}
