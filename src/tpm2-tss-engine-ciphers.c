/*
https://github.com/bigbrett/wsaesengine/blob/master/src/wsaesengine.c
https://github.com/gost-engine/engine/blob/master/gost_eng.c
*/

#include <string.h>

#include <openssl/engine.h>
#include <tss2/tss2_esys.h>

#include "tpm2-tss-engine.h"
#include "tpm2-tss-engine-common.h"

static int tpm_aes_nids[] = {NID_aes_256_cbc};

static int
cipher_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
    TSS2_RC r;
    ESYS_AUXCONTEXT eactx = (ESYS_AUXCONTEXT){0};
    ESYS_TR keyHandle = ESYS_TR_NONE;
    TPMT_SIGNATURE *sig = NULL;

    r = init_tpm_key (  &eactx,
                        &keyHandle,
                        tpm2Data);
    ERRchktss(cipher_init_key, r, goto error);

}

static int
cipher_update(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{


}

static int
cipher_cleanup(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{


}

EVP_CIPHER tpm_ciphers =
{
    NID_aes_256_cbc,
    int block_size;
    /* Default value for variable length ciphers */
    int key_len;
    int iv_len;
    /* Various flags */
    unsigned long flags;
    /* init key */
    int (*init) (EVP_CIPHER_CTX *ctx, const unsigned char *key,
                 const unsigned char *iv, int enc);
    /* encrypt/decrypt data */
    int (*do_cipher) (EVP_CIPHER_CTX *ctx, unsigned char *out,
                      const unsigned char *in, size_t inl);
    /* cleanup ctx */
    int (*cleanup) (EVP_CIPHER_CTX *);
    /* how big ctx->cipher_data needs to be */
    int ctx_size;
    /* Populate a ASN1_TYPE with parameters */
    int (*set_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
    /* Get parameters from a ASN1_TYPE */
    int (*get_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
    /* Miscellaneous operations */
    int (*ctrl) (EVP_CIPHER_CTX *, int type, int arg, void *ptr);
    /* Application data */
    void *app_data;
}

static int
tpm_ciphers(ENGINE* e, const EVP_CIPHER** cipher, const int** nids, int nid)
{
    if (cipher == NULL) {
        *nids = tpm_nids;
        return sizeof(tpm_aes_nids) / sizeof(tpm_aes_nids[0]) - 1;
    }

    switch (nid) {
    case NID_aes_256_cbc:
        *cipher = &tpm_aes_cbc;
        break;
    default:
        *cipher = NULL;
        return 0;
    }
    return 1;
}

int
init_ciphers(ENGINE *e)
{
    if ( !ENGINE_set_ciphers(e, tpm_ciphers)) {
        printf("ENGINE_set_ciphers failed\n");
        return 0;
    }
}
