/*
https://github.com/bigbrett/wsaesengine/blob/master/src/wsaesengine.c
https://github.com/gost-engine/engine/blob/master/gost_eng.c
*/

#include <string.h>

#include <openssl/engine.h>
#include <tss2/tss2_esys.h>

#include "tpm2-tss-engine.h"
#include "tpm2-tss-engine-common.h"

static int tpm_aes_nids[] = {NID_aes256_cbc};

/*
struct evp_cipher_ctx_st {
    const EVP_CIPHER *cipher;
    ENGINE *engine;             /* functional reference if 'cipher' is
                                 * ENGINE-provided
    int encrypt;                /* encrypt or decrypt
    int buf_len;                /* number we have left
    unsigned char oiv[EVP_MAX_IV_LENGTH]; /* original iv
    unsigned char iv[EVP_MAX_IV_LENGTH]; /* working iv
    unsigned char buf[EVP_MAX_BLOCK_LENGTH]; /* saved partial block
    int num;                    /* used by cfb/ofb/ctr mode
    FIXME: Should this even exist? It appears unused
    void *app_data;             /* application stuff
    int key_len;                /* May change for variable length cipher
    unsigned long flags;        /* Various flags
    void *cipher_data;          /* per EVP data
    int final_used;
    int block_mask;
    unsigned char final[EVP_MAX_BLOCK_LENGTH]; /* possible final block
}  EVP_CIPHER_CTX  ;
*/

static int
tpm_cipher_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
    EVP_CIPHER_CTX_get_app_data
    ctx->cipher->app_data

    TSS2_RC r;
    ESYS_AUXCONTEXT eactx = (ESYS_AUXCONTEXT){0};
    ESYS_TR keyHandle = ESYS_TR_NONE;
    TPMT_SIGNATURE *sig = NULL;

    r = init_tpm_key(&eactx, &keyHandle, tpm2Data);
    ERRchktss(tpm_cipher_init_key, r, goto error);

}

static int
tpm_do_cipher_aes256_cbc(EVP_CIPHER_CTX *ctx,unsigned char *out, const unsigned char *in, size_t inl)
{
    //tpm2_encryptdecrypt
}

static int
tpm_cipher_cleanup(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
    //cleanup
}

EVP_CIPHER tpm_aes256_cbc =
{
    NID_aes256_cbc,                                               // int nid                   // EVP_CIPHER_meth_new()
    1,                                                            // int block_size;
    32,                                                           // int key_len;
    8,                                                            // int iv_len;               // EVP_CIPHER_meth_set_iv_length()
    EVP_CIPH_CBC_MODE,                                            // unsigned long flags;      // EVP_CIPHER_meth_set_flags()
    cipher_init_key,                                              // *init_key                 // EVP_CIPHER_meth_set_init()
    cipher_update,                                                // *do_cipher                // EVP_CIPHER_meth_set_do_cipher()
    cipher_cleanup,                                               // cleanup ctx               // EVP_CIPHER_meth_set_cleanup()
    1000,                                                         // int cipher_data size      // EVP_CIPHER_meth_set_impl_ctx_size()
    EVP_CIPHER_set_asn1_iv,                                       //                           // EVP_CIPHER_meth_set_set_asn1_params
    EVP_CIPHER_set_asn1_iv,                                       //                           // EVP_CIPHER_meth_set_get_asn1_params
    NULL,                                                         //                           // EVP_CIPHER_meth_set_ctrl
    NULL                                                          // void *app_data;
}

static int
tpm_ciphers_selector(ENGINE* e, const EVP_CIPHER** cipher, const int** nids, int nid)
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
    if ( !ENGINE_set_ciphers(e, tpm_ciphers_selector)) {
        printf("ENGINE_set_ciphers failed\n");
        return 0;
    }
}
