/*
https://github.com/bigbrett/wsaesengine/blob/master/src/wsaesengine.c
https://github.com/gost-engine/engine/blob/master/gost_eng.c
*/

#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <tss2/tss2_esys.h>

#include "tpm2-tss-engine.h"
#include "tpm2-tss-engine-common.h"

typedef struct {
    TPM2_DATA *tpm2Data;
    TPMI_YES_NO enc;     // Note: Openssl (encrypt:1) != TSS (encrypt:0)
    TPM2B_IV iv;
} TPM2_DATA_CIPHER;

/*
#define NID_tpm2_aes_128_cbc 1
#define NID_tpm2_aes_192_ocb 5
#define NID_tpm2_aes_256_cfb 9
*/

static int tpm2_cipher_nids[] = {
    /*
    NID_tpm2_aes_128_cbc,
    NID_tpm2_aes_192_ocb,
    NID_tpm2_aes_256_cfb,
    */
    NID_aes_256_cbc,
    NID_aes_256_ocb,
    NID_aes_256_cfb1,
    0
};

static int
tpm2_cipher_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
    TPM2_DATA_CIPHER *tpm2DataCipher = NULL;

    DBG("Init Key\n");

    // Init Struct
    tpm2DataCipher = OPENSSL_malloc(sizeof(*tpm2DataCipher));
    if (tpm2DataCipher == NULL) {
        ERR(tpm2_cipher_init_key, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    memset(tpm2DataCipher, 0, sizeof(*tpm2DataCipher));

    // Fill TPM2_DATA
    if (strncmp((char *)key, "0x81", 4) == 0) {
        uint32_t handle;
        sscanf((char *)key, "0x%x", &handle);
        if (!tpm2tss_tpm2data_readtpm(handle, &(tpm2DataCipher->tpm2Data))) {
            ERR(tpm2_cipher_init_key, TPM2TSS_R_TPM2DATA_READ_FAILED);
            goto error;
        }
    }
    else if (key == NULL) {
        // Create Key

    } else {
        // Use blob context
    }

    // Fill other data : IV, ENC
    tpm2DataCipher->iv.size = strlen(iv);
    memcpy(tpm2DataCipher->iv.buffer, iv, tpm2DataCipher->iv.size);
    // Note: Openssl (encrypt:1) != TSS (encrypt:0)
    tpm2DataCipher->enc = !enc;
    EVP_CIPHER_CTX_set_app_data(ctx, tpm2DataCipher);

    return 1;

error :
    if (tpm2DataCipher)
        OPENSSL_free(tpm2DataCipher);
    return 0;
}

static int
tpm2_do_cipher_aes_256_cbc(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    TPM2_DATA_CIPHER *tpm2DataCipher;
    TSS2_RC ret;
    ESYS_AUXCONTEXT eactx = (ESYS_AUXCONTEXT){0};
    ESYS_TR keyHandle = ESYS_TR_NONE;
    TPM2B_MAX_BUFFER *out_data;
    TPM2B_MAX_BUFFER *in_data;
    TPM2B_IV *iv_out;
    TPMI_ALG_SYM_MODE mode;
    TPMI_YES_NO enc;
    TPM2B_IV iv;

    DBG("Do cipher\n");

    // Get App Data
    tpm2DataCipher = EVP_CIPHER_CTX_get_app_data(ctx);

    // Init TPM key
    ret = init_tpm_key(&eactx, &keyHandle, tpm2DataCipher->tpm2Data);
    ERRchktss(tpm2_do_cipher_aes_256_cbc, ret, goto error);

    // Copy in_data : unsigned char* to TPM2B_MAX_BUFFER
    in_data = OPENSSL_malloc(sizeof(*in_data));
    if (tpm2DataCipher == NULL) {
        ERR(tpm2_do_cipher_aes_256_cbc, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    memcpy(in_data->buffer, in, inl);
    in_data->size = inl;

    // Get mode value
    mode = tpm2DataCipher->tpm2Data->pub.publicArea.parameters.symDetail.sym.mode.sym;
    enc = tpm2DataCipher->enc;
    iv = tpm2DataCipher->iv;

    ret = Esys_EncryptDecrypt2( eactx.ectx,
                                keyHandle,
                                ESYS_TR_PASSWORD,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                in_data,
                                enc,
                                mode,
                                &iv,
                                &out_data,
                                &iv_out );
    if (ret == TPM2_RC_COMMAND_CODE) {
        DBG("Command Code Not Supported : Esys_EncryptDecrypt2 !\n");
        DBG("Trying other Command Code  : Esys_EncryptDecrypt ...\n");
        ret = Esys_EncryptDecrypt( eactx.ectx,
                                    keyHandle,
                                    ESYS_TR_PASSWORD,
                                    ESYS_TR_NONE,
                                    ESYS_TR_NONE,
                                    enc,
                                    mode,
                                    &iv,
                                    in_data,
                                    &out_data,
                                    &iv_out );
    }
    ERRchktss(tpm2_do_cipher_aes_256_cbc, ret, goto error);

    // Copy out_data : TPM2B_MAX_BUFFER to unsigned char*
    memcpy(out, out_data->buffer, out_data->size);
    out[out_data->size] = '\0';

    if (keyHandle != ESYS_TR_NONE) {
        if (tpm2DataCipher->tpm2Data->privatetype == KEY_TYPE_HANDLE) {
            Esys_TR_Close(eactx.ectx, &keyHandle);
        } else {
            Esys_FlushContext(eactx.ectx, keyHandle);
        }
    }
    esys_auxctx_free(&eactx);
    return 1;

error :
    if (tpm2DataCipher)
        OPENSSL_free(tpm2DataCipher);
    return 0;
}

static int
tpm2_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
    //cleanup
    DBG("cleanup\n");

    return 1;
}

static int
tpm2_set_asn1_params(EVP_CIPHER_CTX *ctx, ASN1_TYPE *type)
{
    DBG("set asn1 params\n");

    return 0;
}

static int
tpm2_get_asn1_params(EVP_CIPHER_CTX *ctx, ASN1_TYPE *type)
{
    DBG("get asn1 params\n");

    return 0;
}
/*
static const EVP_CIPHER tpm_aes256_cbc =
{
    NID_aes_256_cbc,                                               // int nid                   // EVP_CIPHER_meth_new()
    1,                                                            // int block_size;
    32,                                                           // int key_len;
    8,                                                            // int iv_len;               // EVP_CIPHER_meth_set_iv_length()
    EVP_CIPH_CBC_MODE,                                            // unsigned long flags;      // EVP_CIPHER_meth_set_flags()
    tpm_cipher_init_key,                                          // *init_key                 // EVP_CIPHER_meth_set_init()
    tpm_do_cipher_aes256_cbc,                                     // *do_cipher                // EVP_CIPHER_meth_set_do_cipher()
    tpm_cipher_cleanup,                                           // cleanup ctx               // EVP_CIPHER_meth_set_cleanup()
    1000,                                                         // int cipher_data size      // EVP_CIPHER_meth_set_impl_ctx_size()
    EVP_CIPHER_set_asn1_iv,                                       //                           // EVP_CIPHER_meth_set_set_asn1_params
    EVP_CIPHER_set_asn1_iv,                                       //                           // EVP_CIPHER_meth_set_get_asn1_params
    NULL,                                                         //                           // EVP_CIPHER_meth_set_ctrl
    NULL                                                          // void *app_data;
};
*/
static EVP_CIPHER *_tpm2_aes_256_cbc = NULL;
const EVP_CIPHER *tpm2_aes_256_cbc(void)
{
    if (_tpm2_aes_256_cbc == NULL &&
        ((_tpm2_aes_256_cbc = EVP_CIPHER_meth_new(NID_aes_256_cbc, 1, 32)) == NULL
         || !EVP_CIPHER_meth_set_iv_length(_tpm2_aes_256_cbc, 16)
         || !EVP_CIPHER_meth_set_flags(_tpm2_aes_256_cbc, EVP_CIPH_CBC_MODE | EVP_CIPH_ALWAYS_CALL_INIT)
         || !EVP_CIPHER_meth_set_init(_tpm2_aes_256_cbc, tpm2_cipher_init_key)
         || !EVP_CIPHER_meth_set_do_cipher(_tpm2_aes_256_cbc, tpm2_do_cipher_aes_256_cbc)
         || !EVP_CIPHER_meth_set_cleanup(_tpm2_aes_256_cbc, tpm2_cipher_cleanup)
         || !EVP_CIPHER_meth_set_impl_ctx_size(_tpm2_aes_256_cbc, 1000)
         || !EVP_CIPHER_meth_set_set_asn1_params(_tpm2_aes_256_cbc, tpm2_set_asn1_params)
         || !EVP_CIPHER_meth_set_get_asn1_params(_tpm2_aes_256_cbc, tpm2_get_asn1_params)
         || !EVP_CIPHER_meth_set_ctrl(_tpm2_aes_256_cbc, NULL)))
    {
        EVP_CIPHER_meth_free(_tpm2_aes_256_cbc);
        _tpm2_aes_256_cbc = NULL;
    }
    return _tpm2_aes_256_cbc;
}

static int
tpm2_ciphers_selector(ENGINE* e, const EVP_CIPHER** cipher, const int** nids, int nid)
{
    int ret = 1;

    if (cipher == NULL) {
        *nids = tpm2_cipher_nids;
        return sizeof(tpm2_cipher_nids) / sizeof(tpm2_cipher_nids[0]) - 1;
    }

    switch (nid) {
    case NID_aes_256_cbc:
        *cipher = tpm2_aes_256_cbc();
        break;
    case NID_aes_256_ocb:
        //*cipher = tpm2_aes_256_ocb();
        break;
    case NID_aes_256_cfb1:
        //*cipher = tpm2_aes_256_cfb();
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
    if ( !ENGINE_set_ciphers(e, tpm2_ciphers_selector)) {
        DBG("ENGINE_set_ciphers failed\n");
        return 0;
    }

    return 1;
}
