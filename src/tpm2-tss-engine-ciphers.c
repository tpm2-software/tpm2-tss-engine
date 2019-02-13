#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <tss2/tss2_esys.h>

#include "tpm2-tss-engine.h"
#include "tpm2-tss-engine-common.h"

#define HANDLE_SIZE 8

typedef struct {
    TPM2_DATA *tpm2Data;
    TPMI_YES_NO enc;     // Note: Openssl (encrypt:1) != TSS (encrypt:0)
    TPM2B_IV iv;
} TPM2_DATA_CIPHER;

static int tpm2_cipher_nids[] = {
    NID_aes_128_cbc,
    NID_aes_192_ocb,
    NID_aes_256_cfb1,
    NID_aes_256_cbc,
    NID_aes_256_ocb,
    NID_aes_256_cfb1,
    0
};

static int convert_array_hex_to_char(const unsigned char *in, unsigned char *out, size_t size)
{
    for(size_t i = 0; i < size; i++)
    {
        sprintf((char *)out + 2*i, "%02x", in[i]);
    }

    return 0;
}

static int
tpm2_cipher_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
    TPM2_DATA_CIPHER *tpm2DataCipher = NULL;
    uint32_t keyHandle = 0;

    DBG("Init Key\n");

    /* Init Struct */
    tpm2DataCipher = OPENSSL_malloc(sizeof(*tpm2DataCipher));
    if (tpm2DataCipher == NULL) {
        ERR(tpm2_cipher_init_key, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    memset(tpm2DataCipher, 0, sizeof(*tpm2DataCipher));

    /* Populate TPM2_DATA depending of key value */
    if (key == NULL) {
        // Create Key or Use an empty Key

        return 1;
    } else if (strncmp((char *)key, "0x81", 4) == 0) {
        // Read persistent key, use for openssl API : EVP_EncryptInit_ex()

        sscanf((char *)key, "0x%x", &keyHandle);
        if (!tpm2tss_tpm2data_readtpm(keyHandle, &(tpm2DataCipher->tpm2Data))) {
            ERR(tpm2_cipher_init_key, TPM2TSS_R_TPM2DATA_READ_FAILED);
            goto error;
        }
    } else if ((key[0] == 0x81) && (key[HANDLE_SIZE/2 + 1] == 0)) {
        // Read persistent key, use for openssl app : openssl enc

        unsigned char tmp[HANDLE_SIZE];
        convert_array_hex_to_char(key, tmp, HANDLE_SIZE/2);
        sscanf((char *)tmp, "%x", &keyHandle);
        if (!tpm2tss_tpm2data_readtpm(keyHandle, &(tpm2DataCipher->tpm2Data))) {
            ERR(tpm2_cipher_init_key, TPM2TSS_R_TPM2DATA_READ_FAILED);
            goto error;
        }
    } else {
        // Use blob context

        return 1;
    }

    printf("key  : %x %d\n", keyHandle, keyHandle);

    /* Fill other data : IV, ENC */
    tpm2DataCipher->iv.size = strlen((char *)iv);
    memcpy(tpm2DataCipher->iv.buffer, iv, tpm2DataCipher->iv.size);
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
    TPM2B_IV iv_in;
    TPMI_ALG_SYM_MODE mode;
    TPMI_YES_NO enc;

    DBG("Do cipher\n");

    /* Get App Data */
    tpm2DataCipher = EVP_CIPHER_CTX_get_app_data(ctx);
    if (tpm2DataCipher == NULL)
        return 1;

    /* Init TPM key */
    ret = init_tpm_key(&eactx, &keyHandle, tpm2DataCipher->tpm2Data);
    ERRchktss(tpm2_do_cipher_aes_256_cbc, ret, goto error);

    /* Copy in_data : unsigned char* to TPM2B_MAX_BUFFER */
    in_data = OPENSSL_malloc(sizeof(TPM2B_MAX_BUFFER));
    if (tpm2DataCipher == NULL) {
        ERR(tpm2_do_cipher_aes_256_cbc, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    memcpy(in_data->buffer, in, inl);
    in_data->size = inl;

    /* Get mode value */
    mode = tpm2DataCipher->tpm2Data->pub.publicArea.parameters.symDetail.sym.mode.sym;
    enc = tpm2DataCipher->enc;
    iv_in = tpm2DataCipher->iv;

    printf("data : %s", in_data->buffer);
    printf("mode : 0x%x\n", mode);
    printf("enc  : %d\n", enc);
    printf("iv   : %d\n", iv_in.size);
    printf("key  : 0x%x %d\n", keyHandle);

    /* Trying to encrypt */
    ret = Esys_EncryptDecrypt2( eactx.ectx,
                                keyHandle,
                                ESYS_TR_PASSWORD,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                in_data,
                                enc,
                                mode,
                                &iv_in,
                                &out_data,
                                &iv_out );
    if (ret == TPM2_RC_COMMAND_CODE) {
        DBG("Esys_EncryptDecrypt2 : FAILED\n");
        ret = Esys_EncryptDecrypt( eactx.ectx,
                                   keyHandle,
                                   ESYS_TR_PASSWORD,
                                   ESYS_TR_NONE,
                                   ESYS_TR_NONE,
                                   enc,
                                   mode,
                                   &iv_in,
                                   in_data,
                                   &out_data,
                                   &iv_out );
        if(!ret)
            DBG("Esys_EncryptDecrypt  : SUCCESS\n");
        else
            DBG("Esys_EncryptDecrypt  : FAILED\n");
    }
    ERRchktss(tpm2_do_cipher_aes_256_cbc, ret, goto error);

    /* Copy out_data : TPM2B_MAX_BUFFER to unsigned char* */
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
    NID_aes_256_cbc,                                              // int nid                   // EVP_CIPHER_meth_new()
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
