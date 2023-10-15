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
#include <strings.h>
#include <inttypes.h>
#include <unistd.h>
#include <getopt.h>

#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/pem.h>

#include "tpm2-tss-engine.h"
#include "tpm2-tss-engine-common.h"

/* This tool uses a different error reporting scheme than the lib. */
#undef ERR
#define VERB(...) if (opt.verbose) fprintf(stderr, __VA_ARGS__)
#define ERR(...) fprintf(stderr, __VA_ARGS__)

char *help =
    "Usage: [options] <filename>\n"
    "Arguments:\n"
    "    <filename>      storage for the encrypted private key\n"
    "Options:\n"
    "    -a, --alg       public key algorithm (rsa, ecdsa, sm2) (default: rsa)\n"
    "    -c, --curve     curve for ecc (default: nist_p256)\n"
    "    -e, --exponent  exponent for rsa (default: 65537)\n"
    "    -h, --help      print help\n"
    "    -u, --public    import a key and read its public portion from this file\n"
    "    -r, --private   import the sensitive key portion from this file\n"
    "    -o, --ownerpw   password for the owner hierarchy (default: none)\n"
    "    -p, --password  password for the created key (default: none)\n"
    "    -P, --parent    specific handle for the parent key (default: none)\n"
    "    -s, --keysize   key size in bits for rsa (default: 2048)\n"
    "    -v, --verbose   print verbose messages\n"
    "    -W, --parentpw  password for the parent key (default: none)\n"
    "    -t, --tcti      tcti configuration string (default: none)\n"
    "\n";

static const char *optstr = "a:c:e:hu:r:o:p:P:s:vW:t:";

static const struct option long_options[] = {
    {"alg",      required_argument, 0, 'a'},
    {"curve",    required_argument, 0, 'c'},
    {"exponent", required_argument, 0, 'e'},
    {"help",     no_argument,       0, 'h'},
    {"public",   required_argument, 0, 'u'},
    {"private",  required_argument, 0, 'r'},
    {"ownerpw",  required_argument, 0, 'o'},
    {"password", required_argument, 0, 'p'},
    {"parent",   required_argument, 0, 'P'},
    {"keysize",  required_argument, 0, 's'},
    {"verbose",  no_argument,       0, 'v'},
    {"parentpw", required_argument, 0, 'W'},
    {"tcti",     required_argument, 0, 't'},
    {0,          0,                 0,  0 }
};

static struct opt {
    char *filename;
    TPMI_ALG_PUBLIC alg;
    TPMI_ECC_CURVE curve;
    int exponent;
    char *importpub;
    char *importtpm;
    char *ownerpw;
    char *password;
    TPM2_HANDLE parent;
    char *parentpw;
    int keysize;
    int verbose;
    char *tcti_conf;
} opt;

/** Parse and set command line options.
 *
 * This function parses the command line options and sets the appropriate values
 * in the opt struct.
 * @param argc The argument count.
 * @param argv The arguments.
 * @retval 0 on success
 * @retval 1 on failure
 */
int
parse_opts(int argc, char **argv)
{
    /* set the default values */
    opt.filename = NULL;
    opt.alg = TPM2_ALG_RSA;
    opt.curve = TPM2_ECC_NIST_P256;
    opt.exponent = 65537;
    opt.importpub = NULL;
    opt.importtpm = NULL;
    opt.ownerpw = NULL;
    opt.password = NULL;
    opt.parent = 0;
    opt.parentpw = NULL;
    opt.keysize = 2048;
    opt.verbose = 0;
    opt.tcti_conf = NULL;

    /* parse the options */
    int c;
    int opt_idx = 0;
    while (-1 != (c = getopt_long(argc, argv, optstr,
                                  long_options, &opt_idx))) {
        switch(c) {
        case 'h':
            printf("%s", help);
            exit(0);
        case 'v':
            opt.verbose = 1;
            break;
        case 'a':
            if (strcasecmp(optarg, "rsa") == 0) {
                opt.alg = TPM2_ALG_RSA;
                break;
            } else if (strcasecmp(optarg, "ecdsa") == 0) {
                opt.alg = TPM2_ALG_ECDSA;
                break;
            } else if (strcasecmp(optarg, "sm2") == 0) {
                opt.alg = TPM2_ALG_ECDSA;
                opt.curve = TPM2_ECC_SM2_P256;
                break;
            } else {
                ERR("Unknown algorithm.\n");
                exit(1);
            }
        case 'c':
            if (strcasecmp(optarg, "nist_p256") == 0) {
                opt.curve = TPM2_ECC_NIST_P256;
                break;
            } else if (strcasecmp(optarg, "nist_p384") == 0) {
                opt.curve = TPM2_ECC_NIST_P384;
                break;
            } else {
                ERR("Unknown curve.\n");
                exit(1);
            }
        case 'e':
            if (sscanf(optarg, "%i", &opt.exponent) != 1) {
                ERR("Error parsing keysize.\n");
                exit(1);
            }
            break;
        case 'u':
            opt.importpub = optarg;
            break;
        case 'r':
            opt.importtpm = optarg;
            break;
        case 'o':
            opt.ownerpw = optarg;
            break;
        case 'p':
            opt.password = optarg;
            break;
        case 'P':
            if (sscanf(optarg, "%x", &opt.parent) != 1 &&
                sscanf(optarg, "0x%x", &opt.parent) != 1 &&
                sscanf(optarg, "%i", &opt.parent) != 1) {
                ERR("Error parsing parent handle");
                exit(1);
            }
            break;
        case 'W':
            opt.parentpw = optarg;
            break;
        case 's':
            if (sscanf(optarg, "%i", &opt.keysize) != 1) {
                ERR("Error parsing keysize.\n");
                exit(1);
            }
            break;
        case 't':
            opt.tcti_conf = optarg;
            break;
        default:
            ERR("Unknown option at index %i.\n\n", opt_idx);
            ERR("%s", help);
            exit(1);
        }
    }

    /* parse the non-option arguments */
    if (optind >= argc) {
        ERR("Missing argument <filename>.\n\n");
        ERR("%s", help);
        exit(1);
    }
    opt.filename = argv[optind];
    optind++;

    if (optind < argc) {
        ERR("Unknown argument provided.\n\n");
        ERR("%s", help);
        exit(1);
    }

    if (!!opt.importpub != !!opt.importtpm) {
        ERR("Import requires both --public and --private\n");
        return 1;
    }

    return 0;
}

/** Generate an RSA key
 *
 * This function calls out to generate an RSA key using the TPM.
 * @retval TPM2_DATA data to be written to disk
 * @retval NULL on failure
 */
static TPM2_DATA *
genkey_rsa()
{
    VERB("Generating RSA key using TPM\n");

    RSA *rsa = NULL;
    BIGNUM *e = BN_new();
    if (!e) {
        ERR("out of memory\n");
        return NULL;
    }
    BN_set_word(e, opt.exponent);

    rsa = RSA_new();
    if (!rsa) {
        ERR("out of memory\n");
        BN_free(e);
        return NULL;
    }
    if (!tpm2tss_rsa_genkey(rsa, opt.keysize, e, opt.password, opt.parent)) {
        BN_free(e);
        RSA_free(rsa);
        ERR("Error: Generating key failed\n");
        return NULL;
    }

    VERB("Key generated\n");

    TPM2_DATA *tpm2Data = OPENSSL_malloc(sizeof(*tpm2Data));
    if (tpm2Data == NULL) {
        ERR("out of memory\n");
        BN_free(e);
        RSA_free(rsa);
        return NULL;
    }
    memcpy(tpm2Data, RSA_get_app_data(rsa), sizeof(*tpm2Data));

    BN_free(e);
    RSA_free(rsa);

    return tpm2Data;
}

/** Generate an ECDSA key
 *
 * This function calls out to generate an ECDSA key using the TPM.
 * @retval TPM2_DATA data to be written to disk
 * @retval NULL on failure
 */
static TPM2_DATA *
genkey_ecdsa()
{
    EC_KEY *eckey = NULL;

    eckey = EC_KEY_new();
    if (!eckey) {
        ERR("out of memory\n");
        return NULL;
    }
    if (!tpm2tss_ecc_genkey(eckey, opt.curve, opt.password, opt.parent)) {
        EC_KEY_free(eckey);
        ERR("Error: Generating key failed\n");
        return NULL;
    }

    TPM2_DATA *tpm2Data = OPENSSL_malloc(sizeof(*tpm2Data));
    if (tpm2Data == NULL) {
        ERR("out of memory\n");
        EC_KEY_free(eckey);
        return NULL;
    }
    memcpy(tpm2Data, tpm2tss_ecc_getappdata(eckey), sizeof(*tpm2Data));

    EC_KEY_free(eckey);

    return tpm2Data;
}

/** Main function
 *
 * This function initializes OpenSSL and then calls the key generation
 * functions.
 * @param argc The argument count.
 * @param argv The arguments.
 * @retval 0 on success
 * @retval 1 on failure
 */
int
main(int argc, char **argv)
{
    if (parse_opts(argc, argv) != 0)
        exit(1);

    int r;
    TPM2_DATA *tpm2Data = NULL;

#if OPENSSL_VERSION_NUMBER < 0x1010000fL
    OPENSSL_config(NULL);
#else
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
#endif

    /* Initialize the tpm2-tss engine */
    ENGINE_load_dynamic();

    /* Openssl 1.1.0 requires the lib-prefix for the engine_id */
    ENGINE *tpm_engine = ENGINE_by_id("tpm2tss");
    if (!tpm_engine)
        tpm_engine = ENGINE_by_id("libtpm2tss");
    if (tpm_engine == NULL) {
        ERR("Could not load tpm2tss engine\n");
        return 1;
    }

    int init_res = ENGINE_init(tpm_engine);
    VERB("Engine name: %s\nInit result: %d \n", ENGINE_get_name(tpm_engine),
         init_res);
    if (!init_res)
        return 1;

    if (opt.ownerpw &&
            !ENGINE_ctrl(tpm_engine, TPM2TSS_SET_OWNERAUTH, 0, opt.ownerpw, NULL)) {
        ERR("Could not set ownerauth\n");
        return 1;
    }

    if (opt.parentpw &&
            !ENGINE_ctrl(tpm_engine, TPM2TSS_SET_PARENTAUTH, 0, opt.parentpw, NULL)) {
        ERR("Could not set parentauth\n");
        return 1;
    }

    if (opt.tcti_conf &&
            !ENGINE_ctrl(tpm_engine, TPM2TSS_SET_TCTI, 0, opt.tcti_conf, NULL)) {
        ERR("Could not set parentauth\n");
        return 1;
    }

    if (opt.importpub && opt.importtpm) {
        VERB("Importing the TPM key\n");
        r = tpm2tss_tpm2data_importtpm(opt.importpub, opt.importtpm, opt.parent,
                                       opt.password == NULL, &tpm2Data);
        if (r != 1)
            return 1;
    } else switch (opt.alg) {
    case TPM2_ALG_RSA:
        VERB("Generating the rsa key\n");
        tpm2Data = genkey_rsa();
        break;
    case TPM2_ALG_ECDSA:
        if (opt.curve == TPM2_ECC_SM2_P256)
            VERB("Generating the sm2 key\n");
        else
            VERB("Generating the ecdsa key\n");
        tpm2Data = genkey_ecdsa();
        break;
    default:
        break;
    }

    if (tpm2Data == NULL) {
        ERR("Key could not be generated.\n");
        return 1;
    }

    /* Write the key to disk */
    VERB("Writing key to disk\n");

    if (!tpm2tss_tpm2data_write(tpm2Data, opt.filename)) {
        ERR("Error writing file\n");
        OPENSSL_free(tpm2Data);
        return 1;
    }

    OPENSSL_free(tpm2Data);

    VERB("*** SUCCESS ***\n");
    return 0;
}
