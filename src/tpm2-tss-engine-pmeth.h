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
#ifndef TPM2_TSS_ENGINE_PMETH_H
#define TPM2_TSS_ENGINE_PMETH_H

#include <openssl/evp.h>

typedef struct {
    int (*pinit) (EVP_PKEY_CTX *ctx);
    int (*pcopy) (EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);
    void (*pcleanup)(EVP_PKEY_CTX *ctx);

    int (*psign)(EVP_PKEY_CTX *ctx, unsigned char *sig,
            size_t *siglen, const unsigned char *tbs,
            size_t tbslen);
    int (*psign_init) (EVP_PKEY_CTX *ctx);

    int (*pverify_recover_init) (EVP_PKEY_CTX
            *ctx);
    int (*pverify_recover) (EVP_PKEY_CTX
            *ctx,
            unsigned char
            *sig,
            size_t *siglen,
            const unsigned
            char *tbs,
            size_t tbslen);

    int (*pverify_init) (EVP_PKEY_CTX *ctx);
    int (*pverify) (EVP_PKEY_CTX *ctx,
            const unsigned char *sig,
            size_t siglen,
            const unsigned char *tbs,
            size_t tbslen);

    int (*pencrypt_init) (EVP_PKEY_CTX *ctx);
    int (*pencryptfn) (EVP_PKEY_CTX *ctx,
            unsigned char *out,
            size_t *outlen,
            const unsigned char *in,
            size_t inlen);

    int (*pdecrypt_init) (EVP_PKEY_CTX *ctx);
    int (*pdecrypt) (EVP_PKEY_CTX *ctx,
            unsigned char *out,
            size_t *outlen,
            const unsigned char *in,
            size_t inlen);

    int (*pctrl) (EVP_PKEY_CTX *ctx, int type, int p1,
            void *p2);
    int (*pctrl_str) (EVP_PKEY_CTX *ctx,
            const char *type,
            const char *value);

} TPM2TSS_RSA_ORIG_METH;

EVP_PKEY_METHOD *tpm2tss_get_pkey_method_rsa();

EVP_PKEY_ASN1_METHOD *tpm2tss_get_pkey_asn1_method_rsa();

#endif /* TPM2_TSS_ENGINE_PMETH_H */
