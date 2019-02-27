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

static EVP_PKEY_METHOD *pkey_method_rsa = NULL;
static EVP_PKEY_ASN1_METHOD *pkey_asn1_method_rsa = NULL;

static const int pkey_nids[] = {
        EVP_PKEY_RSA,
        0
};

static int tpm2tss_pkey_asn1_meths(ENGINE *e,
        EVP_PKEY_ASN1_METHOD **ameth,
        const int **nids, int nid)
{
    (void)e;

    if (!ameth) {
        *nids = pkey_nids;
        return sizeof(pkey_nids) / sizeof(int) - 1;
    }

    switch (nid) {
    case EVP_PKEY_RSA:
            if (pkey_asn1_method_rsa == NULL)
                pkey_asn1_method_rsa = tpm2tss_get_pkey_asn1_method_rsa();
            if (pkey_asn1_method_rsa == NULL)
                    return 0;
            *ameth = pkey_asn1_method_rsa;
            return 1;
    }

    *ameth = NULL;
    return 0;
}

static int tpm2tss_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                           const int **nids, int nid)
{
    (void)e;

    if (!pmeth) {
        *nids = pkey_nids;
        return sizeof(pkey_nids) / sizeof(int) - 1;
    }

    switch (nid) {
    case EVP_PKEY_RSA:
            if (pkey_method_rsa == NULL)
                    pkey_method_rsa = tpm2tss_get_pkey_method_rsa();
            if (pkey_method_rsa == NULL)
                    return 0;
            *pmeth = pkey_method_rsa;
            return 1;
    }

    *pmeth = NULL;
    return 0;
}

int init_pmeth(ENGINE *e)
{
    if (!e)
        return 0;

    if (!ENGINE_set_pkey_asn1_meths(e, tpm2tss_pkey_asn1_meths))
        return 0;

    return ENGINE_set_pkey_meths(e, tpm2tss_pkey_meths);
}
